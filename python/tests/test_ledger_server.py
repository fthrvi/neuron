"""
Tests for the credit-ledger service (ledger_server.py): the persistent LedgerService logic +
the HTTP API end-to-end (real socket on a test port). Proves the integration seam works:
can_consume gate → settle → balances survive restart → dispute clawback; forged receipt → 422.
"""
import hashlib
import json
import os
import sys
import threading
import urllib.request

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
from ledger_server import LedgerService, _make_handler  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402


def _sha(toks):
    return hashlib.sha256(",".join(str(int(t)) for t in toks).encode()).hexdigest()


def _receipt(run_id="r1", tokens=(1, 2, 3, 4)):
    toks = list(tokens)
    return {"run_id": run_id, "n_generated": len(toks), "generated_tokens": toks,
            "output_sha256": _sha(toks),
            "chain": [{"node_id": "wA", "layer_start": 0, "layer_end": 16},
                      {"node_id": "wB", "layer_start": 16, "layer_end": 32}]}


# ---------------------------------------------------------------- LedgerService + persistence

def test_service_settle_and_persist(tmp_path):
    p = str(tmp_path / "ledger.json")
    svc = LedgerService(p, grace=5)
    # gate: fresh requester has only grace
    assert svc.can_consume("op", 5)["ok"] is True
    assert svc.can_consume("op", 6)["ok"] is False
    # settle a run
    d = svc.settle(_receipt(), requester="op")
    assert d["total"] == 128 and d["credited"] == {"wA": 64, "wB": 64}
    assert svc.balance("wA")["balance"] == 64
    assert os.path.exists(p)                       # persisted
    # a NEW service instance loads the same balances (survives restart)
    svc2 = LedgerService(p, grace=5)
    assert svc2.balance("wA")["balance"] == 64
    assert svc2.balance("op")["balance"] == -128
    # wA can now consume what it earned (+grace)
    assert svc2.can_consume("wA", 69)["ok"] is True
    assert svc2.can_consume("wA", 70)["ok"] is False


def test_service_idempotent_and_dispute(tmp_path):
    svc = LedgerService(str(tmp_path / "l.json"))
    svc.settle(_receipt(), requester="op")
    svc.settle(_receipt(), requester="op")          # replay
    assert svc.balance("wA")["balance"] == 64       # not doubled
    assert svc.dispute("r1")["clawed"] is True
    assert svc.balance("wA")["balance"] == 0
    # clawback persisted
    svc2 = LedgerService(str(tmp_path / "l.json"))
    assert svc2.balance("wA")["balance"] == 0


def test_service_forged_receipt_raises(tmp_path):
    from core.credit_ledger import CreditError
    svc = LedgerService(str(tmp_path / "l.json"))
    bad = _receipt(); bad["generated_tokens"][0] = 999   # tamper, keep hash
    with pytest.raises(CreditError):
        svc.settle(bad, requester="op")
    assert svc.balance("wA")["balance"] == 0


# ---------------------------------------------------------------- HTTP API end-to-end

@pytest.fixture
def server(tmp_path):
    svc = LedgerService(str(tmp_path / "http.json"), grace=10)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(svc))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=5) as r:
        return r.status, json.loads(r.read())


def _post(base, path, obj):
    req = urllib.request.Request(base + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_http_full_flow(server):
    # health
    assert _get(server, "/health")[1]["ok"] is True
    # gate before serving (grace=10)
    assert _get(server, "/can_consume?account=op&cost=10")[1]["ok"] is True
    assert _get(server, "/can_consume?account=op&cost=11")[1]["ok"] is False
    # settle after serving
    code, body = _post(server, "/settle", {"receipt": _receipt(), "requester": "op"})
    assert code == 200 and body["delta"]["total"] == 128
    assert _get(server, "/balance?account=wA")[1]["balance"] == 64
    assert _get(server, "/balances")[1]["balances"]["op"] == -128
    # forged receipt → 422
    bad = _receipt(run_id="r2"); bad["output_sha256"] = "0" * 64
    code, body = _post(server, "/settle", {"receipt": bad, "requester": "op"})
    assert code == 422 and "error" in body
    # dispute
    code, body = _post(server, "/dispute", {"run_id": "r1"})
    assert code == 200 and body["clawed"] is True
    assert _get(server, "/balance?account=wA")[1]["balance"] == 0


def test_http_local_free_and_transfer_and_history(server):
    # LOCAL run: own_nodes = both workers → free (charged 0)
    code, body = _post(server, "/settle",
                       {"receipt": _receipt(run_id="local"), "requester": "alice",
                        "own_nodes": ["wA", "wB"]})
    assert code == 200 and body["delta"]["total"] == 0
    assert _get(server, "/balance?account=alice")[1]["balance"] == 0   # not charged for own GPUs
    # NETWORK run: alice uses bob's wB (own = wA only) → pays for wB
    _post(server, "/settle", {"receipt": _receipt(run_id="net"), "requester": "alice",
                              "own_nodes": ["wA"]})
    assert _get(server, "/balance?account=wB")[1]["balance"] == 64
    assert _get(server, "/balance?account=alice")[1]["balance"] == -64
    # transfer (send/receive)
    code, body = _post(server, "/transfer", {"from": "wB", "to": "carol", "amount": 20, "memo": "tip"})
    assert code == 200 and body["balances"]["carol"] == 20
    code, body = _post(server, "/transfer", {"from": "wB", "to": "carol", "amount": 9999})
    assert code == 422                                        # overdraw refused
    # history
    h = _get(server, "/history?account=wB")[1]
    assert h["balance"] == 44
    kinds = [e["kind"] for e in h["history"]]
    assert "earn" in kinds and "send" in kinds


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
