"""
Tests for the credit-ledger service (ledger_server.py): the persistent LedgerService logic +
the HTTP API end-to-end (real socket on a test port). Proves the integration seam works:
can_consume gate → settle → balances survive restart → dispute clawback; forged receipt → 422.
"""
import hashlib
import base64
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
from ledger_auth import canonical_string  # noqa: E402
from ledger_migrate import migrate  # noqa: E402
from core.ledger_store import LedgerStore  # noqa: E402
from ledger_server import (  # noqa: E402
    LedgerService,
    V2LedgerService,
    _make_handler,
    _make_v2_handler,
)
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


# ---------------------------------------------------------------- signed SQLite v2 HTTP API

def _v2_keypair():
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return private, public


@pytest.fixture
def v2_identities(tmp_path):
    identities = {}
    rows = []
    for label, node, operator, tier in (
        ("alice", "requester-node", "alice", "trusted"),
        ("bob", "worker-bob", "bob", "known"),
        ("carol", "worker-carol", "carol", "known"),
        ("alice_worker", "worker-alice", "alice", "known"),
        ("mallory", "stranger-node", "mallory", "stranger"),
        ("operator", "operator-node", "ledger-operator", "self"),
    ):
        private, public = _v2_keypair()
        identities[label] = {"private": private, "public": public}
        rows.append(f"{public}\t{node}\t{operator}\t{tier}\ttest")
    roster = tmp_path / "admission-peers.tsv"
    roster.write_text("\n".join(rows) + "\n", encoding="utf-8")
    identities["roster"] = roster
    return identities


def _v2_receipt(run_id="run-1", tokens=(1, 2), *, stages=None):
    generated = list(tokens)
    return {
        "run_id": run_id,
        "n_generated": len(generated),
        "generated_tokens": generated,
        "output_sha256": _sha(generated),
        "chain": stages or [
            {"node_id": "worker-bob", "layer_start": 0, "layer_end": 10},
            {"node_id": "worker-carol", "layer_start": 10, "layer_end": 20},
        ],
        "worker_signatures": [],
    }


def _v2_participation(identity, receipt, node_id, start, end):
    message = (
        f'{receipt["run_id"]}|{node_id}|[{start},{end})|{receipt["output_sha256"]}'
    ).encode("utf-8")
    signature = identity["private"].sign(message)
    return {
        "node_id": node_id,
        "pubkey": identity["public"],
        "layer_start": start,
        "layer_end": end,
        "sig": base64.b64encode(signature).decode("ascii"),
    }


def _sign_receipt(receipt, identities):
    by_node = {
        "worker-bob": identities["bob"],
        "worker-carol": identities["carol"],
        "worker-alice": identities["alice_worker"],
    }
    receipt["worker_signatures"] = [
        _v2_participation(
            by_node[stage["node_id"]], receipt, stage["node_id"],
            stage["layer_start"], stage["layer_end"],
        )
        for stage in receipt["chain"]
    ]
    return receipt


@contextmanager
def _running_v2(store_path, roster_path):
    service = V2LedgerService(store_path, roster_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_v2_handler(service))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}", service
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
        service.close()


@pytest.fixture
def v2_server(tmp_path, v2_identities):
    with _running_v2(tmp_path / "ledger.sqlite", v2_identities["roster"]) as running:
        yield running


class _Timestamp:
    def __init__(self):
        self.value = int(time.time()) - 20

    def next(self):
        self.value += 1
        return self.value


@pytest.fixture
def timestamps():
    return _Timestamp()


def _v2_request(base, method, path, identity=None, obj=None, *, timestamp=None,
                raw_body=None, authorization=None):
    if raw_body is not None:
        body = raw_body
    elif obj is not None:
        body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    else:
        body = b""
    headers = {}
    if identity is not None:
        timestamp = int(time.time()) if timestamp is None else timestamp
        signature = identity["private"].sign(
            canonical_string(method, path, body, timestamp)
        )
        authorization = (
            f'Sthambha-Ed25519 keyid="{identity["public"]}",'
            f'sig="{base64.b64encode(signature).decode("ascii")}",ts="{timestamp}"'
        )
    if authorization is not None:
        headers["Authorization"] = authorization
    if obj is not None or raw_body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        base + path, data=body if method == "POST" else None,
        headers=headers, method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_v2_unsigned_post_and_unrostered_key_give_401(v2_server, timestamps):
    base, _ = v2_server
    code, _ = _v2_request(base, "POST", "/transfer", obj={"to": "bob", "amount": 1})
    assert code == 401

    private, public = _v2_keypair()
    outsider = {"private": private, "public": public}
    code, _ = _v2_request(
        base, "POST", "/transfer", outsider, {"to": "bob", "amount": 1},
        timestamp=timestamps.next(),
    )
    assert code == 401


def test_v2_envelope_replay_is_refused_and_persists_across_restart(
    tmp_path, v2_identities, timestamps
):
    store = tmp_path / "ledger.sqlite"
    body = json.dumps({"to": "bob", "amount": 1}, separators=(",", ":")).encode()
    timestamp = timestamps.next()
    identity = v2_identities["alice"]
    signature = identity["private"].sign(
        canonical_string("POST", "/transfer", body, timestamp)
    )
    authorization = (
        f'Sthambha-Ed25519 keyid="{identity["public"]}",'
        f'sig="{base64.b64encode(signature).decode()}",ts="{timestamp}"'
    )
    with _running_v2(store, v2_identities["roster"]) as (base, _):
        assert _v2_request(
            base, "POST", "/transfer", raw_body=body, authorization=authorization
        )[0] == 200
        assert _v2_request(
            base, "POST", "/transfer", raw_body=body, authorization=authorization
        )[0] == 401
    with _running_v2(store, v2_identities["roster"]) as (base, _):
        assert _v2_request(
            base, "POST", "/transfer", raw_body=body, authorization=authorization
        )[0] == 401


def test_v2_forged_receipt_is_422_and_changes_nothing(
    v2_server, v2_identities, timestamps
):
    base, service = v2_server
    receipt = _sign_receipt(_v2_receipt(), v2_identities)
    receipt["generated_tokens"][0] = 999
    code, _ = _v2_request(
        base, "POST", "/settle", v2_identities["alice"], {"receipt": receipt},
        timestamp=timestamps.next(),
    )
    assert code == 422
    assert service.store.balance("alice") == 0
    assert service.store.balance("bob") == 0
    assert service.store.balance("carol") == 0


def test_v2_valid_receipt_settles_and_replay_is_idempotent(
    v2_server, v2_identities, timestamps
):
    base, service = v2_server
    receipt = _sign_receipt(_v2_receipt(), v2_identities)
    payload = {"receipt": receipt, "requester": "mallory"}
    first_code, first = _v2_request(
        base, "POST", "/settle", v2_identities["alice"], payload,
        timestamp=timestamps.next(),
    )
    second_code, second = _v2_request(
        base, "POST", "/settle", v2_identities["alice"], payload,
        timestamp=timestamps.next(),
    )
    assert first_code == second_code == 200
    assert first["delta"] == second["delta"] == -40
    assert service.store.balance("alice") == -40
    assert service.store.balance("bob") == 20
    assert service.store.balance("carol") == 20


def test_v2_new_run_id_for_same_work_does_not_double_credit(
    v2_server, v2_identities, timestamps
):
    base, service = v2_server
    first = _sign_receipt(_v2_receipt("first-run"), v2_identities)
    second = _sign_receipt(_v2_receipt("second-run"), v2_identities)
    results = []
    for receipt in (first, second):
        code, result = _v2_request(
            base, "POST", "/settle", v2_identities["alice"], {"receipt": receipt},
            timestamp=timestamps.next(),
        )
        assert code == 200
        results.append(result)
    assert results[0]["receipt_id"] == results[1]["receipt_id"]
    assert service.store.balance("bob") == 20
    assert service.store.balance("carol") == 20


def test_v2_own_node_receipt_is_free(v2_server, v2_identities, timestamps):
    base, service = v2_server
    receipt = _v2_receipt(
        stages=[{"node_id": "worker-alice", "layer_start": 0, "layer_end": 20}]
    )
    _sign_receipt(receipt, v2_identities)
    code, result = _v2_request(
        base, "POST", "/settle", v2_identities["alice"], {"receipt": receipt},
        timestamp=timestamps.next(),
    )
    assert code == 200
    assert result["charged"] == result["delta"] == 0
    assert result["credited"] == {}
    assert service.store.balance("alice") == 0


def test_v2_over_limit_is_402(v2_server, v2_identities, timestamps):
    base, service = v2_server
    receipt = _v2_receipt(tokens=range(11), stages=[
        {"node_id": "worker-bob", "layer_start": 0, "layer_end": 10}
    ])
    _sign_receipt(receipt, v2_identities)
    code, _ = _v2_request(
        base, "POST", "/settle", v2_identities["mallory"], {"receipt": receipt},
        timestamp=timestamps.next(),
    )
    assert code == 402
    assert service.store.balance("mallory") == 0
    assert service.store.balance("bob") == 0


def test_v2_transfer_source_is_always_signers_operator(
    v2_server, v2_identities, timestamps
):
    base, service = v2_server
    code, result = _v2_request(
        base, "POST", "/transfer", v2_identities["alice"],
        {"from": "bob", "to": "mallory", "amount": 1},
        timestamp=timestamps.next(),
    )
    assert code == 200 and result["from"] == "alice"
    assert service.store.balance("alice") == -1
    assert service.store.balance("bob") == 0
    assert service.store.balance("mallory") == 1


def test_v2_dispute_by_stranger_is_refused(v2_server, v2_identities, timestamps):
    base, service = v2_server
    receipt = _sign_receipt(_v2_receipt(), v2_identities)
    code, settled = _v2_request(
        base, "POST", "/settle", v2_identities["alice"], {"receipt": receipt},
        timestamp=timestamps.next(),
    )
    assert code == 200
    code, _ = _v2_request(
        base, "POST", "/dispute", v2_identities["mallory"],
        {"receipt_id": settled["receipt_id"]}, timestamp=timestamps.next(),
    )
    assert code == 403
    assert service.store.balance("bob") == 20


@pytest.mark.parametrize("disputer", ["alice", "operator"])
def test_v2_requester_or_operator_key_can_dispute_permanently(
    v2_server, v2_identities, timestamps, disputer
):
    base, _ = v2_server
    tokens = (1, 2) if disputer == "alice" else (3, 4, 5)
    receipt = _sign_receipt(_v2_receipt(tokens=tokens), v2_identities)
    code, settled = _v2_request(
        base, "POST", "/settle", v2_identities["alice"], {"receipt": receipt},
        timestamp=timestamps.next(),
    )
    assert code == 200
    code, disputed = _v2_request(
        base, "POST", "/dispute", v2_identities[disputer],
        {"receipt_id": settled["receipt_id"]}, timestamp=timestamps.next(),
    )
    assert code == 200 and disputed["clawed"] is True
    code, _ = _v2_request(
        base, "POST", "/settle", v2_identities["alice"], {"receipt": receipt},
        timestamp=timestamps.next(),
    )
    assert code == 409


def test_v2_signed_gets_are_own_only_and_balances_is_refused(
    v2_server, v2_identities, timestamps
):
    base, _ = v2_server
    own_path = "/balance?account=alice"
    code, result = _v2_request(
        base, "GET", own_path, v2_identities["alice"], timestamp=timestamps.next()
    )
    assert code == 200 and result["account"] == "alice"
    # Asking about someone else answers about YOURSELF: it never reveals bob's entry
    # (a v1-era ?account= parameter must not disable the gate either).
    other_path = "/balance?account=bob"
    code, result = _v2_request(
        base, "GET", other_path, v2_identities["alice"], timestamp=timestamps.next()
    )
    assert code == 200 and result["account"] == "alice"
    assert _v2_request(base, "GET", "/balances")[0] == 403
    assert _v2_request(base, "GET", "/health")[1] == {
        "ok": True, "store": "sqlite", "signed": True
    }


def test_migration_round_trip_preserves_totals_and_is_idempotent(tmp_path, capsys):
    source = tmp_path / "ledger.json"
    target = tmp_path / "ledger.sqlite"
    snapshot = {
        "balances": {"alice": -40, "bob": 20, "carol": 20, "unused": 0},
        "settled": {
            "legacy-run": {
                "credited": {"bob": 20, "carol": 20},
                "requester": "alice", "debited": 40, "total": 40,
            }
        },
        "journal": [],
    }
    source.write_text(json.dumps(snapshot), encoding="utf-8")
    migrate(source, target)
    migrate(source, target)
    output = capsys.readouterr().out
    assert "accounts=4 receipts=1 balance_total=0" in output
    assert "already migrated" in output
    with LedgerStore(target) as store:
        assert sum(store.balance(account) for account in snapshot["balances"]) == 0
        assert store.balance("alice") == -40
        assert store.balance("bob") == 20


def test_migration_refuses_nonempty_target_without_force(tmp_path):
    source = tmp_path / "ledger.json"
    target = tmp_path / "ledger.sqlite"
    source.write_text(
        json.dumps({"balances": {"alice": 5}, "settled": {}, "journal": []}),
        encoding="utf-8",
    )
    target.write_bytes(b"do not overwrite")
    with pytest.raises(FileExistsError, match="--force"):
        migrate(source, target)
    assert target.read_bytes() == b"do not overwrite"

    migrate(source, target, force=True)
    with LedgerStore(target) as store:
        assert store.balance("alice") == 5


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
