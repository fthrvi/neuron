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
from ledger_auth import SettlementFrozen, canonical_string  # noqa: E402
from ledger_migrate import migrate  # noqa: E402
from core.ledger_store import LedgerStore  # noqa: E402
from core import ledger_store as ledger_store_module  # noqa: E402
from core.ledger_store import HOLD_S, MIN_WITHDRAW_CREDITS  # noqa: E402
from ledger_server import (  # noqa: E402
    LedgerService,
    V2LedgerService,
    _make_handler,
    _make_v2_handler,
    _operator_tiers,
    _row_identity,
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
        ("stranger_depositor", "deposit-node", "stranger-depositor", "stranger"),
        ("suspended", "suspended-node", "suspended-operator", "suspended"),
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
        "v": 1,
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
    payload = {"receipt": receipt}
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


def test_v2_suspended_participant_freezes_receipt_without_storing_it(
    v2_server, v2_identities, timestamps
):
    base, service = v2_server
    receipt = _sign_receipt(_v2_receipt(), v2_identities)
    bob = v2_identities["bob"]["public"]
    with service.rosters._lock:
        normal = {key: dict(row) for key, row in service.rosters._roster.items()}
        suspended = {key: dict(row) for key, row in normal.items()}
        suspended[bob]["tier"] = "suspended"
        service.rosters._roster = suspended

    assert _v2_request(
        base,
        "POST",
        "/settle",
        v2_identities["alice"],
        {"receipt": receipt},
        timestamp=timestamps.next(),
    ) == (409, {"error": "a participant is suspended; settlement is frozen"})
    assert service.store._db.execute(
        "SELECT COUNT(*) FROM receipts"
    ).fetchone()[0] == 0

    with service.rosters._lock:
        service.rosters._roster = normal
    code, result = _v2_request(
        base,
        "POST",
        "/settle",
        v2_identities["alice"],
        {"receipt": receipt},
        timestamp=timestamps.next(),
    )
    assert code == 200
    assert result["credited"] == {"bob": 20, "carol": 20}
    assert result["charged"] == 40


def test_legacy_receipt_waits_for_unsuspend_then_replays_stored_values(
    tmp_path, v2_identities
):
    service = V2LedgerService(
        tmp_path / "ledger.sqlite", v2_identities["roster"], start_sweeper=False
    )
    try:
        receipt = _sign_receipt(_v2_receipt(), v2_identities)
        requester = v2_identities["alice"]["public"]
        bob = v2_identities["bob"]["public"]
        roster = service.rosters.snapshot()
        suspended = {key: dict(row) for key, row in roster.items()}
        suspended[bob]["tier"] = "suspended"

        with pytest.raises(
            SettlementFrozen,
            match="a participant is suspended; settlement is frozen",
        ):
            service.settle({"receipt": receipt}, requester, suspended)
        assert service.store._db.execute(
            "SELECT COUNT(*) FROM receipts"
        ).fetchone()[0] == 0
        assert all(
            service.store.balance(account) == 0
            for account in ("alice", "bob", "carol")
        )

        first = service.settle({"receipt": receipt}, requester, roster)
        balances = {
            account: service.store.balance(account)
            for account in ("alice", "bob", "carol")
        }
        replay = service.settle({"receipt": receipt}, requester, suspended)

        assert replay == first
        assert first["credited"] == {"bob": 20, "carol": 20}
        assert first["charged"] == 40
        assert {
            account: service.store.balance(account)
            for account in ("alice", "bob", "carol")
        } == balances
    finally:
        service.close()


def test_v2_settle_creates_credited_accounts_with_roster_tiers(
    v2_server, v2_identities, timestamps
):
    base, service = v2_server
    receipt = _sign_receipt(_v2_receipt(), v2_identities)
    code, _ = _v2_request(
        base, "POST", "/settle", v2_identities["alice"], {"receipt": receipt},
        timestamp=timestamps.next(),
    )
    assert code == 200
    rows = service.store._db.execute(
        "SELECT id, tier FROM accounts WHERE id IN ('bob', 'carol')"
    ).fetchall()
    assert {row["id"]: row["tier"] for row in rows} == {
        "bob": "known", "carol": "known",
    }


def test_operator_tiers_uses_highest_roster_tier():
    roster = {
        "key-1": {"operator": "worker", "tier": "known"},
        "key-2": {"operator": "worker", "tier": "trusted"},
        "key-3": {"operator": "other", "tier": "unexpected"},
        "key-4": {"operator": "suspended-only", "tier": "suspended"},
        "key-5": {"operator": "worker", "tier": "suspended"},
    }
    assert _operator_tiers(roster) == {"worker": "trusted", "other": "stranger"}


def test_v2_new_run_id_for_same_work_does_not_double_credit(
    v2_server, v2_identities, timestamps
):
    """Two genuinely worker-signed runs of identical output are BOTH paid; replaying one run's
    signatures under an invented run_id pays nothing (the signature binds the real run_id)."""
    base, service = v2_server
    first = _sign_receipt(_v2_receipt("first-run"), v2_identities)
    second = _sign_receipt(_v2_receipt("second-run"), v2_identities)
    replay = _v2_receipt("invented-run")
    replay["worker_signatures"] = first["worker_signatures"]
    results = []
    for receipt in (first, second, replay):
        code, result = _v2_request(
            base, "POST", "/settle", v2_identities["alice"], {"receipt": receipt},
            timestamp=timestamps.next(),
        )
        assert code == 200
        results.append(result)
    assert results[0]["receipt_id"] != results[1]["receipt_id"]
    assert results[2]["credited"] == {} and results[2]["charged"] == 0
    assert service.store.balance("bob") == 40
    assert service.store.balance("carol") == 40


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
    receipt = _v2_receipt(tokens=(1, 2), stages=[
        {"node_id": "worker-bob", "layer_start": 0, "layer_end": 500_001}
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


def test_v2_transfer_to_suspended_operator_is_frozen(
    v2_server, v2_identities, timestamps
):
    base, service = v2_server
    bob = v2_identities["bob"]["public"]
    with service.rosters._lock:
        suspended = {
            key: dict(row) for key, row in service.rosters._roster.items()
        }
        suspended[bob]["tier"] = "suspended"
        service.rosters._roster = suspended

    assert _v2_request(
        base,
        "POST",
        "/transfer",
        v2_identities["alice"],
        {"to": "bob", "amount": 1},
        timestamp=timestamps.next(),
    ) == (409, {"error": "recipient is suspended; transfers are frozen"})
    assert service.store.balance("alice") == 0
    assert service.store.balance("bob") == 0


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


def test_funds_routes_are_hidden_when_off_and_require_signatures_when_on(
    v2_server, v2_identities, timestamps, monkeypatch
):
    base, _ = v2_server
    monkeypatch.delenv("NAK_FUNDS_ROUTES", raising=False)
    assert _v2_request(base, "GET", "/wallet")[0] == 404
    assert _v2_request(
        base, "POST", "/wallet/bind", obj={"address": "1" * 32}
    )[0] == 404

    monkeypatch.setenv("NAK_FUNDS_ROUTES", "on")
    assert _v2_request(base, "GET", "/wallet")[0] == 401
    assert _v2_request(base, "GET", "/wallet/status")[0] == 401
    assert _v2_request(base, "POST", "/withdraw", obj={"amount": 1})[0] == 401


def test_wallet_is_queued_and_all_gets_answer_only_for_signer(
    v2_server, v2_identities, timestamps, monkeypatch
):
    monkeypatch.setenv("NAK_FUNDS_ROUTES", "on")
    base, service = v2_server
    code, wallet = _v2_request(
        base, "GET", "/wallet?account=bob", v2_identities["alice"],
        timestamp=timestamps.next(),
    )
    assert code == 200
    assert wallet == {
        "account": "alice",
        "status": "pending",
        "deposit_address": None,
        "requested_ts": wallet["requested_ts"],
    }
    queued = service.store._db.execute(
        "SELECT operator FROM deposit_account_requests"
    ).fetchall()
    assert [row["operator"] for row in queued] == ["alice"]

    service.store.deposit("alice:0", "alice", MIN_WITHDRAW_CREDITS * 2, 1)
    service.store.deposit("bob:0", "bob", MIN_WITHDRAW_CREDITS * 3, 2)
    code, status = _v2_request(
        base, "GET", "/wallet/status?account=bob", v2_identities["alice"],
        timestamp=timestamps.next(),
    )
    assert code == 200 and status["account"] == "alice"
    assert status["balance"] == MIN_WITHDRAW_CREDITS * 2
    assert status["withdrawable"] == MIN_WITHDRAW_CREDITS * 2
    assert status["balance_usdc"] == "2.00000000"
    assert status["pending_withdrawals"] == []



def test_row_identity_refuses_reserved_operator():
    with pytest.raises(PermissionError, match="reserved"):
        _row_identity("key", {"key": {"operator": "treasury", "tier": "self"}})


def test_suspended_signer_gets_403_on_balance_withdraw_and_task_authorize(
    v2_server, v2_identities, timestamps, monkeypatch
):
    monkeypatch.setenv("NAK_FUNDS_ROUTES", "on")
    monkeypatch.setenv("NAK_SPEND_ROUTES", "on")
    base, _ = v2_server
    suspended = v2_identities["suspended"]
    worker = v2_identities["bob"]

    requests = (
        ("GET", "/balance", None),
        ("POST", "/withdraw", {"amount": MIN_WITHDRAW_CREDITS}),
        ("POST", "/spend/task/authorize", {
            "client_nonce": "suspended-authorize",
            "task_hash": "a" * 64,
            "worker_keyid": worker["public"],
            "amount": 1,
            "deadline": int(time.time()) + 60,
        }),
    )
    for method, path, body in requests:
        assert _v2_request(
            base, method, path, suspended, body, timestamp=timestamps.next()
        ) == (403, {"error": "signing key is suspended"})


def test_known_payer_can_refund_existing_hold_after_worker_is_suspended(
    tmp_path, v2_identities, timestamps, monkeypatch
):
    monkeypatch.setenv("NAK_SPEND_ROUTES", "on")
    roster_path = v2_identities["roster"]
    with _running_v2(tmp_path / "suspended-refund.sqlite", roster_path) as running:
        base, service = running
        service.store.deposit("funding", "alice", 100, 1)
        authorize = {
            "client_nonce": "before-worker-suspension",
            "task_hash": "b" * 64,
            "worker_keyid": v2_identities["bob"]["public"],
            "amount": 100,
            "deadline": int(time.time()) + 60,
        }
        code, hold = _v2_request(
            base, "POST", "/spend/task/authorize", v2_identities["alice"],
            authorize, timestamp=timestamps.next(),
        )
        assert code == 200

        rows = roster_path.read_text(encoding="utf-8").splitlines()
        roster_path.write_text(
            "\n".join(
                row.replace("\tknown\t", "\tsuspended\t")
                if row.startswith(v2_identities["bob"]["public"] + "\t") else row
                for row in rows
            ) + "\n",
            encoding="utf-8",
        )
        service.rosters.refresh_seconds = 0

        assert _v2_request(
            base, "POST", "/spend/task/refund", v2_identities["alice"],
            {"hold_id": hold["hold_id"], "reason": "worker suspended"},
            timestamp=timestamps.next(),
        )[0] == 200
        assert service.store.task_hold_status(hold["hold_id"])["state"] == "refunded"
        assert service.store.balance("alice") == 100


def test_withdraw_requires_bound_cooled_address_minimum_and_one_per_day(
    v2_server, v2_identities, timestamps, monkeypatch
):
    monkeypatch.setenv("NAK_FUNDS_ROUTES", "on")
    base, service = v2_server
    service.store.deposit("alice:0", "alice", MIN_WITHDRAW_CREDITS * 3, 1)

    code, _ = _v2_request(
        base, "POST", "/withdraw", v2_identities["alice"],
        {"amount": MIN_WITHDRAW_CREDITS}, timestamp=timestamps.next(),
    )
    assert code == 403

    first_address = "1" * 32
    second_address = "So11111111111111111111111111111111111111112"
    code, bound = _v2_request(
        base, "POST", "/wallet/bind", v2_identities["alice"],
        {"address": first_address}, timestamp=timestamps.next(),
    )
    assert code == 200 and bound["cooling_until"] is None

    code, _ = _v2_request(
        base, "POST", "/withdraw", v2_identities["alice"],
        {"amount": MIN_WITHDRAW_CREDITS - 100}, timestamp=timestamps.next(),
    )
    assert code == 422
    code, withdrawal = _v2_request(
        base, "POST", "/withdraw", v2_identities["alice"],
        {"amount": MIN_WITHDRAW_CREDITS}, timestamp=timestamps.next(),
    )
    assert code == 200 and withdrawal["state"] == "pending"
    code, _ = _v2_request(
        base, "POST", "/withdraw", v2_identities["alice"],
        {"amount": MIN_WITHDRAW_CREDITS}, timestamp=timestamps.next(),
    )
    assert code == 429

    code, changed = _v2_request(
        base, "POST", "/wallet/bind", v2_identities["alice"],
        {"address": second_address}, timestamp=timestamps.next(),
    )
    assert code == 200 and changed["changed"] is True
    code, _ = _v2_request(
        base, "POST", "/withdraw", v2_identities["alice"],
        {"amount": MIN_WITHDRAW_CREDITS}, timestamp=timestamps.next(),
    )
    assert code == 403


def test_withdraw_tier_rule_allows_own_deposits_but_not_stranger_earnings(
    v2_server, v2_identities, timestamps, monkeypatch
):
    monkeypatch.setenv("NAK_FUNDS_ROUTES", "on")
    clock = [1_000_000]
    monkeypatch.setattr(ledger_store_module.time, "time", lambda: clock[0])
    signed_at = [clock[0] - 10]

    def next_signed_at():
        signed_at[0] += 1
        return signed_at[0]

    base, service = v2_server
    address = "1" * 32

    service.store.deposit(
        "own:0", "stranger-depositor", MIN_WITHDRAW_CREDITS, 1
    )
    code, _ = _v2_request(
        base, "POST", "/wallet/bind", v2_identities["stranger_depositor"],
        {"address": address}, timestamp=next_signed_at(),
    )
    assert code == 200
    code, _ = _v2_request(
        base, "POST", "/withdraw", v2_identities["stranger_depositor"],
        {"amount": MIN_WITHDRAW_CREDITS}, timestamp=next_signed_at(),
    )
    assert code == 200

    service.store.deposit("funded:0", "alice", MIN_WITHDRAW_CREDITS * 2, 2)
    service.store.settle(
        "earnings", "alice",
        {"mallory": MIN_WITHDRAW_CREDITS, "bob": MIN_WITHDRAW_CREDITS},
        MIN_WITHDRAW_CREDITS * 2, "self",
    )
    for who in ("mallory", "bob"):
        code, _ = _v2_request(
            base, "POST", "/wallet/bind", v2_identities[who],
            {"address": address}, timestamp=next_signed_at(),
        )
        assert code == 200
    clock[0] += HOLD_S + 1
    signed_at[0] = clock[0] - 10

    code, _ = _v2_request(
        base, "POST", "/withdraw", v2_identities["mallory"],
        {"amount": MIN_WITHDRAW_CREDITS}, timestamp=next_signed_at(),
    )
    assert code == 403
    code, _ = _v2_request(
        base, "POST", "/withdraw", v2_identities["bob"],
        {"amount": MIN_WITHDRAW_CREDITS}, timestamp=next_signed_at(),
    )
    assert code == 200


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
        json.dumps(
            {"balances": {"alice": 5, "bob": -5}, "settled": {}, "journal": []}
        ),
        encoding="utf-8",
    )
    target.write_bytes(b"do not overwrite")
    with pytest.raises(FileExistsError, match="--force"):
        migrate(source, target)
    assert target.read_bytes() == b"do not overwrite"

    migrate(source, target, force=True)
    with LedgerStore(target) as store:
        assert store.balance("alice") == 5
        assert store.balance("bob") == -5


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


@pytest.mark.parametrize("tier", ["Suspended", "SUSPENDED", "suspended ", " SuSpEnDeD"])
def test_suspended_tier_case_and_whitespace_variants_get_403(
    tmp_path, timestamps, monkeypatch, tier
):
    monkeypatch.setenv("NAK_FUNDS_ROUTES", "on")
    private, public = _v2_keypair()
    roster = tmp_path / "variant-peers.tsv"
    # tab-delimited so trailing/leading spaces survive into the tier field
    roster.write_text(f"{public}\tvariant-node\tvariant-op\t{tier}\ttest\n", encoding="utf-8")
    identity = {"private": private, "public": public}
    with _running_v2(tmp_path / "variant.sqlite", roster) as (base, _):
        assert _v2_request(
            base, "GET", "/balance", identity, timestamp=timestamps.next()
        ) == (403, {"error": "signing key is suspended"})


def test_mangled_short_roster_row_is_not_admitted(tmp_path, timestamps, monkeypatch):
    # Current behaviour: a row with fewer than 5 fields is silently skipped
    # (the loader's `len(fields) < 5: continue`), so the key is unrostered
    # and gets the same 401 as any unknown key -- never admitted, never a
    # stranger-tier row.
    monkeypatch.setenv("NAK_FUNDS_ROUTES", "on")
    private, public = _v2_keypair()
    roster = tmp_path / "short-peers.tsv"
    roster.write_text(f"{public}\tshort-node\tshort-op\tsuspended\n", encoding="utf-8")
    identity = {"private": private, "public": public}
    with _running_v2(tmp_path / "short.sqlite", roster) as (base, _):
        assert _v2_request(
            base, "GET", "/balance", identity, timestamp=timestamps.next()
        )[0] == 401
