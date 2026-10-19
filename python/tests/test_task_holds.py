"""M2 fixed-price task hold storage, API, migration, and race tests."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.ledger_store import (  # noqa: E402
    HOLD_S,
    TASK_DEADLINE_MAX_S,
    TASK_MAX_AMOUNT,
    TASK_REFUND_GRACE_S,
    CreditLimitError,
    LedgerStore,
    LedgerValueError,
    SpendConflict,
    SpendNotFound,
    SpendStateError,
)
from ledger_auth import canonical_string  # noqa: E402
from ledger_server import V2LedgerService, _make_v2_handler  # noqa: E402


def _identity(label: str) -> dict[str, object]:
    private = ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(label.encode()).digest()
    )
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return {"private": private, "public": public}


@pytest.fixture
def identities(tmp_path):
    result = {}
    rows = []
    for label, operator, tier in (
        ("payer", "payer", "trusted"),
        ("payer2", "payer", "trusted"),
        ("worker", "worker", "known"),
        ("outsider", "outsider", "known"),
    ):
        result[label] = _identity(label)
        rows.append(
            f"{result[label]['public']}\t{label}\t{operator}\t{tier}\ttest"
        )
    roster = tmp_path / "roster.tsv"
    roster.write_text("\n".join(rows) + "\n", encoding="utf-8")
    result["roster"] = roster
    return result


def _authorize(store, clock, *, nonce="nonce", task_hash="a" * 64, **changes):
    values = {
        "payer_keyid": "payer-key",
        "payer_account": "payer",
        "tier": "stranger",
        "client_nonce": nonce,
        "task_hash": task_hash,
        "worker_keyid": "worker-key",
        "worker_account": "worker",
        "amount": 100,
        "deadline": clock[0] + 60,
    }
    values.update(changes)
    return store.authorize_task_hold(**values)


def _total(store):
    return int(
        store._db.execute("SELECT COALESCE(SUM(balance), 0) FROM accounts").fetchone()[0]
    )


def test_pay_refund_replays_conflicts_conserve_and_earnings_mature(tmp_path):
    clock = [1_000_000]
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 1_000, 1)
        initial_total = _total(store)

        paid = _authorize(store, clock, nonce="pay", task_hash="1" * 64)
        result = store.pay_task_hold(paid["hold_id"], "payer-key")
        assert (result["state"], result["replayed"]) == ("paid", False)
        assert store.pay_task_hold(paid["hold_id"], "payer-key")["replayed"] is True
        with pytest.raises(SpendStateError, match="paid"):
            store.refund_task_hold(paid["hold_id"], "payer-key", "late")
        assert store.balance("worker") == 100
        assert store.withdrawable("worker") == 0
        clock[0] += HOLD_S + 1
        assert store.withdrawable("worker") == 100
        assert _total(store) == initial_total

        refunded = _authorize(
            store, clock, nonce="refund", task_hash="2" * 64,
            deadline=clock[0] + 60,
        )
        result = store.refund_task_hold(refunded["hold_id"], "payer-key", "rejected")
        assert (result["state"], result["replayed"]) == ("refunded", False)
        assert store.refund_task_hold(
            refunded["hold_id"], "payer-key", "different replay reason"
        )["replayed"] is True
        with pytest.raises(SpendStateError, match="refunded"):
            store.pay_task_hold(refunded["hold_id"], "payer-key")
        assert _total(store) == initial_total
        assert all(
            balance == 0
            for balance, in store._db.execute(
                "SELECT balance FROM accounts WHERE id LIKE '__spend_hold__:task:%'"
            )
        )


def test_party_scope_hides_holds_and_worker_is_read_only(tmp_path):
    clock = [2_000_000]
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 500, 1)
        hold = _authorize(store, clock)
        assert store.task_hold_status_scoped(
            hold["hold_id"], "worker-key"
        )["state"] == "open"
        for caller in ("worker-key", "outsider-key"):
            with pytest.raises(SpendNotFound, match="not found"):
                store.pay_task_hold(hold["hold_id"], caller)
            with pytest.raises(SpendNotFound, match="not found"):
                store.refund_task_hold(hold["hold_id"], caller, "no")
        with pytest.raises(SpendNotFound, match="not found"):
            store.task_hold_status_scoped(hold["hold_id"], "outsider-key")
        with pytest.raises(SpendNotFound, match="not found"):
            store.task_hold_status_scoped("missing", "worker-key")


def test_authorize_validation_capacity_nonce_and_open_task_uniqueness(tmp_path):
    clock = [3_000_000]
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        with pytest.raises(LedgerValueError, match="own account"):
            _authorize(store, clock, worker_account="payer")
        with pytest.raises(LedgerValueError, match="task_hash"):
            _authorize(store, clock, task_hash="A" * 64)
        for amount in (0, TASK_MAX_AMOUNT + 1, True):
            with pytest.raises(LedgerValueError, match="amount"):
                _authorize(store, clock, amount=amount)
        for deadline in (
            clock[0] + 59,
            clock[0] + TASK_DEADLINE_MAX_S + 1,
            True,
        ):
            with pytest.raises(LedgerValueError, match="deadline"):
                _authorize(store, clock, deadline=deadline)
        with pytest.raises(CreditLimitError):
            _authorize(store, clock, amount=1_000_001)

        store.deposit("funding", "payer", 1_000, 1)
        first = _authorize(store, clock)
        replay = _authorize(store, clock)
        assert replay["hold_id"] == first["hold_id"]
        with pytest.raises(SpendConflict, match="client_nonce"):
            _authorize(store, clock, amount=99)
        with pytest.raises(SpendConflict, match="open hold"):
            _authorize(store, clock, nonce="other")


def test_concurrent_pay_vs_expiry_has_one_terminal_outcome(tmp_path):
    for iteration in range(12):
        clock = [4_000_000 + iteration * 100_000]
        path = tmp_path / f"race-{iteration}.db"
        with LedgerStore(path, clock=lambda: clock[0]) as store:
            store.deposit(f"funding-{iteration}", "payer", 100, 1)
            hold = _authorize(store, clock, nonce=str(iteration))
            cutoff = hold["deadline"] + TASK_REFUND_GRACE_S
            clock[0] = cutoff - 1
            barrier = threading.Barrier(2)

            def pay():
                barrier.wait()
                try:
                    return store.pay_task_hold(hold["hold_id"], "payer-key")["state"]
                except SpendStateError:
                    return "lost"

            def sweep():
                barrier.wait()
                return hold["hold_id"] in store.expire_spend_holds_batch(
                    cutoff=cutoff
                ).affected

            with ThreadPoolExecutor(max_workers=2) as pool:
                pay_result = pool.submit(pay)
                sweep_result = pool.submit(sweep)
                paid = pay_result.result(timeout=5) == "paid"
                swept = sweep_result.result(timeout=5)
            status = store.task_hold_status(hold["hold_id"])
            assert (paid, swept) in {(True, False), (False, True)}
            assert status["state"] == ("paid" if paid else "refunded")
            assert store.balance("worker") == (100 if paid else 0)
            assert store.balance("payer") == (0 if paid else 100)
            assert _total(store) == 0


def test_expiry_sweep_refunds_only_after_deadline_grace(tmp_path):
    clock = [5_000_000]
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 100, 1)
        hold = _authorize(store, clock)
        cutoff = hold["deadline"] + TASK_REFUND_GRACE_S
        assert store.expire_spend_holds_batch(cutoff=cutoff - 1).affected == ()
        assert store.expire_spend_holds_batch(cutoff=cutoff).affected == (
            hold["hold_id"],
        )
        assert store.task_hold_status(hold["hold_id"])["state"] == "refunded"
        assert store.balance("payer") == 100
        assert _total(store) == 0


def test_migrates_real_forgejo_main_database_idempotently(tmp_path):
    base_source = subprocess.check_output(
        ["git", "show", "forgejo/main:python/core/ledger_store.py"], text=True
    )
    base_module = tmp_path / "base_ledger_store.py"
    base_module.write_text(base_source, encoding="utf-8")
    database = tmp_path / "ledger.db"
    driver = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location('base_ledger_store', sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
with module.LedgerStore(sys.argv[2], clock=lambda: 1000000) as store:
    store.deposit('base-funding', 'payer', 1000, 1)
    store.authorize_spend(
        payer_keyid='payer-key', payer_account='payer', tier='stranger',
        client_nonce='base-nonce', session_id='base-session', model_id='model',
        billing_mode='greedy-direct-v1', max_prompt_tokens=5,
        max_output_tokens=5, workers=[{
            'worker_keyid': 'worker-key', 'worker_account': 'worker',
            'layer_start': 0, 'layer_end': 4, 'price_multiplier': 2,
        }], hold_id='base-hold')
"""
    subprocess.run(
        [sys.executable, "-c", driver, str(base_module), str(database)], check=True
    )

    expected_balances = {
        "payer": 920,
        "treasury": -1_000,
        "__spend_hold__:base-hold": 80,
    }
    for _ in range(2):
        with LedgerStore(database, clock=lambda: 1_000_000) as store:
            assert store.spend_status("base-hold")["state"] == "open"
            assert {
                row["id"]: int(row["balance"])
                for row in store._db.execute(
                    "SELECT id, balance FROM accounts WHERE balance != 0"
                )
            } == expected_balances
            assert store._db.execute(
                "SELECT COUNT(*) FROM task_holds"
            ).fetchone()[0] == 0
            assert _total(store) == 0


@contextmanager
def _running(service):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_v2_handler(service))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(base, method, path, identity=None, obj=None):
    body = json.dumps(obj, separators=(",", ":")).encode() if obj is not None else b""
    headers = {}
    if identity is not None:
        timestamp = max(int(time.time()), getattr(_request, "last_timestamp", 0) + 1)
        _request.last_timestamp = timestamp
        signature = identity["private"].sign(
            canonical_string(method, path, body, timestamp)
        )
        headers["Authorization"] = (
            f'Sthambha-Ed25519 keyid="{identity["public"]}",'
            f'sig="{base64.b64encode(signature).decode()}",ts="{timestamp}"'
        )
    request = urllib.request.Request(
        base + path,
        data=body if obj is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _task_body(identities, now, **changes):
    body = {
        "client_nonce": "task-nonce",
        "task_hash": "a" * 64,
        "worker_keyid": identities["worker"]["public"],
        "amount": 100,
        "deadline": now + 60,
    }
    body.update(changes)
    return body


def test_signed_http_routes_gating_strict_shapes_scopes_and_codes(
    tmp_path, identities, monkeypatch
):
    clock = [6_000_000]
    service = V2LedgerService(
        tmp_path / "ledger.sqlite",
        identities["roster"],
        clock=lambda: clock[0],
        start_sweeper=False,
    )
    try:
        service.store.deposit("funding", "payer", 1_000, 1)
        body = _task_body(identities, clock[0])
        with _running(service) as base:
            monkeypatch.delenv("NAK_SPEND_ROUTES", raising=False)
            for method, path, obj in (
                ("POST", "/spend/task/authorize", body),
                ("POST", "/spend/task/pay", {"hold_id": "x"}),
                ("POST", "/spend/task/refund", {"hold_id": "x", "reason": "x"}),
                ("GET", "/spend/task/status?hold_id=x", None),
            ):
                assert _request(base, method, path, obj=obj)[0] == 404

            monkeypatch.setenv("NAK_SPEND_ROUTES", "on")
            assert _request(base, "POST", "/spend/task/authorize", obj=body)[0] == 401
            assert _request(
                base, "POST", "/spend/task/authorize", identities["payer"],
                {**body, "unknown": True},
            )[0] == 422
            code, authorization = _request(
                base, "POST", "/spend/task/authorize", identities["payer"], body
            )
            assert code == 200
            assert set(authorization) == {
                "v", "hold_id", "task_hash", "worker_keyid", "amount",
                "deadline", "state",
            }
            hold_id = authorization["hold_id"]
            path = f"/spend/task/status?hold_id={hold_id}"
            code, status = _request(base, "GET", path, identities["worker"])
            assert code == 200
            assert set(status) == {
                "v", "hold_id", "task_hash", "payer_account", "worker_keyid",
                "amount", "deadline", "state", "server_time",
            }
            for caller in (identities["worker"], identities["outsider"]):
                assert _request(
                    base, "POST", "/spend/task/pay", caller, {"hold_id": hold_id}
                ) == (404, {"error": "spend hold not found"})
                assert _request(
                    base, "POST", "/spend/task/refund", caller,
                    {"hold_id": hold_id, "reason": "no"},
                ) == (404, {"error": "spend hold not found"})
            assert _request(base, "GET", path, identities["outsider"]) == (
                404, {"error": "spend hold not found"}
            )
            code, paid = _request(
                base, "POST", "/spend/task/pay", identities["payer"],
                {"hold_id": hold_id},
            )
            assert (code, paid["state"], paid["replayed"]) == (200, "paid", False)
            assert _request(
                base, "POST", "/spend/task/pay", identities["payer"],
                {"hold_id": hold_id},
            )[1]["replayed"] is True
            assert _request(
                base, "POST", "/spend/task/refund", identities["payer"],
                {"hold_id": hold_id, "reason": "late"},
            )[0] == 409

            insufficient = _task_body(
                identities, clock[0], client_nonce="large", task_hash="b" * 64,
                amount=TASK_MAX_AMOUNT,
            )
            assert _request(
                base, "POST", "/spend/task/authorize", identities["payer"],
                insufficient,
            )[0] == 402
    finally:
        service.close()


def test_service_rejects_unknown_worker_self_pay_and_body_bounds(tmp_path, identities):
    clock = [7_000_000]
    service = V2LedgerService(
        tmp_path / "ledger.sqlite", identities["roster"],
        clock=lambda: clock[0], start_sweeper=False,
    )
    try:
        roster = service.rosters.snapshot()
        payer = identities["payer"]["public"]
        with pytest.raises(PermissionError, match="not rostered"):
            service.authorize_task_hold(
                _task_body(identities, clock[0], worker_keyid="f" * 64), payer, roster
            )
        with pytest.raises(LedgerValueError, match="own account"):
            service.authorize_task_hold(
                _task_body(
                    identities, clock[0],
                    worker_keyid=identities["payer2"]["public"],
                ),
                payer,
                roster,
            )
        for changes in (
            {"client_nonce": "x" * 129},
            {"task_hash": "A" * 64},
            {"amount": 0},
            {"deadline": clock[0] + 59},
            {"deadline": clock[0] + TASK_DEADLINE_MAX_S + 1},
        ):
            with pytest.raises(LedgerValueError):
                service.authorize_task_hold(
                    _task_body(identities, clock[0], **changes), payer, roster
                )
    finally:
        service.close()
