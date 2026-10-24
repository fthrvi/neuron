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
    TASK_DISPUTE_BACKSTOP_S,
    TASK_MAX_AMOUNT,
    TASK_REFUND_GRACE_S,
    CreditLimitError,
    LedgerStore,
    LedgerValueError,
    SpendConflict,
    SpendNotFound,
    SpendStateError,
    TaskHoldNotOpen,
    TaskSubmittedLocked,
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
        ("operator", "ledger-operator", "self"),
        ("selfpayer", "selfpayer", "self"),
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
                "SELECT balance FROM accounts WHERE id LIKE '__task_hold__:%'"
            )
        )


def test_suspended_task_worker_freezes_pay_and_silence_pay_but_not_refund(tmp_path):
    clock = [1_500_000]
    frozen = [True]
    is_frozen = lambda keyid: frozen[0] and keyid == "worker-key"
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 500, 1)
        direct = _authorize(store, clock, nonce="direct", task_hash="3" * 64)
        with pytest.raises(
            SpendConflict, match="worker is suspended; settlement is frozen"
        ):
            store.pay_task_hold(
                direct["hold_id"], "payer-key", is_frozen=is_frozen
            )
        assert store.task_hold_status(direct["hold_id"])["state"] == "open"
        assert store.balance("worker") == 0

        submitted = _authorize(
            store, clock, nonce="silence", task_hash="4" * 64
        )
        store.submit_task_hold(submitted["hold_id"], "worker-key", "a" * 64)
        store.receive_task_hold(submitted["hold_id"], "payer-key", "a" * 64)
        refundable = _authorize(
            store, clock, nonce="refund-frozen", task_hash="5" * 64
        )
        clock[0] = submitted["deadline"] + TASK_REFUND_GRACE_S

        store.expire_spend_holds(is_frozen=is_frozen)
        assert store.task_hold_status(submitted["hold_id"])["state"] == "open"
        assert store.task_hold_status(refundable["hold_id"])["state"] == "refunded"
        assert store.balance("worker") == 0

        frozen[0] = False
        assert store.expire_spend_holds(is_frozen=is_frozen) == [submitted["hold_id"]]
        assert store.task_hold_status(submitted["hold_id"])["state"] == "paid"
        assert store.balance("worker") == 100


def test_sweeper_uses_last_successful_roster_when_refresh_fails(
    tmp_path, identities
):
    clock = [1_600_000]
    service = V2LedgerService(
        tmp_path / "cached.sqlite",
        identities["roster"],
        clock=lambda: clock[0],
        start_sweeper=False,
    )
    try:
        service.store.deposit("funding", "payer", 200, 1)
        worker_keyid = identities["worker"]["public"]
        payable = _authorize(
            service.store,
            clock,
            nonce="cached-pay",
            worker_keyid=worker_keyid,
        )
        service.store.submit_task_hold(payable["hold_id"], worker_keyid, "a" * 64)
        service.store.receive_task_hold(payable["hold_id"], "payer-key", "a" * 64)
        clock[0] = payable["deadline"] + TASK_REFUND_GRACE_S
        service.rosters.refresh_seconds = 0
        identities["roster"].unlink()

        service._sweep_spend_holds_once()

        assert service.store.task_hold_status(payable["hold_id"])["state"] == "paid"
        assert service.store.balance("worker") == 100
        assert service._sweep_error == "FileNotFoundError"
    finally:
        service.close()


def test_sweeper_without_any_roster_snapshot_refunds_but_defers_pay(tmp_path):
    clock = [1_700_000]
    service = V2LedgerService(
        tmp_path / "no-roster.sqlite",
        tmp_path / "missing-roster.tsv",
        clock=lambda: clock[0],
        start_sweeper=False,
    )
    try:
        service.store.deposit("funding", "payer", 300, 1)
        payable = _authorize(
            service.store,
            clock,
            nonce="no-roster-pay",
            task_hash="b" * 64,
        )
        service.store.submit_task_hold(
            payable["hold_id"], "worker-key", "c" * 64
        )
        service.store.receive_task_hold(
            payable["hold_id"], "payer-key", "c" * 64
        )
        refundable = _authorize(
            service.store,
            clock,
            nonce="no-roster-refund",
            task_hash="d" * 64,
        )
        clock[0] = payable["deadline"] + TASK_REFUND_GRACE_S

        service._sweep_spend_holds_once()

        assert service.store.task_hold_status(payable["hold_id"])["state"] == "open"
        assert service.store.task_hold_status(refundable["hold_id"])["state"] == "refunded"
        assert service.store.balance("worker") == 0
        assert service._sweep_error == "FileNotFoundError"
    finally:
        service.close()


def _submitted(store, clock, nonce, task_hash, *, received=True):
    hold = _authorize(store, clock, nonce=nonce, task_hash=task_hash)
    store.submit_task_hold(hold["hold_id"], "worker-key", task_hash)
    if received:
        store.receive_task_hold(hold["hold_id"], "payer-key", task_hash)
    return hold


def test_operator_resolve_pay_refused_frozen_but_refund_allowed(tmp_path):
    clock = [1_750_000]
    frozen = lambda keyid: keyid == "worker-key"
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 300, 1)
        total = _total(store)
        pay = _submitted(store, clock, "resolve-pay", "6" * 64)
        refund = _submitted(store, clock, "resolve-refund", "7" * 64)
        for hold in (pay, refund):
            store.dispute_task_hold(
                hold["hold_id"], "payer-key", "quality", "n", is_frozen=frozen
            )
        with pytest.raises(
            SpendConflict, match="worker is suspended; settlement is frozen"
        ):
            store.resolve_task_hold(pay["hold_id"], "pay", "ok", is_frozen=frozen)
        assert store.task_hold_status(pay["hold_id"])["state"] == "disputed"
        assert store.balance("worker") == 0
        resolved = store.resolve_task_hold(
            refund["hold_id"], "refund", "fraud", is_frozen=frozen
        )
        assert resolved["state"] == "refunded"
        assert store.balance("payer") == 200
        # Unsuspended, the same disputed hold can be paid.
        assert store.resolve_task_hold(pay["hold_id"], "pay", "ok")["state"] == "paid"
        assert _total(store) == total


def test_operator_task_resolve_service_enforces_suspension(tmp_path, identities):
    clock = [1_900_000]
    service = V2LedgerService(
        tmp_path / "ledger.sqlite",
        identities["roster"],
        clock=lambda: clock[0],
        start_sweeper=False,
    )
    try:
        service.store.deposit("funding", "payer", 300, 1)
        roster = service.rosters.snapshot()
        payer = identities["payer"]["public"]
        worker = identities["worker"]["public"]
        ids = []
        for nonce, th in (("operator-pay", "8"), ("operator-refund", "9")):
            hold = service.authorize_task_hold(
                _task_body(
                    identities, clock[0], client_nonce=nonce, task_hash=th * 64,
                ),
                payer,
                roster,
            )
            service.submit_task_hold(
                {"hold_id": hold["hold_id"], "result_hash": th * 64}, worker, roster
            )
            service.dispute_task_hold(
                {"hold_id": hold["hold_id"], "reason": "q", "note": "n"}, payer, roster
            )
            ids.append(hold["hold_id"])
        suspended = {key: dict(row) for key, row in roster.items()}
        suspended[worker]["tier"] = "suspended"
        operator = identities["operator"]["public"]

        with pytest.raises(
            SpendConflict, match="worker is suspended; settlement is frozen"
        ):
            service.resolve_task_hold(
                {"hold_id": ids[0], "outcome": "pay", "reason": "ok"},
                operator,
                suspended,
            )
        assert service.store.task_hold_status(ids[0])["state"] == "disputed"
        resolved = service.resolve_task_hold(
            {"hold_id": ids[1], "outcome": "refund", "reason": "bad"},
            operator,
            suspended,
        )
        assert resolved["state"] == "refunded"
    finally:
        service.close()


def test_backstop_pay_to_suspended_worker_defers_then_pays_after_unsuspend(tmp_path):
    clock = [1_800_000]
    frozen = [True]
    is_frozen = lambda keyid: frozen[0] and keyid == "worker-key"
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 200, 1)
        total = _total(store)
        delivered = _submitted(store, clock, "bk-delivered", "3" * 64)
        missing = _submitted(store, clock, "bk-missing", "4" * 64, received=False)
        for hold in (delivered, missing):
            store.dispute_task_hold(
                hold["hold_id"], "payer-key", "review", "x", is_frozen=is_frozen
            )
        cutoff = delivered["deadline"] + TASK_DISPUTE_BACKSTOP_S
        clock[0] = cutoff
        # Delivered: deferred, not refunded.  Undelivered: refund to payer.
        assert store.expire_spend_holds(is_frozen=is_frozen) == [missing["hold_id"]]
        assert store.task_hold_status(delivered["hold_id"])["state"] == "disputed"
        assert store.task_hold_status(missing["hold_id"])["state"] == "refunded"
        assert store.balance("worker") == 0
        # Retried on the next sweep, still frozen.
        assert store.expire_spend_holds(is_frozen=is_frozen) == []
        assert store.task_hold_status(delivered["hold_id"])["state"] == "disputed"
        frozen[0] = False
        assert store.expire_spend_holds(is_frozen=is_frozen) == [delivered["hold_id"]]
        assert store.task_hold_status(delivered["hold_id"])["state"] == "paid"
        assert (store.balance("worker"), _total(store)) == (100, total)


def test_silence_pay_of_submitted_open_hold_defers_for_suspended_worker(tmp_path):
    clock = [1_850_000]
    frozen = [True]
    is_frozen = lambda keyid: frozen[0] and keyid == "worker-key"
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 100, 1)
        hold = _submitted(store, clock, "silence-frozen", "5" * 64)
        clock[0] = hold["deadline"] + TASK_REFUND_GRACE_S
        assert store.expire_spend_holds(is_frozen=is_frozen) == []
        assert store.task_hold_status(hold["hold_id"])["state"] == "open"
        assert store.balance("payer") == 0 and store.balance("worker") == 0
        frozen[0] = False
        assert store.expire_spend_holds(is_frozen=is_frozen) == [hold["hold_id"]]
        assert store.task_hold_status(hold["hold_id"])["state"] == "paid"


def test_dispute_works_while_worker_suspended_even_after_deferred_silence_pay(
    tmp_path,
):
    clock = [1_870_000]
    frozen = lambda keyid: keyid == "worker-key"
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 200, 1)
        early = _submitted(store, clock, "dispute-early", "a" * 64)
        late = _submitted(store, clock, "dispute-late", "b" * 64)
        d = store.dispute_task_hold(
            early["hold_id"], "payer-key", "quality", "n", is_frozen=frozen
        )
        assert d["state"] == "disputed"
        clock[0] = late["deadline"] + TASK_REFUND_GRACE_S
        d = store.dispute_task_hold(
            late["hold_id"], "payer-key", "quality", "n", is_frozen=frozen
        )
        assert d["state"] == "disputed"
        assert store.balance("worker") == 0


def test_suspended_payer_routes_denied_and_its_holds_follow_sweep_rules(
    tmp_path, identities, monkeypatch
):
    clock = [1_880_000]
    service = V2LedgerService(
        tmp_path / "ledger.sqlite", identities["roster"],
        clock=lambda: clock[0], start_sweeper=False,
    )
    try:
        service.store.deposit("funding", "payer", 200, 1)
        roster = service.rosters.snapshot()
        payer = identities["payer"]["public"]
        hold = service.authorize_task_hold(
            _task_body(identities, clock[0], client_nonce="sp", task_hash="c" * 64),
            payer, roster,
        )
        # Suspend the payer's operator rows in the roster file.
        text = identities["roster"].read_text()
        identities["roster"].write_text(
            text.replace("\ttrusted\t", "\tsuspended\t")
        )
        service.rosters.refresh_seconds = 0
        monkeypatch.setenv("NAK_SPEND_ROUTES", "on")
        with _running(service) as base:
            for path, body in (
                ("/spend/task/pay", {"hold_id": hold["hold_id"]}),
                ("/spend/task/refund", {"hold_id": hold["hold_id"], "reason": "r"}),
                ("/spend/task/dispute",
                 {"hold_id": hold["hold_id"], "reason": "r", "note": "n"}),
            ):
                code, _ = _request(base, "POST", path, identities["payer"], body)
                assert code in (401, 403), (path, code)
        # Unsubmitted hold expires: refund may credit the frozen payer balance.
        clock[0] = hold["deadline"] + TASK_REFUND_GRACE_S
        service._sweep_spend_holds_once()
        assert service.store.task_hold_status(hold["hold_id"])["state"] == "refunded"
        assert service.store.balance("payer") == 200
    finally:
        service.close()


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


def test_worker_submit_is_idempotent_hash_bound_and_terminal_aware(tmp_path):
    clock = [2_500_000]
    result_hash = "b" * 64
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 300, 1)
        hold = _authorize(store, clock)
        assert _total(store) == 0
        for caller in ("payer-key", "outsider-key"):
            with pytest.raises(SpendNotFound, match="not found"):
                store.submit_task_hold(hold["hold_id"], caller, result_hash)
        with pytest.raises(LedgerValueError, match="result_hash"):
            store.submit_task_hold(hold["hold_id"], "worker-key", "B" * 64)

        submitted = store.submit_task_hold(
            hold["hold_id"], "worker-key", result_hash
        )
        assert submitted["submitted_at"] == clock[0]
        assert submitted["result_hash"] == result_hash
        assert submitted["replayed"] is False
        assert _total(store) == 0
        assert store.submit_task_hold(
            hold["hold_id"], "worker-key", result_hash
        )["replayed"] is True
        with pytest.raises(SpendConflict, match="different result_hash"):
            store.submit_task_hold(hold["hold_id"], "worker-key", "c" * 64)

        store.pay_task_hold(hold["hold_id"], "payer-key")
        assert _total(store) == 0
        with pytest.raises(TaskHoldNotOpen) as exc:
            store.submit_task_hold(hold["hold_id"], "worker-key", result_hash)
        assert exc.value.state == "paid"

        refunded = _authorize(
            store, clock, nonce="refunded", task_hash="d" * 64,
        )
        store.refund_task_hold(refunded["hold_id"], "payer-key", "rejected")
        assert _total(store) == 0
        with pytest.raises(TaskHoldNotOpen) as exc:
            store.submit_task_hold(refunded["hold_id"], "worker-key", "e" * 64)
        assert exc.value.state == "refunded"

        expired = _authorize(
            store, clock, nonce="expired", task_hash="f" * 64,
        )
        clock[0] = expired["deadline"] + TASK_REFUND_GRACE_S
        with pytest.raises(TaskHoldNotOpen, match="deadline passed") as exc:
            store.submit_task_hold(expired["hold_id"], "worker-key", "f" * 64)
        assert exc.value.state == "open"
        expired_status = store.task_hold_status(expired["hold_id"])
        assert expired_status["state"] == "open"
        assert (expired_status["submitted_at"], expired_status["result_hash"]) == (0, "")
        assert store.expire_spend_holds_batch(cutoff=clock[0]).affected == (
            expired["hold_id"],
        )
        assert store.task_hold_status(expired["hold_id"])["state"] == "refunded"
        assert _total(store) == 0


def test_payer_received_is_scoped_idempotent_hash_bound_and_accepts_late_delivery(
    tmp_path,
):
    clock = [2_750_000]
    submitted_hash = "7" * 64
    received_hash = "8" * 64
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 200, 1)
        hold = _authorize(store, clock)
        for caller in ("worker-key", "outsider-key"):
            with pytest.raises(SpendNotFound, match="not found"):
                store.receive_task_hold(hold["hold_id"], caller, received_hash)
        with pytest.raises(SpendConflict, match="no pre-deadline submission"):
            store.receive_task_hold(hold["hold_id"], "payer-key", received_hash)

        store.submit_task_hold(hold["hold_id"], "worker-key", submitted_hash)
        clock[0] = hold["deadline"] + 1
        with pytest.raises(LedgerValueError, match="result_hash"):
            store.receive_task_hold(hold["hold_id"], "payer-key", "A" * 64)
        received = store.receive_task_hold(
            hold["hold_id"], "payer-key", received_hash
        )
        assert received["received_at"] == clock[0]
        assert received["received_hash"] == received_hash
        assert received["replayed"] is False
        assert store.receive_task_hold(
            hold["hold_id"], "payer-key", received_hash
        )["replayed"] is True
        with pytest.raises(SpendConflict, match="different result_hash"):
            store.receive_task_hold(hold["hold_id"], "payer-key", "9" * 64)
        assert _total(store) == 0

        store.pay_task_hold(hold["hold_id"], "payer-key")
        with pytest.raises(TaskHoldNotOpen) as exc:
            store.receive_task_hold(hold["hold_id"], "payer-key", received_hash)
        assert exc.value.state == "paid"

        late_mark = _authorize(
            store, clock, nonce="late-mark", task_hash="6" * 64,
            deadline=clock[0] + 60,
        )
        store._db.execute("DROP TRIGGER task_holds_submission_transition")
        store._db.execute(
            "UPDATE task_holds SET submitted_at=?, result_hash=? WHERE hold_id=?",
            (late_mark["deadline"] + 1, submitted_hash, late_mark["hold_id"]),
        )
        with pytest.raises(SpendConflict, match="no pre-deadline submission"):
            store.receive_task_hold(
                late_mark["hold_id"], "payer-key", received_hash
            )


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


def test_concurrent_pay_refund_received_and_sweep_never_double_settle(tmp_path):
    for iteration in range(12):
        clock = [4_000_000 + iteration * 100_000]
        path = tmp_path / f"race-{iteration}.db"
        with LedgerStore(path, clock=lambda: clock[0]) as store:
            store.deposit(f"funding-{iteration}", "payer", 100, 1)
            hold = _authorize(store, clock, nonce=str(iteration))
            store.submit_task_hold(hold["hold_id"], "worker-key", "f" * 64)
            assert _total(store) == 0
            cutoff = hold["deadline"] + TASK_REFUND_GRACE_S
            clock[0] = cutoff
            barrier = threading.Barrier(4)

            def pay():
                barrier.wait()
                try:
                    return store.pay_task_hold(hold["hold_id"], "payer-key")["state"]
                except SpendStateError:
                    return "lost"

            def refund():
                barrier.wait()
                try:
                    return store.refund_task_hold(
                        hold["hold_id"], "payer-key", "rejected"
                    )["state"]
                except SpendStateError:
                    return "lost"

            def sweep():
                barrier.wait()
                return hold["hold_id"] in store.expire_spend_holds_batch(
                    cutoff=cutoff
                ).affected

            def received():
                barrier.wait()
                try:
                    return store.receive_task_hold(
                        hold["hold_id"], "payer-key", "f" * 64
                    )["state"]
                except TaskHoldNotOpen:
                    return "lost"

            with ThreadPoolExecutor(max_workers=4) as pool:
                pay_result = pool.submit(pay)
                refund_result = pool.submit(refund)
                sweep_result = pool.submit(sweep)
                received_result = pool.submit(received)
                pay_result.result(timeout=5)
                refund_result.result(timeout=5)
                sweep_result.result(timeout=5)
                received_result.result(timeout=5)
            status = store.task_hold_status(hold["hold_id"])
            paid = status["state"] == "paid"
            assert status["state"] in {"paid", "refunded"}
            assert store.balance("worker") == (100 if paid else 0)
            assert store.balance("payer") == (0 if paid else 100)
            assert store._db.execute(
                "SELECT COUNT(*) FROM journal WHERE receipt_id IN (?, ?)",
                (f"task-pay:{hold['hold_id']}", f"task-refund:{hold['hold_id']}"),
            ).fetchone()[0] == 2
            assert store._db.execute(
                "SELECT COUNT(*) FROM task_earnings WHERE hold_id=?",
                (hold["hold_id"],),
            ).fetchone()[0] == int(paid)
            assert _total(store) == 0


def test_expiry_sweep_pays_only_matching_submitted_and_received_matrix(tmp_path):
    clock = [5_000_000]
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 400, 1)
        submitted_only = _authorize(store, clock, nonce="submitted-only")
        received_only = _authorize(
            store, clock, nonce="received-only", task_hash="b" * 64,
        )
        both_equal = _authorize(
            store, clock, nonce="both-equal", task_hash="c" * 64,
        )
        both_unequal = _authorize(
            store, clock, nonce="both-unequal", task_hash="d" * 64,
        )
        store.submit_task_hold(submitted_only["hold_id"], "worker-key", "a" * 64)
        store.submit_task_hold(both_equal["hold_id"], "worker-key", "c" * 64)
        store.receive_task_hold(both_equal["hold_id"], "payer-key", "c" * 64)
        store.submit_task_hold(both_unequal["hold_id"], "worker-key", "d" * 64)
        store.receive_task_hold(both_unequal["hold_id"], "payer-key", "e" * 64)

        # This state cannot be produced by the API or receipt trigger.  Exercise
        # it explicitly so the settlement rule remains fail-closed even if a
        # future migration imports a partial/corrupt receipt.
        store._db.execute("DROP TRIGGER task_holds_receipt_transition")
        store._db.execute(
            "UPDATE task_holds SET received_at=?, received_hash=? WHERE hold_id=?",
            (clock[0], "b" * 64, received_only["hold_id"]),
        )
        assert _total(store) == 0
        cutoff = submitted_only["deadline"] + TASK_REFUND_GRACE_S
        assert store.expire_spend_holds_batch(cutoff=cutoff - 1).affected == ()
        assert set(store.expire_spend_holds_batch(cutoff=cutoff).affected) == {
            submitted_only["hold_id"], received_only["hold_id"],
            both_equal["hold_id"], both_unequal["hold_id"],
        }
        assert store.task_hold_status(submitted_only["hold_id"])["state"] == "refunded"
        assert store.task_hold_status(received_only["hold_id"])["state"] == "refunded"
        assert store.task_hold_status(both_equal["hold_id"])["state"] == "paid"
        assert store.task_hold_status(both_unequal["hold_id"])["state"] == "refunded"
        assert store.balance("worker") == 100
        assert store.balance("payer") == 300
        assert _total(store) == 0

        clock[0] = cutoff + HOLD_S + 1
        assert store.withdrawable("worker") == 100
        silence_detail = json.dumps(
            {"hold_id": both_equal["hold_id"], "paid_by_silence": True},
            sort_keys=True,
            separators=(",", ":"),
        )
        rows = store._db.execute(
            "SELECT detail FROM journal WHERE receipt_id=? ORDER BY seq",
            (f"task-pay:{both_equal['hold_id']}",),
        ).fetchall()
        assert [row["detail"] for row in rows] == [silence_detail, silence_detail]

        tampered_detail = json.dumps(
            {
                "hold_id": both_equal["hold_id"],
                "paid_by_silence": True,
                "tampered": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        store._db.execute("DROP TRIGGER journal_no_update")
        store._db.execute(
            "UPDATE journal SET detail=? WHERE receipt_id=?",
            (tampered_detail, f"task-pay:{both_equal['hold_id']}"),
        )
        assert store.withdrawable("worker") == 0


def test_refund_after_submit_is_locked_and_writes_nothing(tmp_path):
    clock = [5_500_000]
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 100, 1)
        hold = _authorize(store, clock)
        store.submit_task_hold(hold["hold_id"], "worker-key", "a" * 64)
        assert _total(store) == 0
        journal_count = store._db.execute("SELECT COUNT(*) FROM journal").fetchone()[0]
        with pytest.raises(TaskSubmittedLocked, match="worker has submitted"):
            store.refund_task_hold(hold["hold_id"], "payer-key", "rejected")
        assert _total(store) == 0
        assert store._db.execute("SELECT COUNT(*) FROM journal").fetchone()[0] == journal_count
        status = store.task_hold_status(hold["hold_id"])
        assert status["state"] == "open" and status["locked"] is True


def test_dispute_is_scoped_idempotent_sweep_proof_and_operator_resolves(tmp_path):
    clock = [5_600_000]
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 300, 1)
        initial_total = _total(store)

        pay = _authorize(store, clock, nonce="dispute-pay", task_hash="1" * 64)
        with pytest.raises(SpendStateError, match="has not been submitted"):
            store.dispute_task_hold(pay["hold_id"], "payer-key", "quality", "early")
        store.submit_task_hold(pay["hold_id"], "worker-key", "1" * 64)
        store.receive_task_hold(pay["hold_id"], "payer-key", "1" * 64)
        with pytest.raises(SpendNotFound):
            store.dispute_task_hold(pay["hold_id"], "outsider-key", "quality", "no")
        disputed = store.dispute_task_hold(
            pay["hold_id"], "payer-key", "quality", "untrusted <note>"
        )
        assert (disputed["state"], disputed["replayed"]) == ("disputed", False)
        assert disputed["dispute_reason"] == "quality" and disputed["locked"] is True
        assert store.dispute_task_hold(
            pay["hold_id"], "payer-key", "quality", "untrusted <note>"
        )["replayed"] is True
        with pytest.raises(SpendConflict, match="different details"):
            store.dispute_task_hold(
                pay["hold_id"], "payer-key", "other", "untrusted <note>"
            )
        clock[0] = pay["deadline"] + TASK_REFUND_GRACE_S
        assert store.expire_spend_holds_batch(cutoff=clock[0]).affected == ()
        assert store.task_hold_status(pay["hold_id"])["state"] == "disputed"
        resolved = store.resolve_task_hold(pay["hold_id"], "pay", "evidence_valid")
        assert (resolved["state"], resolved["replayed"]) == ("paid", False)
        assert store.resolve_task_hold(
            pay["hold_id"], "pay", "evidence_valid"
        )["replayed"] is True
        with pytest.raises(SpendConflict, match="different outcome"):
            store.resolve_task_hold(pay["hold_id"], "refund", "evidence_valid")

        refund = _authorize(
            store, clock, nonce="dispute-refund", task_hash="2" * 64,
            deadline=clock[0] + 60,
        )
        store.submit_task_hold(refund["hold_id"], "worker-key", "2" * 64)
        store.dispute_task_hold(refund["hold_id"], "payer-key", "invalid", "bad")
        result = store.resolve_task_hold(refund["hold_id"], "refund", "fraud_confirmed")
        assert (result["state"], result["replayed"]) == ("refunded", False)
        assert store.balance("worker") == 100
        assert _total(store) == initial_total

        pay_detail = json.loads(store._db.execute(
            "SELECT detail FROM journal WHERE receipt_id=? ORDER BY seq LIMIT 1",
            (f"task-pay:{pay['hold_id']}",),
        ).fetchone()[0])
        assert pay_detail == {
            "hold_id": pay["hold_id"], "resolved_by": "operator",
            "dispute_reason": "quality", "resolution_reason": "evidence_valid",
        }
        clock[0] += HOLD_S + 1
        assert store.withdrawable("worker") == 100


def test_dispute_backstop_pays_proven_delivery_and_refunds_without_receipt(tmp_path):
    clock = [5_700_000]
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 200, 1)
        delivered = _authorize(store, clock, nonce="delivered", task_hash="3" * 64)
        missing = _authorize(store, clock, nonce="missing", task_hash="4" * 64)
        store.submit_task_hold(delivered["hold_id"], "worker-key", "3" * 64)
        store.receive_task_hold(delivered["hold_id"], "payer-key", "3" * 64)
        store.submit_task_hold(missing["hold_id"], "worker-key", "4" * 64)
        store.dispute_task_hold(delivered["hold_id"], "payer-key", "review", "a")
        store.dispute_task_hold(missing["hold_id"], "payer-key", "review", "b")

        cutoff = delivered["deadline"] + TASK_DISPUTE_BACKSTOP_S
        assert store.expire_spend_holds_batch(cutoff=cutoff - 1).affected == ()
        assert set(store.expire_spend_holds_batch(cutoff=cutoff).affected) == {
            delivered["hold_id"], missing["hold_id"],
        }
        assert store.task_hold_status(delivered["hold_id"])["state"] == "paid"
        assert store.task_hold_status(missing["hold_id"])["state"] == "refunded"
        assert (store.balance("worker"), store.balance("payer"), _total(store)) == (
            100, 100, 0,
        )
        for prefix, hold in (("task-pay", delivered), ("task-refund", missing)):
            details = store._db.execute(
                "SELECT detail FROM journal WHERE receipt_id=? ORDER BY seq",
                (f"{prefix}:{hold['hold_id']}",),
            ).fetchall()
            assert details and all(json.loads(row[0])["dispute_backstop"] for row in details)
        clock[0] = cutoff + HOLD_S + 1
        assert store.withdrawable("worker") == 100


def test_migrates_real_forgejo_main_database_idempotently(tmp_path):
    base_source = subprocess.check_output(
        ["git", "show", "4ee5314:python/core/ledger_store.py"], text=True
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
    store.authorize_task_hold(
        payer_keyid='payer-key', payer_account='payer', tier='stranger',
        client_nonce='base-task-nonce', task_hash='9' * 64,
        worker_keyid='worker-key', worker_account='worker', amount=50,
        deadline=1000060, hold_id='base-task-hold')
    store.authorize_task_hold(
        payer_keyid='payer-key', payer_account='payer', tier='stranger',
        client_nonce='base-paid-nonce', task_hash='8' * 64,
        worker_keyid='worker-key', worker_account='worker', amount=25,
        deadline=1000060, hold_id='base-paid-task')
    store.pay_task_hold('base-paid-task', 'payer-key')
"""
    subprocess.run(
        [sys.executable, "-c", driver, str(base_module), str(database)], check=True
    )

    expected_balances = {
        "payer": 845,
        "worker": 25,
        "treasury": -1_000,
        "__spend_hold__:base-hold": 80,
        "__task_hold__:base-task-hold": 50,
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
            ).fetchone()[0] == 2
            assert store.task_hold_status("base-paid-task")["state"] == "paid"
            assert store._db.execute(
                "SELECT COUNT(*) FROM task_earnings WHERE hold_id='base-paid-task'"
            ).fetchone()[0] == 1
            task = store.task_hold_status("base-task-hold")
            assert (task["submitted_at"], task["result_hash"]) == (0, "")
            assert (task["received_at"], task["received_hash"]) == (0, "")
            assert task["dispute_reason"] is None and task["locked"] is False
            table_sql = store._db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='task_holds'"
            ).fetchone()[0]
            assert "'disputed'" in table_sql
            assert {
                "dispute_reason", "dispute_note", "disputed_at",
                "resolved_outcome", "resolution_reason",
            }.issubset({
                row[1] for row in store._db.execute("PRAGMA table_info(task_holds)")
            })
            assert store._db.execute("PRAGMA foreign_key_check").fetchone() is None
            assert _total(store) == 0

    with LedgerStore(database, clock=lambda: 1_000_000) as store:
        store.submit_task_hold("base-task-hold", "worker-key", "9" * 64)
        disputed = store.dispute_task_hold(
            "base-task-hold", "payer-key", "migration_check", "preserved"
        )
        assert disputed["state"] == "disputed"
        assert store._db.execute("PRAGMA foreign_key_check").fetchone() is None


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
                ("POST", "/spend/task/submit", {"hold_id": "x", "result_hash": "a" * 64}),
                ("POST", "/spend/task/received", {"hold_id": "x", "result_hash": "a" * 64}),
                ("POST", "/spend/task/pay", {"hold_id": "x"}),
                ("POST", "/spend/task/refund", {"hold_id": "x", "reason": "x"}),
                ("POST", "/spend/task/dispute", {"hold_id": "x", "reason": "x", "note": ""}),
                ("POST", "/spend/task/resolve", {"hold_id": "x", "outcome": "pay", "reason": "x"}),
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
                "amount", "deadline", "state", "submitted_at", "result_hash",
                "received_at", "received_hash", "dispute_reason", "locked",
                "refund_after_submit", "server_time",
            }
            assert (status["submitted_at"], status["result_hash"]) == (0, "")
            assert (status["received_at"], status["received_hash"]) == (0, "")
            assert status["dispute_reason"] is None and status["locked"] is False
            assert status["refund_after_submit"] is False
            submit_body = {"hold_id": hold_id, "result_hash": "b" * 64}
            for caller in (identities["payer"], identities["outsider"]):
                assert _request(
                    base, "POST", "/spend/task/submit", caller, submit_body
                ) == (404, {"error": "spend hold not found"})
            received_body = {"hold_id": hold_id, "result_hash": "b" * 64}
            for caller in (identities["worker"], identities["outsider"]):
                assert _request(
                    base, "POST", "/spend/task/received", caller, received_body
                ) == (404, {"error": "spend hold not found"})
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
            assert _request(
                base, "POST", "/spend/task/submit", identities["worker"],
                {**submit_body, "unknown": True},
            )[0] == 422
            code, submitted = _request(
                base, "POST", "/spend/task/submit", identities["worker"], submit_body
            )
            assert (code, submitted["state"], submitted["replayed"]) == (
                200, "open", False,
            )
            assert submitted["submitted_at"] == clock[0]
            assert submitted["result_hash"] == "b" * 64
            assert _request(
                base, "POST", "/spend/task/submit", identities["worker"], submit_body
            )[1]["replayed"] is True
            assert _request(
                base, "POST", "/spend/task/submit", identities["worker"],
                {**submit_body, "result_hash": "c" * 64},
            )[0] == 409
            assert _request(
                base, "POST", "/spend/task/received", identities["payer"],
                {**received_body, "unknown": True},
            )[0] == 422
            code, received = _request(
                base, "POST", "/spend/task/received", identities["payer"],
                received_body,
            )
            assert (code, received["state"], received["replayed"]) == (
                200, "open", False,
            )
            assert received["received_at"] == clock[0]
            assert received["received_hash"] == "b" * 64
            assert _request(
                base, "POST", "/spend/task/received", identities["payer"],
                received_body,
            )[1]["replayed"] is True
            assert _request(
                base, "POST", "/spend/task/received", identities["payer"],
                {**received_body, "result_hash": "c" * 64},
            )[0] == 409
            code, status = _request(base, "GET", path, identities["worker"])
            assert code == 200
            assert (status["submitted_at"], status["result_hash"]) == (
                clock[0], "b" * 64,
            )
            assert (status["received_at"], status["received_hash"]) == (
                clock[0], "b" * 64,
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
            assert _request(
                base, "POST", "/spend/task/submit", identities["worker"], submit_body
            ) == (409, {"error": "task hold is paid", "state": "paid"})
            assert _request(
                base, "POST", "/spend/task/received", identities["payer"], received_body
            ) == (409, {"error": "task hold is paid", "state": "paid"})

            refund_body = _task_body(
                identities, clock[0], client_nonce="refund-terminal",
                task_hash="d" * 64,
            )
            code, authorization = _request(
                base, "POST", "/spend/task/authorize", identities["payer"],
                refund_body,
            )
            assert code == 200
            refunded_id = authorization["hold_id"]
            assert _request(
                base, "POST", "/spend/task/refund", identities["payer"],
                {"hold_id": refunded_id, "reason": "rejected"},
            )[0] == 200
            assert _request(
                base, "POST", "/spend/task/submit", identities["worker"],
                {"hold_id": refunded_id, "result_hash": "e" * 64},
            ) == (409, {"error": "task hold is refunded", "state": "refunded"})
            assert _total(service.store) == 0

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


def test_submit_deadline_is_inclusive_late_submit_writes_nothing_and_status_flags_refund(
    tmp_path, identities, monkeypatch
):
    clock = [6_500_000]
    service = V2LedgerService(
        tmp_path / "ledger.sqlite", identities["roster"],
        clock=lambda: clock[0], start_sweeper=False,
    )
    try:
        service.store.deposit("funding", "payer", 200, 1)
        monkeypatch.setenv("NAK_SPEND_ROUTES", "on")
        deadline = clock[0] + 60
        with _running(service) as base:
            exact = _request(
                base, "POST", "/spend/task/authorize", identities["payer"],
                _task_body(identities, clock[0], deadline=deadline),
            )[1]
            late = _request(
                base, "POST", "/spend/task/authorize", identities["payer"],
                _task_body(
                    identities, clock[0], client_nonce="late", task_hash="f" * 64,
                    deadline=deadline,
                ),
            )[1]

            clock[0] = deadline
            exact_submit = {"hold_id": exact["hold_id"], "result_hash": "1" * 64}
            assert _request(
                base, "POST", "/spend/task/submit", identities["worker"], exact_submit
            )[0] == 200

            clock[0] = deadline + 1
            before = service.store.task_hold_status(late["hold_id"])
            journal_count = service.store._db.execute(
                "SELECT COUNT(*) FROM journal"
            ).fetchone()[0]
            balances = service.store._db.execute(
                "SELECT id, balance FROM accounts ORDER BY id"
            ).fetchall()
            late_submit = {"hold_id": late["hold_id"], "result_hash": "2" * 64}
            assert _request(
                base, "POST", "/spend/task/submit", identities["worker"], late_submit
            ) == (409, {"error": "deadline passed", "state": "open"})
            after = service.store.task_hold_status(late["hold_id"])
            assert (before["submitted_at"], before["result_hash"]) == (0, "")
            assert after == before
            assert service.store._db.execute(
                "SELECT COUNT(*) FROM journal"
            ).fetchone()[0] == journal_count
            assert service.store._db.execute(
                "SELECT id, balance FROM accounts ORDER BY id"
            ).fetchall() == balances

            assert _request(
                base, "POST", "/spend/task/refund", identities["payer"],
                {"hold_id": exact["hold_id"], "reason": "rejected"},
            ) == (
                409,
                {
                    "error": (
                        "The worker has submitted. Accept to pay, or dispute; "
                        "you cannot take the reward back yourself."
                    ),
                    "code": "task_submitted_locked",
                },
            )
            exact_path = f"/spend/task/status?hold_id={exact['hold_id']}"
            late_path = f"/spend/task/status?hold_id={late['hold_id']}"
            exact_status = _request(
                base, "GET", exact_path, identities["worker"]
            )[1]
            late_status = _request(
                base, "GET", late_path, identities["worker"]
            )[1]
            assert exact_status["refund_after_submit"] is False
            assert exact_status["locked"] is True and exact_status["state"] == "open"
            assert late_status["refund_after_submit"] is False
    finally:
        service.close()


def test_signed_dispute_and_operator_resolve_routes(tmp_path, identities, monkeypatch):
    clock = [6_800_000]
    service = V2LedgerService(
        tmp_path / "ledger.sqlite", identities["roster"],
        clock=lambda: clock[0], start_sweeper=False,
    )
    try:
        service.store.deposit("funding", "payer", 100, 1)
        monkeypatch.setenv("NAK_SPEND_ROUTES", "on")
        with _running(service) as base:
            authorization = _request(
                base, "POST", "/spend/task/authorize", identities["payer"],
                _task_body(identities, clock[0]),
            )[1]
            hold_id = authorization["hold_id"]
            _request(
                base, "POST", "/spend/task/submit", identities["worker"],
                {"hold_id": hold_id, "result_hash": "5" * 64},
            )
            locked = _request(
                base, "POST", "/spend/task/refund", identities["payer"],
                {"hold_id": hold_id, "reason": "reject"},
            )
            assert locked[0] == 409 and locked[1]["code"] == "task_submitted_locked"
            dispute = {"hold_id": hold_id, "reason": "quality", "note": "review <raw>"}
            assert _request(
                base, "POST", "/spend/task/dispute", identities["outsider"], dispute,
            ) == (404, {"error": "spend hold not found"})
            code, result = _request(
                base, "POST", "/spend/task/dispute", identities["payer"], dispute,
            )
            assert (code, result["state"], result["replayed"]) == (
                200, "disputed", False,
            )
            assert _request(
                base, "POST", "/spend/task/dispute", identities["payer"], dispute,
            )[1]["replayed"] is True
            status = _request(
                base, "GET", f"/spend/task/status?hold_id={hold_id}",
                identities["worker"],
            )[1]
            assert status["state"] == "disputed"
            assert status["dispute_reason"] == "quality" and status["locked"] is True

            resolution = {
                "hold_id": hold_id, "outcome": "pay", "reason": "evidence_valid",
            }
            assert _request(
                base, "POST", "/spend/task/resolve", identities["payer"], resolution,
            ) == (403, {"error": "only the ledger operator may resolve task disputes"})
            code, result = _request(
                base, "POST", "/spend/task/resolve", identities["operator"], resolution,
            )
            assert (code, result["state"], result["replayed"]) == (200, "paid", False)
            assert _request(
                base, "POST", "/spend/task/resolve", identities["operator"], resolution,
            )[1]["replayed"] is True

            refund_hold = _request(
                base, "POST", "/spend/task/authorize", identities["payer"],
                _task_body(
                    identities, clock[0], client_nonce="refund-dispute",
                    task_hash="6" * 64,
                ),
            )[1]
            refund_id = refund_hold["hold_id"]
            _request(
                base, "POST", "/spend/task/submit", identities["worker"],
                {"hold_id": refund_id, "result_hash": "6" * 64},
            )
            _request(
                base, "POST", "/spend/task/dispute", identities["payer"],
                {"hold_id": refund_id, "reason": "invalid", "note": "bad"},
            )
            code, result = _request(
                base, "POST", "/spend/task/resolve", identities["operator"],
                {"hold_id": refund_id, "outcome": "refund", "reason": "confirmed"},
            )
            assert (code, result["state"], result["replayed"]) == (
                200, "refunded", False,
            )
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


def test_task_accounts_use_their_own_reserved_stem_and_unbacked_ones_refuse_startup(tmp_path):
    from core.ledger_store import is_reserved

    assert is_reserved("__task_hold__:abc") and is_reserved("__spend_hold__:abc")
    clock = [1_000_000]
    database = tmp_path / "ledger.db"
    with LedgerStore(database, clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 1_000, 1)
        hold = _authorize(store, clock, nonce="n", task_hash="5" * 64)
        assert store._db.execute(
            "SELECT escrow_account FROM task_holds WHERE hold_id=?", (hold["hold_id"],)
        ).fetchone()[0] == f"__task_hold__:{hold['hold_id']}"
        store._db.execute(
            "INSERT INTO accounts(id, balance) VALUES ('__task_hold__:ghost', 0)"
        )
        store._db.commit()
    with pytest.raises(Exception, match="not backed by a task hold"):
        LedgerStore(database, clock=lambda: clock[0])


def test_forgejo_main_code_still_opens_a_store_with_paid_and_open_task_holds(tmp_path):
    clock = [1_000_000]
    database = tmp_path / "ledger.db"
    with LedgerStore(database, clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 1_000, 1)
        paid = _authorize(store, clock, nonce="p", task_hash="6" * 64)
        store.pay_task_hold(paid["hold_id"], "payer-key")
        opened = _authorize(
            store, clock, nonce="o", task_hash="7" * 64, amount=50
        )
        store.submit_task_hold(opened["hold_id"], "worker-key", "8" * 64)
        store.receive_task_hold(opened["hold_id"], "payer-key", "8" * 64)
        new_total = _total(store)
        new_balances = {
            row["id"]: int(row["balance"])
            for row in store._db.execute("SELECT id, balance FROM accounts WHERE balance != 0")
        }
    assert "payer" in new_balances and any(k.startswith("__task_hold__:") for k in new_balances)
    base_module = tmp_path / "base_ledger_store.py"
    base_module.write_text(
        subprocess.check_output(["git", "show", "4ee5314:python/core/ledger_store.py"],
                                text=True, cwd=os.path.dirname(__file__)),
        encoding="utf-8",
    )
    driver = """
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('base_ledger_store', sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
with module.LedgerStore(sys.argv[2], clock=lambda: 1000000) as store:
    rows = store._db.execute('SELECT id, balance FROM accounts WHERE balance != 0').fetchall()
    total = store._db.execute('SELECT COALESCE(SUM(balance), 0) FROM accounts').fetchone()[0]
    print(json.dumps({'total': total, 'balances': {r[0]: r[1] for r in rows}}))
"""
    out = subprocess.run(
        [sys.executable, "-c", driver, str(base_module), str(database)],
        check=True, capture_output=True, text=True,
    )
    opened = json.loads(out.stdout.strip().splitlines()[-1])
    assert opened["total"] == new_total == 0
    assert opened["balances"] == new_balances


def test_identical_authorize_replay_near_the_deadline_returns_the_same_hold(tmp_path, identities):
    clock = [7_000_000]
    service = V2LedgerService(
        tmp_path / "ledger.sqlite", identities["roster"],
        clock=lambda: clock[0], start_sweeper=False,
    )
    try:
        roster = service.rosters.snapshot()
        payer = identities["payer"]["public"]
        service.store.deposit("funding", "payer", 1_000, 1)
        body = _task_body(identities, clock[0], deadline=clock[0] + 120)
        first = service.authorize_task_hold(body, payer, roster)
        clock[0] += 100                                   # now only 20 s remain: inside the 60 s floor
        assert service.authorize_task_hold(dict(body), payer, roster)["hold_id"] == first["hold_id"]
        with pytest.raises(SpendConflict):                # a changed field is still a conflict
            service.authorize_task_hold(dict(body, amount=101), payer, roster)
        with pytest.raises(LedgerValueError):             # a NEW hold still needs the window
            service.authorize_task_hold(
                dict(body, client_nonce="other", task_hash="b" * 64), payer, roster)
    finally:
        service.close()


def test_late_dispute_cannot_evade_silence_pay_or_expiry(tmp_path):
    clock = [5_900_000]
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 300, 1)
        silent = _authorize(store, clock, nonce="late-pay", task_hash="7" * 64)
        store.submit_task_hold(silent["hold_id"], "worker-key", "7" * 64)
        store.receive_task_hold(silent["hold_id"], "payer-key", "7" * 64)
        expired = _authorize(store, clock, nonce="late-exp", task_hash="8" * 64)
        store.submit_task_hold(expired["hold_id"], "worker-key", "8" * 64)
        clock[0] = max(silent["deadline"], expired["deadline"]) + TASK_REFUND_GRACE_S
        # Sweep has not run; the dispute must settle the hold, not escape it.
        for hold in (silent, expired):
            with pytest.raises(SpendStateError, match="not open"):
                store.dispute_task_hold(hold["hold_id"], "payer-key", "late", "x")
        assert store.task_hold_status(silent["hold_id"])["state"] == "paid"
        assert store.task_hold_status(expired["hold_id"])["state"] == "refunded"
        assert store.balance("worker") == 100


def test_resolver_may_not_be_a_party_to_its_own_dispute(
    tmp_path, identities, monkeypatch
):
    clock = [6_900_000]
    service = V2LedgerService(
        tmp_path / "ledger.sqlite", identities["roster"],
        clock=lambda: clock[0], start_sweeper=False,
    )
    try:
        service.store.deposit("funding", "selfpayer", 100, 1)
        monkeypatch.setenv("NAK_SPEND_ROUTES", "on")
        with _running(service) as base:
            hold_id = _request(
                base, "POST", "/spend/task/authorize", identities["selfpayer"],
                _task_body(identities, clock[0], task_hash="9" * 64),
            )[1]["hold_id"]
            _request(
                base, "POST", "/spend/task/submit", identities["worker"],
                {"hold_id": hold_id, "result_hash": "9" * 64},
            )
            assert _request(
                base, "POST", "/spend/task/dispute", identities["selfpayer"],
                {"hold_id": hold_id, "reason": "quality", "note": "mine"},
            )[0] == 200
            code, _body = _request(
                base, "POST", "/spend/task/resolve", identities["selfpayer"],
                {"hold_id": hold_id, "outcome": "refund", "reason": "mine"},
            )
            assert code == 403
            assert service.store.task_hold_status(hold_id)["state"] == "disputed"
    finally:
        service.close()
