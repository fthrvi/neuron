"""N1 spend escrow pricing, lifecycle, concurrency, and accounting tests."""
import os
import sqlite3
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import core.ledger_store as ledger_store_module  # noqa: E402
from core.ledger_store import (  # noqa: E402
    HOLD_S,
    SPEND_EXECUTION_S,
    SPEND_SETTLEMENT_GRACE_S,
    CreditLimitError,
    LedgerStore,
    LedgerValueError,
    SpendConflict,
    is_reserved,
)


def _worker(key="worker-key", account="worker", start=0, end=4, price=2):
    return {
        "worker_keyid": key,
        "worker_account": account,
        "layer_start": start,
        "layer_end": end,
        "price_multiplier": price,
    }


def _authorize(store, nonce="nonce", session="session", **overrides):
    values = {
        "payer_keyid": "payer-key",
        "payer_account": "payer",
        "tier": "stranger",
        "client_nonce": nonce,
        "session_id": session,
        "model_id": "model",
        "billing_mode": "greedy-direct-v1",
        "max_prompt_tokens": 5,
        "max_output_tokens": 5,
        "workers": [_worker()],
    }
    values.update(overrides)
    return store.authorize_spend(**values)


def _assert_zero_sum(store):
    assert store._db.execute(
        "SELECT COALESCE(SUM(balance), 0) FROM accounts"
    ).fetchone()[0] == 0


def _assert_spend_journals_zero_sum(store):
    rows = store._db.execute(
        "SELECT receipt_id, COUNT(*), SUM(amount) FROM journal "
        "WHERE receipt_id LIKE 'spend-%' GROUP BY receipt_id"
    ).fetchall()
    assert rows
    assert all(int(row[1]) == 2 and int(row[2]) == 0 for row in rows)


def test_additive_idempotent_schema_and_immutable_snapshots(tmp_path):
    path = tmp_path / "ledger.db"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE old_data(value TEXT)")
    db.execute("INSERT INTO old_data VALUES ('preserved')")
    db.commit()
    db.close()

    with LedgerStore(path) as store:
        assert store._db.execute("SELECT value FROM old_data").fetchone()[0] == "preserved"
        tables = {
            row[0]
            for row in store._db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {"spend_holds", "spend_hold_workers"} <= tables
        hold = _authorize(store)
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            store._db.execute(
                "UPDATE spend_hold_workers SET worker_account_at_authorize='other' "
                "WHERE hold_id=?",
                (hold["hold_id"],),
            )

    with LedgerStore(path) as reopened:
        assert reopened.spend_status(hold["hold_id"])["state"] == "open"
        assert reopened._db.execute("SELECT value FROM old_data").fetchone()[0] == "preserved"


def test_prompt_output_pricing_settlement_and_release_are_zero_sum(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        store.deposit("funding", "payer", 1_000, 1)
        hold = _authorize(store)
        entry = hold["workers"][0]
        assert entry["max_token_layers"] == (5 + 5) * 4
        assert entry["max_cost"] == 80
        assert hold["max_cost"] == 80
        assert hold["escrow_balance"] == 80
        assert store.balance("payer") == 920

        store.claim_spend_worker(hold["hold_id"], "worker-key", "claim-1")
        checkpoint = store.settle_spend_usage(hold["hold_id"], "worker-key", 3, 1)
        assert checkpoint["accepted_delta"] == (3 + 1) * 4 * 2
        assert store.balance("worker") == 32
        with pytest.raises(SpendConflict, match="prompt token count"):
            store.settle_spend_usage(hold["hold_id"], "worker-key", 4, 1)

        settled = store.settle_spend_usage(
            hold["hold_id"],
            "worker-key",
            3,
            2,
            final=True,
            final_receipt_id="receipt-final",
        )
        assert settled["accepted_delta"] == 8
        assert settled["state"] == "settled"
        assert settled["escrow_balance"] == 0
        assert store.balance("worker") == 40
        assert store.balance("payer") == 960
        replay = store.settle_spend_usage(
            hold["hold_id"],
            "worker-key",
            3,
            2,
            final=True,
            final_receipt_id="receipt-final",
        )
        assert replay["accepted_delta"] == 0
        _assert_zero_sum(store)
        _assert_spend_journals_zero_sum(store)


def test_payer_owned_entry_is_snapshotted_free_and_stays_zero(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        hold = _authorize(
            store,
            workers=[_worker(account="payer", end=8, price=9)],
        )
        entry = hold["workers"][0]
        assert entry["billable"] is False
        assert entry["max_cost"] == 0
        assert hold["escrow_balance"] == 0
        store.claim_spend_worker(hold["hold_id"], "worker-key", "claim")
        result = store.settle_spend_usage(
            hold["hold_id"], "worker-key", 5, 5, final=True
        )
        assert result["accepted_delta"] == 0
        assert result["state"] == "settled"
        assert result["escrow_balance"] == 0
        assert store.balance("payer") == 0
        _assert_zero_sum(store)


def test_authorize_is_idempotent_and_conflicting_nonce_or_session_fails(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        first = _authorize(store)
        replay = _authorize(store)
        assert replay["hold_id"] == first["hold_id"]
        assert store._db.execute("SELECT COUNT(*) FROM spend_holds").fetchone()[0] == 1
        with pytest.raises(SpendConflict, match="client_nonce"):
            _authorize(store, max_output_tokens=6)
        with pytest.raises(SpendConflict, match="session_id"):
            _authorize(store, nonce="different")


def test_abandon_releases_only_unclaimed_entry_and_claimed_release_is_deferred(
    tmp_path,
):
    with LedgerStore(tmp_path / "ledger.db") as store:
        hold = _authorize(
            store,
            workers=[
                _worker(key="claimed", account="worker-a", end=2, price=1),
                _worker(key="unused", account="worker-b", start=2, end=4, price=1),
            ],
        )
        store.claim_spend_worker(hold["hold_id"], "claimed", "instance")
        requested = store.request_spend_release(hold["hold_id"], "payer-key")
        assert requested["release_requested"] is True
        assert requested["state"] == "open"
        assert requested["escrow_balance"] == 40

        abandoned = store.abandon_spend_worker(
            hold["hold_id"], "unused", "payer-key"
        )
        assert abandoned["state"] == "open"
        assert abandoned["escrow_balance"] == 20
        assert store.abandon_spend_worker(
            hold["hold_id"], "unused", "payer-key"
        )["escrow_balance"] == 20

        settled = store.settle_spend_usage(
            hold["hold_id"], "claimed", 2, 1, final=True
        )
        assert settled["state"] == "settled"
        assert settled["escrow_balance"] == 0
        assert store.balance("worker-a") == 6
        _assert_zero_sum(store)
        _assert_spend_journals_zero_sum(store)


def test_concurrent_authorizations_cannot_exceed_eligible_capacity(tmp_path):
    path = tmp_path / "ledger.db"
    first = LedgerStore(path)
    second = LedgerStore(path)
    barrier = threading.Barrier(2)

    def authorize(store, index):
        barrier.wait()
        try:
            _authorize(
                store,
                nonce=f"nonce-{index}",
                session=f"session-{index}",
                max_prompt_tokens=600_000,
                max_output_tokens=0,
                workers=[_worker(key=f"worker-{index}", end=1, price=1)],
            )
            return "committed"
        except CreditLimitError:
            return "refused"

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda item: authorize(*item), ((first, 1), (second, 2))))
        assert sorted(results) == ["committed", "refused"]
        with LedgerStore(path) as check:
            assert check._db.execute("SELECT COUNT(*) FROM spend_holds").fetchone()[0] == 1
            assert check._db.execute(
                "SELECT SUM(balance) FROM accounts WHERE id LIKE '__spend_hold__:%'"
            ).fetchone()[0] == 600_000
            _assert_zero_sum(check)
    finally:
        first.close()
        second.close()


def test_immature_and_unfunded_earnings_are_excluded_from_capacity(
    tmp_path, monkeypatch
):
    clock = [1_000_000]
    monkeypatch.setattr(ledger_store_module.time, "time", lambda: clock[0])
    with LedgerStore(tmp_path / "ledger.db") as store:
        store.deposit("funding", "consumer", 100, 1)
        store.settle("funded", "consumer", {"payer": 100}, 100, "self")
        assert store.balance("payer") == 100
        assert store.eligible_spend_capacity("payer", "stranger") == 1_000_000
        with pytest.raises(CreditLimitError):
            _authorize(
                store,
                max_prompt_tokens=1_000_001,
                max_output_tokens=0,
                workers=[_worker(end=1, price=1)],
            )

        store.settle("unfunded", "borrower", {"unfunded-payer": 50}, 50, "self")
        clock[0] += HOLD_S + 1
        assert store.eligible_spend_capacity("payer", "stranger") == 1_000_100
        assert store.eligible_spend_capacity("unfunded-payer", "stranger") == 1_000_000


def test_dispute_after_authorization_cannot_touch_escrow(tmp_path, monkeypatch):
    clock = [2_000_000]
    monkeypatch.setattr(ledger_store_module.time, "time", lambda: clock[0])
    with LedgerStore(tmp_path / "ledger.db") as store:
        store.deposit("funding", "consumer", 100, 1)
        store.settle("earning", "consumer", {"payer": 100}, 100, "self")
        clock[0] += HOLD_S + 1
        hold = _authorize(
            store,
            max_prompt_tokens=100,
            max_output_tokens=0,
            workers=[_worker(end=1, price=1)],
        )
        assert hold["escrow_balance"] == 100
        assert store.dispute("earning") is True
        assert store.balance("payer") == -100
        assert store.spend_status(hold["hold_id"])["escrow_balance"] == 100
        store.claim_spend_worker(hold["hold_id"], "worker-key", "claim")
        result = store.settle_spend_usage(
            hold["hold_id"], "worker-key", 100, 0, final=True
        )
        assert result["state"] == "settled"
        assert result["escrow_balance"] == 0
        assert store.balance("worker") == 100
        _assert_zero_sum(store)


def test_concurrent_withdrawal_and_authorization_share_real_collateral(tmp_path):
    path = tmp_path / "ledger.db"
    with LedgerStore(path) as setup:
        setup.deposit("funding", "payer", 100_000_000, 1)
    first = LedgerStore(path)
    second = LedgerStore(path)
    barrier = threading.Barrier(2)

    def authorize():
        barrier.wait()
        try:
            _authorize(
                first,
                max_prompt_tokens=60_000_000,
                max_output_tokens=0,
                workers=[_worker(end=1, price=1)],
            )
            return "authorize"
        except CreditLimitError:
            return "refused"

    def withdraw():
        barrier.wait()
        try:
            second.withdraw_hold(
                "payer", 60_000_000, "address", withdrawal_id="racing-withdrawal"
            )
            return "withdraw"
        except CreditLimitError:
            return "refused"

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [pool.submit(authorize), pool.submit(withdraw)]
            results = [future.result() for future in results]
        assert results.count("refused") == 1
        with LedgerStore(path) as check:
            spend_rows = check._db.execute(
                "SELECT hold_id, escrow_account FROM spend_holds"
            ).fetchall()
            for row in spend_rows:
                assert check._balance_in(check._db, row["escrow_account"]) == 60_000_000
                check._assert_spend_hold_in(check._db, row["hold_id"])
            _assert_zero_sum(check)
    finally:
        first.close()
        second.close()


def test_release_and_two_deadline_expiry_leave_closed_accounts_empty(
    tmp_path, monkeypatch
):
    clock = [3_000_000]
    monkeypatch.setattr(ledger_store_module.time, "time", lambda: clock[0])
    with LedgerStore(tmp_path / "ledger.db") as store:
        store.deposit("funding", "payer", 1_000, 1)
        cancelled = _authorize(store, nonce="cancel", session="cancel")
        cancelled = store.request_spend_release(cancelled["hold_id"], "payer-key")
        assert cancelled["state"] == "cancelled"
        assert cancelled["escrow_balance"] == 0

        closing = _authorize(
            store,
            nonce="closing",
            session="closing",
            workers=[
                _worker(key="claimed", account="worker-a", end=2, price=1),
                _worker(key="unused", account="worker-b", start=2, end=4, price=1),
            ],
        )
        store.claim_spend_worker(closing["hold_id"], "claimed", "instance")
        clock[0] += SPEND_EXECUTION_S
        assert closing["hold_id"] in store.expire_spend_holds()
        status = store.spend_status(closing["hold_id"])
        assert status["state"] == "closing"
        assert status["escrow_balance"] == 20
        assert [entry["state"] for entry in status["workers"]] == [
            "claimed",
            "abandoned",
        ]

        clock[0] += SPEND_SETTLEMENT_GRACE_S
        assert closing["hold_id"] in store.expire_spend_holds()
        status = store.spend_status(closing["hold_id"])
        assert status["state"] == "expired"
        assert status["escrow_balance"] == 0
        assert status["workers"][0]["state"] == "expired"

        closed = store._db.execute(
            "SELECT h.hold_id, a.balance FROM spend_holds AS h "
            "JOIN accounts AS a ON a.id=h.escrow_account "
            "WHERE h.state IN ('settled','expired','cancelled','disputed')"
        ).fetchall()
        assert closed and all(int(row["balance"]) == 0 for row in closed)
        _assert_zero_sum(store)
        _assert_spend_journals_zero_sum(store)


@pytest.mark.parametrize(
    "account", ("__spend_hold__:id", "__spend_hold__spoof")
)
def test_spend_internal_accounts_are_not_user_addressable(tmp_path, account):
    assert is_reserved(account)
    with LedgerStore(tmp_path / "ledger.db") as store:
        for operation in (
            lambda: store.balance(account),
            lambda: store.history(account),
            lambda: store.transfer("payer", account, 1, "self"),
            lambda: store.transfer(account, "payer", 1, "self"),
        ):
            with pytest.raises(LedgerValueError, match="reserved"):
                operation()
