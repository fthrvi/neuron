"""Concurrency, durability, and invariant tests for core/ledger_store.py."""
import json
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
    MAX_UNITS,
    RATE,
    TIER_LIMITS,
    CreditLimitError,
    LedgerStore,
    LedgerValueError,
    ReceiptStateError,
    import_legacy_snapshot,
)


def _assert_zero_sum(store):
    total = store._db.execute(
        "SELECT COALESCE(SUM(balance), 0) FROM accounts"
    ).fetchone()[0]
    assert total == 0


def test_50_threads_settling_distinct_receipts_give_exact_sum(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        barrier = threading.Barrier(50)

        def settle_one(index):
            barrier.wait()
            return store.settle(
                f"receipt-{index}", "consumer", {"worker": 7}, 7, "self"
            )

        with ThreadPoolExecutor(max_workers=50) as pool:
            results = list(pool.map(settle_one, range(50)))

        assert results == [-7] * 50
        assert store.balance("worker") == 350
        assert store.balance("consumer") == -350


def test_50_threads_settling_same_receipt_credit_once(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        barrier = threading.Barrier(50)

        def settle_once(_):
            barrier.wait()
            return store.settle("same", "consumer", {"worker": 9}, 9, "self")

        with ThreadPoolExecutor(max_workers=50) as pool:
            results = list(pool.map(settle_once, range(50)))

        assert results == [-9] * 50
        assert store.balance("worker") == 9
        assert store.balance("consumer") == -9
        assert len(store.history("worker")) == 1


def test_racing_settles_cannot_together_cross_credit_limit(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        barrier = threading.Barrier(2)

        def settle_one(receipt_id):
            barrier.wait()
            try:
                store.settle(
                    receipt_id, "new-user", {"worker": 600_000}, 600_000, "stranger"
                )
                return "committed"
            except CreditLimitError:
                return "refused"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(settle_one, ("first", "second")))

        assert sorted(results) == ["committed", "refused"]
        assert store.balance("new-user") == -600_000
        assert store.balance("worker") == 600_000


def test_settle_applies_roster_tiers_only_to_named_credited_accounts(tmp_path):
    path = tmp_path / "ledger.db"
    with LedgerStore(path) as store:
        store.settle(
            "first", "consumer", {"known-worker": 10, "unknown-worker": 10},
            20, "self", account_tiers={"known-worker": "known"},
        )

    with sqlite3.connect(path) as db:
        tiers = dict(db.execute("SELECT id, tier FROM accounts"))
    assert tiers["known-worker"] == "known"
    assert tiers["unknown-worker"] == "stranger"


def test_settle_updates_existing_credited_account_to_current_roster_tier(tmp_path):
    path = tmp_path / "ledger.db"
    with LedgerStore(path) as store:
        store.settle("first", "consumer", {"worker": 10}, 10, "self")
        store.settle(
            "second", "consumer", {"worker": 10}, 10, "self",
            account_tiers={"worker": "trusted"},
        )
        assert store._db.execute(
            "SELECT tier FROM accounts WHERE id='worker'"
        ).fetchone()[0] == "trusted"
        store.settle(
            "third", "consumer", {"worker": 10}, 10, "self",
            account_tiers={"worker": "known"},
        )

    with sqlite3.connect(path) as db:
        tier = db.execute("SELECT tier FROM accounts WHERE id='worker'").fetchone()[0]
    assert tier == "known"


def test_credited_account_tier_does_not_change_requester_limit(tmp_path):
    path = tmp_path / "ledger.db"
    with LedgerStore(path) as store:
        store.settle(
            "allowed", "consumer", {"consumer": 1, "worker": 10}, 11, "stranger",
            account_tiers={"consumer": "self", "worker": "trusted"},
        )
        with pytest.raises(CreditLimitError):
            store.settle(
                "receipt",
                "consumer",
                {"worker": TIER_LIMITS["stranger"]},
                TIER_LIMITS["stranger"],
                "stranger",
                account_tiers={"worker": "trusted"},
            )
        assert store.balance("consumer") == -10
        assert store.balance("worker") == 10

    with sqlite3.connect(path) as db:
        tier = db.execute("SELECT tier FROM accounts WHERE id='consumer'").fetchone()[0]
    assert tier == "stranger"


def test_dispute_is_permanent_and_resettle_is_refused(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        store.settle("receipt", "consumer", {"worker": 25}, 25, "stranger")
        assert store.dispute("receipt") is True
        assert store.receipt_state("receipt") == "disputed"
        assert store.balance("consumer") == 0
        assert store.balance("worker") == 0
        assert store.dispute("receipt") is False

        with pytest.raises(ReceiptStateError):
            store.settle("receipt", "consumer", {"worker": 25}, 25, "stranger")
        assert store.balance("consumer") == 0
        assert store.balance("worker") == 0


@pytest.mark.parametrize("amount", [-1, 0, 1.5, "1", True, MAX_UNITS + 1])
def test_amount_bounds_reject_invalid_values(tmp_path, amount):
    with LedgerStore(tmp_path / "ledger.db") as store:
        with pytest.raises(LedgerValueError):
            store.transfer("from", "to", amount, "self")
        with pytest.raises(LedgerValueError):
            store.settle("receipt", "consumer", {"worker": 1}, amount, "self")
        with pytest.raises(LedgerValueError):
            store.settle("receipt", "consumer", {"worker": amount}, 1, "self")
        assert store.balance("from") == 0
        assert store.balance("to") == 0
        assert store.balance("worker") == 0


def test_corrupt_database_refuses_to_open(tmp_path):
    path = tmp_path / "corrupt.db"
    path.write_bytes(b"this is not a sqlite database")

    with pytest.raises(sqlite3.DatabaseError):
        LedgerStore(path)
    assert path.read_bytes() == b"this is not a sqlite database"


def test_journal_rows_cannot_be_updated_or_deleted(tmp_path):
    path = tmp_path / "ledger.db"
    with LedgerStore(path) as store:
        store.transfer("alice", "bob", 5, "stranger")

    with sqlite3.connect(path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("UPDATE journal SET amount=99")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("DELETE FROM journal")
        assert db.execute("SELECT COUNT(*) FROM journal").fetchone()[0] == 2


def test_transfer_is_atomic_and_refuses_overdraft_beyond_tier_limit(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        limit = TIER_LIMITS["stranger"]
        assert store.transfer("alice", "bob", limit, "stranger") == limit
        assert store.balance("alice") == -limit
        assert store.balance("bob") == limit

        with pytest.raises(CreditLimitError):
            store.transfer("alice", "bob", 1, "stranger")
        assert store.balance("alice") == -limit
        assert store.balance("bob") == limit
        assert [entry["kind"] for entry in store.history("alice")] == ["send"]
        assert [entry["kind"] for entry in store.history("bob")] == ["receive"]


def test_wal_mode_reopen_preserves_balances(tmp_path):
    path = tmp_path / "ledger.db"
    with LedgerStore(path) as store:
        store.settle("receipt", "consumer", {"worker": 40}, 40, "stranger")

    with LedgerStore(path) as reopened:
        assert reopened.balance("worker") == 40
        assert reopened.balance("consumer") == -40
        with sqlite3.connect(path) as db:
            assert db.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_import_legacy_snapshot_preserves_balances_and_marks_receipts(tmp_path):
    snapshot = {
        "balances": {"worker": 64, "consumer": -64, "unused": 0},
        "settled": {
            "legacy-run": {
                "credited": {"worker": 64},
                "requester": "consumer",
                "debited": 64,
                "total": 64,
            }
        },
        "journal": [{"kind": "settle", "run_id": "legacy-run"}],
    }
    path = tmp_path / "ledger.db"
    with LedgerStore(path) as store:
        assert import_legacy_snapshot(snapshot, store) is None
        assert store.balance("worker") == 64
        assert store.balance("consumer") == -64
        assert store.balance("unused") == 0
        assert store.receipt_state("legacy-run") == "legacy_unsigned"
        with pytest.raises(ReceiptStateError):
            store.settle(
                "legacy-run", "consumer", {"worker": 64}, 64, "stranger"
            )

    with sqlite3.connect(path) as db:
        assert db.execute("SELECT SUM(balance) FROM accounts").fetchone()[0] == 0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_free_own_node_settle_is_recorded_once(tmp_path):
    """Local = free: a settle with charged=0 (the requester's own nodes) is stored for the audit
    and is idempotent; it must not be rejected (every live settle on 2026-10-13 was charged 0)."""
    from core.ledger_store import LedgerStore
    store = LedgerStore(str(tmp_path / "l.sqlite"))
    assert store.settle("r-free", "prithvi", {}, 0, "self") == 0
    assert store.settle("r-free", "prithvi", {}, 0, "self") == 0
    assert store.balance("prithvi") == 0


def test_money_schema_and_constants(tmp_path):
    assert RATE == 100
    assert HOLD_S == 7 * 24 * 60 * 60
    assert TIER_LIMITS == {
        "stranger": 1_000_000,
        "known": 25_000_000,
        "trusted": 250_000_000,
        "self": None,
    }
    with LedgerStore(tmp_path / "ledger.db") as store:
        tables = {
            row[0]
            for row in store._db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {
            "chain_refs",
            "deposit_accounts",
            "payout_addresses",
            "withdrawals",
        } <= tables
        with pytest.raises(sqlite3.IntegrityError):
            store._db.execute(
                "INSERT INTO withdrawals(id, operator, amount, address, state, "
                "created_ts, updated_ts) VALUES ('bad', 'alice', 1, 'addr', "
                "'not-a-state', 1, 1)"
            )


def test_deposit_is_idempotent_by_ref_and_preserves_zero_sum(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        assert store.deposit("sig:0", "alice", 12_300, 42) == 12_300
        _assert_zero_sum(store)
        assert store.balance("alice") == 12_300
        assert store.balance("bob") == 0
        assert store.balance("treasury") == -12_300

        # The chain reference is authoritative on replay; no balances or rows move twice.
        assert store.deposit("sig:0", "bob", 99, 999) == 12_300
        _assert_zero_sum(store)
        assert store.balance("alice") == 12_300
        assert store._db.execute("SELECT COUNT(*) FROM chain_refs").fetchone()[0] == 1
        assert store._db.execute(
            "SELECT COUNT(*) FROM journal WHERE kind='deposit'"
        ).fetchone()[0] == 1
        detail = json.loads(store.history("alice")[0]["detail"])
        assert detail == {"rate": RATE, "ref": "sig:0", "slot": 42}


def test_unfunded_earnings_are_never_withdrawable(tmp_path, monkeypatch):
    clock = [1_000_000]
    monkeypatch.setattr(ledger_store_module.time, "time", lambda: clock[0])
    with LedgerStore(tmp_path / "ledger.db") as store:
        store.settle("unfunded", "consumer", {"worker": 40}, 40, "self")
        _assert_zero_sum(store)
        assert json.loads(store.history("worker")[0]["detail"])["funded"] is False
        clock[0] += HOLD_S + 1
        assert store.withdrawable("worker") == 0
        _assert_zero_sum(store)


def test_funded_earnings_mature_after_hold_and_dispute_removes_them(
    tmp_path, monkeypatch
):
    clock = [2_000_000]
    monkeypatch.setattr(ledger_store_module.time, "time", lambda: clock[0])
    with LedgerStore(tmp_path / "ledger.db") as store:
        store.deposit("funding:0", "consumer", 100, 5)
        _assert_zero_sum(store)
        clock[0] += 1
        store.settle("funded", "consumer", {"worker": 40}, 40, "self")
        _assert_zero_sum(store)
        assert json.loads(store.history("worker")[0]["detail"])["funded"] is True
        assert store.withdrawable("worker") == 0

        clock[0] += HOLD_S
        assert store.withdrawable("worker") == 40
        assert store.dispute("funded") is True
        _assert_zero_sum(store)
        assert store.withdrawable("worker") == 0


def test_withdraw_hold_release_and_finalize_preserve_zero_sum(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        store.deposit("deposit:0", "alice", 100, 7)
        _assert_zero_sum(store)
        assert store.withdrawable("alice") == 100

        assert store.withdraw_hold(
            "alice", 40, "address-a", withdrawal_id="release-me"
        ) == "release-me"
        _assert_zero_sum(store)
        assert store.balance("alice") == 60
        assert store.withdrawable("alice") == 60
        assert store.withdraw_release("release-me") == 40
        _assert_zero_sum(store)
        assert store.balance("alice") == 100
        assert store.withdrawable("alice") == 100

        assert store.withdraw_hold(
            "alice", 50, "address-a", withdrawal_id="finalize-me"
        ) == "finalize-me"
        _assert_zero_sum(store)
        with pytest.raises(ReceiptStateError):
            store.withdraw_finalize("finalize-me")
        store._db.execute(
            "UPDATE withdrawals SET state='sent', tx_sig='finalize-signature' "
            "WHERE id='finalize-me'"
        )
        assert store.withdraw_finalize("finalize-me") == 50
        _assert_zero_sum(store)
        assert store.balance("alice") == 50
        assert store.balance("treasury") == -50
        assert store.withdrawable("alice") == 50
        states = dict(store._db.execute("SELECT id, state FROM withdrawals"))
        assert states == {"release-me": "released", "finalize-me": "finalized"}
        for entry in store.history("alice"):
            if entry["kind"] in {"deposit", "withdraw_hold", "withdraw_release"}:
                assert json.loads(entry["detail"])["rate"] == RATE


def test_withdrawal_state_machine_and_unique_transaction_signature(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        store.deposit("deposit:0", "alice", 30, 7)
        sent_id = store.withdraw_hold("alice", 10, "address-a")
        store._db.execute(
            "UPDATE withdrawals SET state='sent', tx_sig='signature-a' WHERE id=?",
            (sent_id,),
        )
        with pytest.raises(ReceiptStateError):
            store.withdraw_release(sent_id)
        assert store.withdraw_finalize(sent_id) == 10
        assert store.withdraw_finalize(sent_id) == 10
        _assert_zero_sum(store)

        expired_id = store.withdraw_hold("alice", 10, "address-a")
        store._db.execute(
            "UPDATE withdrawals SET state='expired' WHERE id=?", (expired_id,)
        )
        with pytest.raises(ReceiptStateError):
            store.withdraw_finalize(expired_id)
        assert store.withdraw_release(expired_id) == 10
        assert store.withdraw_release(expired_id) == 10
        with pytest.raises(sqlite3.IntegrityError):
            store._db.execute(
                "UPDATE withdrawals SET tx_sig='signature-a' WHERE id=?", (expired_id,)
            )
        _assert_zero_sum(store)


def test_money_operations_enforce_max_units_without_partial_writes(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        store.deposit("max:0", "alice", MAX_UNITS, 1)
        _assert_zero_sum(store)
        with pytest.raises(LedgerValueError):
            store.deposit("overflow:0", "alice", 1, 2)
        assert store._db.execute(
            "SELECT COUNT(*) FROM chain_refs WHERE ref='overflow:0'"
        ).fetchone()[0] == 0
        _assert_zero_sum(store)

        store.withdraw_hold(
            "alice", MAX_UNITS, "address-a", withdrawal_id="max-withdrawal"
        )
        _assert_zero_sum(store)
        store._db.execute(
            "UPDATE withdrawals SET state='sent', tx_sig='max-signature' "
            "WHERE id='max-withdrawal'"
        )
        store.withdraw_finalize("max-withdrawal")
        _assert_zero_sum(store)
        assert store.balance("alice") == 0
        assert store.balance("treasury") == 0

    with LedgerStore(tmp_path / "invalid.db") as store:
        for value in (-1, 0, 1.5, True, MAX_UNITS + 1):
            with pytest.raises(LedgerValueError):
                store.deposit("bad:0", "alice", value, 1)
        _assert_zero_sum(store)
