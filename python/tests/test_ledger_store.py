"""Concurrency, durability, and invariant tests for core/ledger_store.py."""
import os
import sqlite3
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.ledger_store import (  # noqa: E402
    MAX_UNITS,
    CreditLimitError,
    LedgerStore,
    LedgerValueError,
    ReceiptStateError,
    import_legacy_snapshot,
)


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
                store.settle(receipt_id, "new-user", {"worker": 60}, 60, "stranger")
                return "committed"
            except CreditLimitError:
                return "refused"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(settle_one, ("first", "second")))

        assert sorted(results) == ["committed", "refused"]
        assert store.balance("new-user") == -60
        assert store.balance("worker") == 60


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
        assert store.transfer("alice", "bob", 100, "stranger") == 100
        assert store.balance("alice") == -100
        assert store.balance("bob") == 100

        with pytest.raises(CreditLimitError):
            store.transfer("alice", "bob", 1, "stranger")
        assert store.balance("alice") == -100
        assert store.balance("bob") == 100
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
