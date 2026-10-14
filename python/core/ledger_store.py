"""Durable, concurrent-safe storage for the reciprocal compute ledger.

The store deliberately owns only accounting.  Authentication and receipt
verification happen at the service boundary; once those checks produce a
receipt id, requester, credits, charge, and roster tier, this module applies
them atomically.

All amounts are integer TEST/devnet units.  SQLite is opened in WAL mode and
every mutation runs under ``BEGIN IMMEDIATE`` while holding a process-local
lock.  SQLite supplies the corresponding inter-process serialization.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


# SQLite's INTEGER storage class is a signed 64-bit value.  Keeping the public
# bound identical prevents a large Python int from silently becoming REAL.
# Per-operation bound in TEST units: large enough for any real settle, small enough that a
# malformed or hostile amount can never approach integer overflow in balances.
MAX_UNITS = 10 ** 12

# These limits mirror nakshatra/scripts/creditlimit.py.  Unknown tiers are
# intentionally treated as strangers (the tightest policy).
TIER_LIMITS: dict[str, int | None] = {
    "stranger": 100,
    "known": 500,
    "trusted": 5_000,
    "self": None,
}


class LedgerError(Exception):
    """Base class for an accounting operation that was refused."""


class LedgerValueError(LedgerError, ValueError):
    """A caller supplied an invalid identifier, amount, or snapshot."""


class CreditLimitError(LedgerError):
    """A debit would put an account beyond its roster tier's limit."""


class ReceiptStateError(LedgerError):
    """A receipt exists but its durable state forbids the requested action."""


def _amount(value: Any, name: str = "amount", *, allow_zero: bool = False) -> int:
    """Return a strictly bounded integer without coercion (positive unless ``allow_zero``)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise LedgerValueError(f"{name} must be an integer")
    low = 0 if allow_zero else 1
    if value < low or value > MAX_UNITS:
        raise LedgerValueError(f"{name} must be between {low} and {MAX_UNITS}")
    return value


def _stored_integer(value: Any, name: str, *, allow_zero: bool = True) -> int:
    """Validate an integer that will be stored directly, including balances."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise LedgerValueError(f"{name} must be an integer")
    low = -MAX_UNITS if allow_zero else 1
    if value < low or value > MAX_UNITS or (not allow_zero and value == 0):
        raise LedgerValueError(f"{name} is outside SQLite integer bounds")
    return value


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise LedgerValueError(f"{name} must be a non-empty string")
    return value


def _tier(value: Any) -> str:
    return value if isinstance(value, str) and value in TIER_LIMITS else "stranger"


def _may_debit(balance: int, amount: int, tier: str) -> bool:
    limit = TIER_LIMITS[_tier(tier)]
    return limit is None or balance - amount >= -limit


class LedgerStore:
    """SQLite-backed ledger implementing exactly-once settlement.

    One instance may be shared by a ``ThreadingHTTPServer``.  The connection is
    configured for cross-thread use, but all access is serialized by ``_lock``;
    this avoids both sqlite cursor races and application-level check-then-write
    races.  ``BEGIN IMMEDIATE`` also serializes writers using other connections.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._closed = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(
            str(self.path),
            timeout=30.0,
            isolation_level=None,
            check_same_thread=False,
        )
        self._db.row_factory = sqlite3.Row
        try:
            # Check before creating or migrating anything.  A corrupt legacy
            # file must stop startup; it must never be replaced by a new DB.
            result = self._db.execute("PRAGMA quick_check").fetchone()
            if result is None or result[0] != "ok":
                detail = result[0] if result else "no result"
                raise sqlite3.DatabaseError(f"ledger integrity check failed: {detail}")
            self._db.execute("PRAGMA busy_timeout=30000")
            self._db.execute("PRAGMA foreign_keys=ON")
            mode = self._db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if mode.lower() != "wal":
                raise sqlite3.DatabaseError(f"ledger requires WAL mode, got {mode!r}")
            self._create_schema()
        except Exception:
            self._db.close()
            self._closed = True
            raise

    def _create_schema(self) -> None:
        max_units = MAX_UNITS
        self._db.executescript(
            f"""
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                balance INTEGER NOT NULL DEFAULT 0
                    CHECK(typeof(balance) = 'integer'
                          AND balance BETWEEN {-max_units} AND {max_units}),
                tier TEXT NOT NULL DEFAULT 'stranger'
            );

            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                requester TEXT NOT NULL,
                credited TEXT NOT NULL,
                charged INTEGER NOT NULL
                    CHECK(typeof(charged) = 'integer'
                          AND charged BETWEEN 0 AND {max_units}),
                delta INTEGER NOT NULL
                    CHECK(typeof(delta) = 'integer'
                          AND delta BETWEEN {-max_units} AND {max_units}),
                tier TEXT NOT NULL,
                state TEXT NOT NULL
                    CHECK(state IN ('settled', 'disputed', 'legacy_unsigned')),
                created_at INTEGER NOT NULL,
                disputed_at INTEGER,
                CHECK(state != 'settled' OR charged >= 0)
            );

            CREATE TABLE IF NOT EXISTS nonces (
                sig_hash TEXT PRIMARY KEY,
                ts INTEGER NOT NULL CHECK(typeof(ts) = 'integer')
            );

            CREATE TABLE IF NOT EXISTS journal (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL CHECK(typeof(ts) = 'integer'),
                kind TEXT NOT NULL,
                receipt_id TEXT,
                account TEXT NOT NULL,
                counterparty TEXT,
                amount INTEGER NOT NULL
                    CHECK(typeof(amount) = 'integer'
                          AND amount BETWEEN {-max_units} AND {max_units}
                          AND amount != 0),
                detail TEXT NOT NULL DEFAULT '{{}}'
            );

            CREATE TRIGGER IF NOT EXISTS journal_no_update
            BEFORE UPDATE ON journal
            BEGIN
                SELECT RAISE(ABORT, 'journal is append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS journal_no_delete
            BEFORE DELETE ON journal
            BEGIN
                SELECT RAISE(ABORT, 'journal is append-only');
            END;
            """
        )

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True

    def __enter__(self) -> "LedgerStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _tx(self, operation):
        with self._lock:
            if self._closed:
                raise sqlite3.ProgrammingError("ledger store is closed")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                result = operation(self._db)
                self._db.execute("COMMIT")
                return result
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    @staticmethod
    def _balance_in(db: sqlite3.Connection, account: str) -> int:
        row = db.execute("SELECT balance FROM accounts WHERE id=?", (account,)).fetchone()
        return int(row[0]) if row else 0

    @staticmethod
    def _checked_balance(value: int, account: str) -> int:
        if value < -MAX_UNITS or value > MAX_UNITS:
            raise LedgerValueError(f"balance for {account!r} exceeds SQLite integer bounds")
        return value

    @staticmethod
    def _ensure_account(db: sqlite3.Connection, account: str, tier: str = "stranger") -> None:
        db.execute(
            "INSERT INTO accounts(id, balance, tier) VALUES (?, 0, ?) "
            "ON CONFLICT(id) DO NOTHING",
            (account, tier),
        )

    @staticmethod
    def _set_balance(db: sqlite3.Connection, account: str, balance: int) -> None:
        db.execute("UPDATE accounts SET balance=? WHERE id=?", (balance, account))

    def settle(
        self,
        receipt_id: str,
        requester: str,
        credited: dict[str, int],
        charged: int,
        tier: str,
    ) -> int:
        """Apply a verified receipt once and return the requester's delta.

        Replaying an already-settled ``receipt_id`` returns its stored delta and
        makes no writes.  A disputed or legacy receipt can never be settled.
        """
        receipt_id = _identifier(receipt_id, "receipt_id")
        requester = _identifier(requester, "requester")
        # Work on the requester's OWN nodes is free (local = free) but is still recorded for the audit.
        charged = _amount(charged, "charged", allow_zero=True)
        tier = _tier(tier)
        if not isinstance(credited, dict):
            raise LedgerValueError("credited must be a dict of account to amount")
        clean_credits: dict[str, int] = {}
        for account, amount in credited.items():
            account = _identifier(account, "credited account")
            clean_credits[account] = _amount(amount, f"credit for {account}")
        if charged == 0 and clean_credits:
            # A free settle may only cover the requester's OWN work. Crediting anyone while
            # charging nothing would mint units from nothing.
            raise LedgerValueError("a zero-charge settle cannot credit any account")
        credited_json = json.dumps(clean_credits, sort_keys=True, separators=(",", ":"))
        now = int(time.time())
        delta = -charged

        def operation(db: sqlite3.Connection) -> int:
            existing = db.execute(
                "SELECT state, delta FROM receipts WHERE receipt_id=?", (receipt_id,)
            ).fetchone()
            if existing:
                if existing["state"] == "settled":
                    return int(existing["delta"])
                raise ReceiptStateError(
                    f"receipt {receipt_id!r} is {existing['state']} and cannot be settled"
                )

            old_requester_balance = self._balance_in(db, requester)
            if not _may_debit(old_requester_balance, charged, tier):
                limit = TIER_LIMITS[tier]
                raise CreditLimitError(
                    f"settlement would exceed {tier} credit limit {limit}: "
                    f"{old_requester_balance} - {charged}"
                )

            # Calculate every final balance before the first write so Python,
            # rather than SQLite numeric coercion, catches int64 overflow.
            final: dict[str, int] = {}
            for account, amount in clean_credits.items():
                final[account] = self._checked_balance(
                    self._balance_in(db, account) + amount, account
                )
            requester_base = final.get(requester, old_requester_balance)
            final[requester] = self._checked_balance(requester_base - charged, requester)

            db.execute(
                "INSERT INTO receipts(receipt_id, requester, credited, charged, delta, tier, "
                "state, created_at) VALUES (?, ?, ?, ?, ?, ?, 'settled', ?)",
                (receipt_id, requester, credited_json, charged, delta, tier, now),
            )
            for account in final:
                self._ensure_account(db, account, tier if account == requester else "stranger")
            db.execute("UPDATE accounts SET tier=? WHERE id=?", (tier, requester))
            for account, balance in final.items():
                self._set_balance(db, account, balance)
            for account, amount in clean_credits.items():
                db.execute(
                    "INSERT INTO journal(ts, kind, receipt_id, account, counterparty, amount) "
                    "VALUES (?, 'earn', ?, ?, ?, ?)",
                    (now, receipt_id, account, requester, amount),
                )
            if charged:  # a free own-node settle has no spend row; its receipts row is the record
                db.execute(
                    "INSERT INTO journal(ts, kind, receipt_id, account, amount, detail) "
                    "VALUES (?, 'spend', ?, ?, ?, ?)",
                    (now, receipt_id, requester, -charged, json.dumps({"tier": tier})),
                )
            return delta

        return self._tx(operation)

    def transfer(self, src: str, dst: str, amount: int, tier: str) -> int:
        """Move units atomically, allowing debt only within ``src``'s tier."""
        src = _identifier(src, "src")
        dst = _identifier(dst, "dst")
        if src == dst:
            raise LedgerValueError("cannot transfer to the same account")
        amount = _amount(amount)
        tier = _tier(tier)
        now = int(time.time())

        def operation(db: sqlite3.Connection) -> int:
            src_old = self._balance_in(db, src)
            dst_old = self._balance_in(db, dst)
            if not _may_debit(src_old, amount, tier):
                limit = TIER_LIMITS[tier]
                raise CreditLimitError(
                    f"transfer would exceed {tier} credit limit {limit}: "
                    f"{src_old} - {amount}"
                )
            src_new = self._checked_balance(src_old - amount, src)
            dst_new = self._checked_balance(dst_old + amount, dst)
            self._ensure_account(db, src, tier)
            self._ensure_account(db, dst)
            db.execute("UPDATE accounts SET tier=? WHERE id=?", (tier, src))
            self._set_balance(db, src, src_new)
            self._set_balance(db, dst, dst_new)
            db.execute(
                "INSERT INTO journal(ts, kind, account, counterparty, amount, detail) "
                "VALUES (?, 'send', ?, ?, ?, ?)",
                (now, src, dst, -amount, json.dumps({"tier": tier})),
            )
            db.execute(
                "INSERT INTO journal(ts, kind, account, counterparty, amount) "
                "VALUES (?, 'receive', ?, ?, ?)",
                (now, dst, src, amount),
            )
            return amount

        return self._tx(operation)

    def dispute(self, receipt_id: str) -> bool:
        """Reverse a receipt once while retaining its permanent receipt row."""
        receipt_id = _identifier(receipt_id, "receipt_id")
        now = int(time.time())

        def operation(db: sqlite3.Connection) -> bool:
            row = db.execute(
                "SELECT requester, credited, charged, state FROM receipts WHERE receipt_id=?",
                (receipt_id,),
            ).fetchone()
            if row is None or row["state"] == "disputed":
                return False
            requester = row["requester"]
            credited = json.loads(row["credited"])
            charged = int(row["charged"])

            final: dict[str, int] = {}
            for account, amount in credited.items():
                final[account] = self._checked_balance(
                    self._balance_in(db, account) - int(amount), account
                )
            requester_base = final.get(requester, self._balance_in(db, requester))
            final[requester] = self._checked_balance(requester_base + charged, requester)
            for account in final:
                self._ensure_account(db, account)
            for account, balance in final.items():
                self._set_balance(db, account, balance)
            db.execute(
                "UPDATE receipts SET state='disputed', disputed_at=? WHERE receipt_id=?",
                (now, receipt_id),
            )
            for account, amount in credited.items():
                db.execute(
                    "INSERT INTO journal(ts, kind, receipt_id, account, counterparty, amount) "
                    "VALUES (?, 'dispute_clawback', ?, ?, ?, ?)",
                    (now, receipt_id, account, requester, -int(amount)),
                )
            if charged:
                db.execute(
                    "INSERT INTO journal(ts, kind, receipt_id, account, amount) "
                    "VALUES (?, 'dispute_refund', ?, ?, ?)",
                    (now, receipt_id, requester, charged),
                )
            return True

        return self._tx(operation)

    def balance(self, account: str) -> int:
        account = _identifier(account, "account")
        with self._lock:
            return self._balance_in(self._db, account)

    def history(self, account: str, limit: int = 50) -> list[dict[str, Any]]:
        account = _identifier(account, "account")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise LedgerValueError("limit must be a positive integer")
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, ts, kind, receipt_id, counterparty, amount, detail "
                "FROM journal WHERE account=? ORDER BY seq DESC LIMIT ?",
                (account, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def receipt_state(self, receipt_id: str) -> str | None:
        receipt_id = _identifier(receipt_id, "receipt_id")
        with self._lock:
            row = self._db.execute(
                "SELECT state FROM receipts WHERE receipt_id=?", (receipt_id,)
            ).fetchone()
        return str(row[0]) if row else None

    def receipt_requester(self, receipt_id: str) -> str | None:
        """Return the immutable owner of a receipt for authorization checks."""
        receipt_id = _identifier(receipt_id, "receipt_id")
        with self._lock:
            row = self._db.execute(
                "SELECT requester FROM receipts WHERE receipt_id=?", (receipt_id,)
            ).fetchone()
        return str(row[0]) if row else None

    def claim_nonce(self, sig_hash: str, ts: int) -> bool:
        """Atomically claim an authenticated envelope signature for replay defense."""
        sig_hash = _identifier(sig_hash, "sig_hash")
        if isinstance(ts, bool) or not isinstance(ts, int):
            raise LedgerValueError("nonce timestamp must be an integer")

        def operation(db: sqlite3.Connection) -> bool:
            try:
                db.execute("INSERT INTO nonces(sig_hash, ts) VALUES (?, ?)", (sig_hash, ts))
            except sqlite3.IntegrityError:
                return False
            return True

        return self._tx(operation)

def import_legacy_snapshot(snapshot: dict[str, Any], store: LedgerStore) -> None:
    """Import one decoded ``CreditLedger.snapshot()`` into an empty store.

    This is intentionally a standalone data transformation: it performs no
    file I/O and has no knowledge of the live ledger path.  Legacy settlement
    rows are retained for idempotency but labelled ``legacy_unsigned`` because
    their worker participation was not cryptographically proven.
    """
    if not isinstance(store, LedgerStore):
        raise LedgerValueError("store must be a LedgerStore")
    if not isinstance(snapshot, dict):
        raise LedgerValueError("legacy snapshot must be a dict")
    raw_balances = snapshot.get("balances", {})
    raw_settled = snapshot.get("settled", {})
    if not isinstance(raw_balances, dict) or not isinstance(raw_settled, dict):
        raise LedgerValueError("legacy balances and settled fields must be dicts")

    balances: dict[str, int] = {}
    for account, value in raw_balances.items():
        account = _identifier(account, "legacy account")
        balances[account] = _stored_integer(value, f"legacy balance for {account}")

    receipts: list[tuple[str, str, str, int, int]] = []
    for receipt_id, raw in raw_settled.items():
        receipt_id = _identifier(receipt_id, "legacy receipt id")
        if not isinstance(raw, dict):
            raise LedgerValueError(f"legacy receipt {receipt_id!r} must be a dict")
        requester = _identifier(raw.get("requester"), "legacy requester")
        charged = _stored_integer(raw.get("debited"), "legacy debited")
        if charged < 0:
            raise LedgerValueError("legacy debited must not be negative")
        raw_credited = raw.get("credited", {})
        if not isinstance(raw_credited, dict):
            raise LedgerValueError("legacy credited must be a dict")
        credited: dict[str, int] = {}
        for account, amount in raw_credited.items():
            account = _identifier(account, "legacy credited account")
            credited[account] = _amount(amount, f"legacy credit for {account}")
        receipts.append(
            (
                receipt_id,
                requester,
                json.dumps(credited, sort_keys=True, separators=(",", ":")),
                charged,
                -charged,
            )
        )

    now = int(time.time())

    def operation(db: sqlite3.Connection) -> None:
        occupied = any(
            db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None
            for table in ("accounts", "receipts", "journal")
        )
        if occupied:
            raise LedgerError("legacy import requires an empty ledger store")
        for account, balance in balances.items():
            db.execute(
                "INSERT INTO accounts(id, balance, tier) VALUES (?, ?, 'stranger')",
                (account, balance),
            )
            if balance:
                db.execute(
                    "INSERT INTO journal(ts, kind, account, amount) "
                    "VALUES (?, 'legacy_import', ?, ?)",
                    (now, account, balance),
                )
        for receipt_id, requester, credited, charged, delta in receipts:
            db.execute(
                "INSERT INTO receipts(receipt_id, requester, credited, charged, delta, tier, "
                "state, created_at) VALUES (?, ?, ?, ?, ?, 'stranger', 'legacy_unsigned', ?)",
                (receipt_id, requester, credited, charged, delta, now),
            )

        imported_rows = db.execute(
            "SELECT id, balance FROM accounts ORDER BY id"
        ).fetchall()
        imported = {str(row[0]): int(row[1]) for row in imported_rows}
        if imported != balances or sum(imported.values()) != sum(balances.values()):
            raise AssertionError("legacy import balance totals do not match the snapshot")

    store._tx(operation)


__all__ = [
    "MAX_UNITS",
    "TIER_LIMITS",
    "LedgerError",
    "LedgerValueError",
    "CreditLimitError",
    "ReceiptStateError",
    "LedgerStore",
    "import_legacy_snapshot",
]
