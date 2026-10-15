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

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


# SQLite's INTEGER storage class is a signed 64-bit value.  Keeping the public
# bound identical prevents a large Python int from silently becoming REAL.
# Per-operation bound in TEST units: large enough for any real settle, small enough that a
# malformed or hostile amount can never approach integer overflow in balances.
MAX_UNITS = 10 ** 12

# Permanent conversion between the ledger's token-layer credits and the SPL
# token's smallest unit. Price changes belong in the model multiplier, not
# here: changing this value would re-price every existing balance.
RATE = 100

# Earnings remain reversible for the full receipt dispute window.
HOLD_S = 7 * 24 * 60 * 60
PAYOUT_COOLING_S = 48 * 60 * 60
WITHDRAWAL_DAY_S = 24 * 60 * 60
MIN_WITHDRAW_CREDITS = RATE * 1_000_000

TREASURY_ACCOUNT = "treasury"
_WITHDRAWAL_HOLD_STEM = "__withdrawal_hold__"
_WITHDRAWAL_HOLD_PREFIX = f"{_WITHDRAWAL_HOLD_STEM}:"
_SPEND_HOLD_STEM = "__spend_hold__"
_SPEND_HOLD_PREFIX = f"{_SPEND_HOLD_STEM}:"

SPEND_EXECUTION_S = 15 * 60
SPEND_SETTLEMENT_GRACE_S = 24 * 60 * 60
SPEND_EXPIRY_BATCH_SIZE = 200

# These limits mirror nakshatra/scripts/creditlimit.py.  Unknown tiers are
# intentionally treated as strangers (the tightest policy).
TIER_LIMITS: dict[str, int | None] = {
    "stranger": 1_000_000,
    "known": 25_000_000,
    "trusted": 250_000_000,
    "self": None,
}


class LedgerError(Exception):
    """Base class for an accounting operation that was refused."""


class LedgerInvariantError(LedgerError):
    """Durable ledger state violated a money-conservation invariant."""


class LedgerValueError(LedgerError, ValueError):
    """A caller supplied an invalid identifier, amount, or snapshot."""


class CreditLimitError(LedgerError):
    """A debit would put an account beyond its roster tier's limit."""


class ReceiptStateError(LedgerError):
    """A receipt exists but its durable state forbids the requested action."""


class DepositConflict(LedgerError):
    """A chain reference was replayed with details that do not match its deposit."""


class DepositBalanceMismatch(LedgerError):
    """A candidate deposit batch does not reconcile to its chain balance."""

    def __init__(self, expected: int, actual: int):
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"indexed deposits plus candidates total {actual}, expected {expected}"
        )


class WithdrawalStateError(ReceiptStateError):
    """A withdrawal does not exist or cannot make the requested state transition."""


class PayoutAddressError(LedgerError):
    """A withdrawal has no usable bound payout address."""


class WithdrawalRateLimitError(LedgerError):
    """The operator already requested a withdrawal in the current window."""


class WithdrawalTierError(LedgerError):
    """The operator's roster tier cannot cash out earned credits."""


class SpendConflict(LedgerError):
    """A spend idempotency key or immutable snapshot conflicts."""


class SpendStateError(ReceiptStateError):
    """A spend hold or worker entry cannot make the requested transition."""


class SpendExpired(SpendStateError):
    """A spend lifecycle request arrived after its applicable deadline."""


@dataclass(frozen=True)
class SpendExpiryBatch:
    """One committed expiry batch at a fixed sweep cutoff."""

    affected: tuple[str, ...]
    remaining: bool
    cutoff: int


def is_reserved(account: object) -> bool:
    """Return whether an account name belongs to ledger-internal accounting."""
    return isinstance(account, str) and (
        account == TREASURY_ACCOUNT
        or account.startswith(_WITHDRAWAL_HOLD_STEM)
        or account.startswith(_SPEND_HOLD_STEM)
    )


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


def _nonnegative_integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LedgerValueError(f"{name} must be an integer")
    if value < 0 or value > MAX_UNITS:
        raise LedgerValueError(f"{name} must be between 0 and {MAX_UNITS}")
    return value


def _bounded_product(*values: int, name: str) -> int:
    result = 1
    for value in values:
        result *= value
        if result > MAX_UNITS:
            raise LedgerValueError(f"{name} exceeds {MAX_UNITS}")
    return result


class LedgerStore:
    """SQLite-backed ledger implementing exactly-once settlement.

    One instance may be shared by a ``ThreadingHTTPServer``.  The connection is
    configured for cross-thread use, but all access is serialized by ``_lock``;
    this avoids both sqlite cursor races and application-level check-then-write
    races.  ``BEGIN IMMEDIATE`` also serializes writers using other connections.
    """

    def __init__(
        self, path: str | Path, *, clock: Callable[[], float] | None = None
    ):
        self.path = Path(path)
        self._clock = clock
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

            CREATE TABLE IF NOT EXISTS chain_refs (
                ref TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                account TEXT NOT NULL,
                token_account TEXT,
                amount INTEGER NOT NULL
                    CHECK(typeof(amount) = 'integer'
                          AND amount BETWEEN 1 AND {max_units}),
                slot INTEGER NOT NULL CHECK(typeof(slot) = 'integer' AND slot >= 0),
                ts INTEGER NOT NULL CHECK(typeof(ts) = 'integer')
            );

            CREATE TABLE IF NOT EXISTS deposit_accounts (
                operator TEXT PRIMARY KEY,
                token_account TEXT NOT NULL,
                created_ts INTEGER NOT NULL CHECK(typeof(created_ts) = 'integer')
            );

            CREATE UNIQUE INDEX IF NOT EXISTS deposit_accounts_token_account
            ON deposit_accounts(token_account);

            CREATE TABLE IF NOT EXISTS deposit_account_requests (
                operator TEXT PRIMARY KEY,
                requested_ts INTEGER NOT NULL CHECK(typeof(requested_ts) = 'integer')
            );

            CREATE TABLE IF NOT EXISTS payout_addresses (
                operator TEXT PRIMARY KEY,
                address TEXT NOT NULL,
                bound_ts INTEGER NOT NULL CHECK(typeof(bound_ts) = 'integer'),
                previous TEXT
            );

            CREATE TABLE IF NOT EXISTS withdrawals (
                id TEXT PRIMARY KEY,
                operator TEXT NOT NULL,
                amount INTEGER NOT NULL
                    CHECK(typeof(amount) = 'integer'
                          AND amount BETWEEN 1 AND {max_units}),
                address TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN
                    ('pending','approved','sent','finalized','released','expired')),
                tx_sig TEXT UNIQUE,
                approval_ref TEXT,
                created_ts INTEGER NOT NULL CHECK(typeof(created_ts) = 'integer'),
                updated_ts INTEGER NOT NULL CHECK(typeof(updated_ts) = 'integer')
            );

            CREATE TABLE IF NOT EXISTS deposit_account_queue (
                operator TEXT PRIMARY KEY,
                requested_ts INTEGER NOT NULL CHECK(typeof(requested_ts) = 'integer'),
                attempts INTEGER NOT NULL DEFAULT 0
                    CHECK(typeof(attempts) = 'integer' AND attempts >= 0),
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS withdrawal_attempts (
                withdrawal_id TEXT NOT NULL,
                attempt INTEGER NOT NULL
                    CHECK(typeof(attempt) = 'integer' AND attempt > 0),
                tx_sig TEXT NOT NULL UNIQUE,
                blockhash TEXT NOT NULL,
                last_valid_block_height INTEGER NOT NULL
                    CHECK(typeof(last_valid_block_height) = 'integer'
                          AND last_valid_block_height >= 0),
                tx_wire TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('sent','expired','finalized')),
                created_ts INTEGER NOT NULL CHECK(typeof(created_ts) = 'integer'),
                updated_ts INTEGER NOT NULL CHECK(typeof(updated_ts) = 'integer'),
                PRIMARY KEY(withdrawal_id, attempt),
                FOREIGN KEY(withdrawal_id) REFERENCES withdrawals(id)
            );

            CREATE TABLE IF NOT EXISTS spend_holds (
                hold_id TEXT PRIMARY KEY,
                payer_keyid TEXT NOT NULL,
                payer_account_at_authorize TEXT NOT NULL,
                payer_tier_at_authorize TEXT NOT NULL,
                client_nonce TEXT NOT NULL,
                session_id TEXT NOT NULL,
                model_id TEXT NOT NULL,
                billing_mode TEXT NOT NULL,
                max_prompt_tokens INTEGER NOT NULL
                    CHECK(typeof(max_prompt_tokens) = 'integer'
                          AND max_prompt_tokens BETWEEN 0 AND {max_units}),
                max_output_tokens INTEGER NOT NULL
                    CHECK(typeof(max_output_tokens) = 'integer'
                          AND max_output_tokens BETWEEN 0 AND {max_units}),
                max_token_layers INTEGER NOT NULL
                    CHECK(typeof(max_token_layers) = 'integer'
                          AND max_token_layers BETWEEN 0 AND {max_units}),
                max_cost INTEGER NOT NULL
                    CHECK(typeof(max_cost) = 'integer'
                          AND max_cost BETWEEN 0 AND {max_units}),
                authorization_digest TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                token_digest TEXT UNIQUE,
                escrow_account TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN
                    ('open','closing','settled','expired','cancelled','disputed')),
                release_requested INTEGER NOT NULL DEFAULT 0
                    CHECK(release_requested IN (0, 1)),
                authorized_at INTEGER NOT NULL CHECK(typeof(authorized_at) = 'integer'),
                execution_deadline INTEGER NOT NULL
                    CHECK(typeof(execution_deadline) = 'integer'),
                settlement_deadline INTEGER NOT NULL
                    CHECK(typeof(settlement_deadline) = 'integer'),
                terminal_at INTEGER,
                updated_at INTEGER NOT NULL CHECK(typeof(updated_at) = 'integer'),
                UNIQUE(payer_keyid, client_nonce),
                UNIQUE(payer_keyid, session_id),
                CHECK(execution_deadline > authorized_at),
                CHECK(settlement_deadline > execution_deadline),
                CHECK((state IN ('settled','expired','cancelled','disputed'))
                      = (terminal_at IS NOT NULL))
            );

            CREATE TABLE IF NOT EXISTS spend_hold_workers (
                hold_id TEXT NOT NULL,
                entry_index INTEGER NOT NULL
                    CHECK(typeof(entry_index) = 'integer' AND entry_index >= 0),
                worker_keyid TEXT NOT NULL,
                worker_account_at_authorize TEXT NOT NULL,
                billable INTEGER NOT NULL CHECK(billable IN (0, 1)),
                layer_start INTEGER NOT NULL
                    CHECK(typeof(layer_start) = 'integer' AND layer_start >= 0),
                layer_end INTEGER NOT NULL
                    CHECK(typeof(layer_end) = 'integer' AND layer_end > layer_start),
                layers INTEGER NOT NULL
                    CHECK(typeof(layers) = 'integer' AND layers > 0),
                price_multiplier INTEGER NOT NULL
                    CHECK(typeof(price_multiplier) = 'integer'
                          AND price_multiplier BETWEEN 1 AND {max_units}),
                max_prompt_tokens INTEGER NOT NULL
                    CHECK(typeof(max_prompt_tokens) = 'integer'
                          AND max_prompt_tokens BETWEEN 0 AND {max_units}),
                max_output_tokens INTEGER NOT NULL
                    CHECK(typeof(max_output_tokens) = 'integer'
                          AND max_output_tokens BETWEEN 0 AND {max_units}),
                max_token_layers INTEGER NOT NULL
                    CHECK(typeof(max_token_layers) = 'integer'
                          AND max_token_layers BETWEEN 0 AND {max_units}),
                max_cost INTEGER NOT NULL
                    CHECK(typeof(max_cost) = 'integer'
                          AND max_cost BETWEEN 0 AND {max_units}),
                state TEXT NOT NULL CHECK(state IN
                    ('planned','claimed','final','abandoned','expired')),
                claim_instance TEXT,
                claimed_at INTEGER,
                cumulative_prompt_tokens INTEGER NOT NULL DEFAULT 0
                    CHECK(typeof(cumulative_prompt_tokens) = 'integer'
                          AND cumulative_prompt_tokens BETWEEN 0 AND {max_units}),
                cumulative_generated_tokens INTEGER NOT NULL DEFAULT 0
                    CHECK(typeof(cumulative_generated_tokens) = 'integer'
                          AND cumulative_generated_tokens BETWEEN 0 AND {max_units}),
                cumulative_token_layers INTEGER NOT NULL DEFAULT 0
                    CHECK(typeof(cumulative_token_layers) = 'integer'
                          AND cumulative_token_layers BETWEEN 0 AND {max_units}),
                cumulative_cost INTEGER NOT NULL DEFAULT 0
                    CHECK(typeof(cumulative_cost) = 'integer'
                          AND cumulative_cost BETWEEN 0 AND {max_units}),
                final INTEGER NOT NULL DEFAULT 0 CHECK(final IN (0, 1)),
                final_receipt_id TEXT,
                finalized_at INTEGER,
                updated_at INTEGER NOT NULL CHECK(typeof(updated_at) = 'integer'),
                PRIMARY KEY(hold_id, worker_keyid),
                UNIQUE(hold_id, entry_index),
                FOREIGN KEY(hold_id) REFERENCES spend_holds(hold_id),
                CHECK(layers = layer_end - layer_start),
                CHECK((billable = 0 AND max_cost = 0) OR billable = 1),
                CHECK(cumulative_prompt_tokens <= max_prompt_tokens),
                CHECK(cumulative_generated_tokens <= max_output_tokens),
                CHECK(cumulative_token_layers <= max_token_layers),
                CHECK(cumulative_cost <= max_cost),
                CHECK(final = 0 OR state = 'final')
            );

            CREATE INDEX IF NOT EXISTS spend_holds_due
            ON spend_holds(state, execution_deadline, settlement_deadline);

            CREATE INDEX IF NOT EXISTS spend_workers_account
            ON spend_hold_workers(worker_account_at_authorize, hold_id);

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

            CREATE TRIGGER IF NOT EXISTS spend_holds_snapshots_immutable
            BEFORE UPDATE OF payer_keyid, payer_account_at_authorize,
                payer_tier_at_authorize, client_nonce, session_id, model_id,
                billing_mode, max_prompt_tokens, max_output_tokens,
                max_token_layers, max_cost, authorization_digest,
                token_digest, escrow_account, authorized_at,
                execution_deadline, settlement_deadline
            ON spend_holds
            BEGIN
                SELECT RAISE(ABORT, 'spend hold snapshot is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS spend_workers_snapshots_immutable
            BEFORE UPDATE OF entry_index, worker_keyid,
                worker_account_at_authorize, billable, layer_start, layer_end,
                layers, price_multiplier, max_prompt_tokens,
                max_output_tokens, max_token_layers, max_cost
            ON spend_hold_workers
            BEGIN
                SELECT RAISE(ABORT, 'spend worker snapshot is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS spend_holds_no_delete
            BEFORE DELETE ON spend_holds
            BEGIN
                SELECT RAISE(ABORT, 'spend holds are permanent');
            END;

            CREATE TRIGGER IF NOT EXISTS spend_workers_no_delete
            BEFORE DELETE ON spend_hold_workers
            BEGIN
                SELECT RAISE(ABORT, 'spend worker entries are permanent');
            END;
            """
        )
        collision = self._db.execute(
            "SELECT a.id, a.balance FROM accounts AS a "
            "LEFT JOIN spend_holds AS h ON h.escrow_account=a.id "
            "WHERE substr(a.id, 1, ?)=? AND h.hold_id IS NULL "
            "ORDER BY a.id LIMIT 1",
            (len(_SPEND_HOLD_STEM), _SPEND_HOLD_STEM),
        ).fetchone()
        if collision is not None:
            raise LedgerError(
                f"reserved spend account {collision['id']!r} (balance "
                f"{int(collision['balance'])}) is not backed by "
                "spend_holds.escrow_account; rename or remap this legacy "
                "account before reopening the ledger"
            )

        spend_hold_columns = {
            str(row[1]) for row in self._db.execute("PRAGMA table_info(spend_holds)")
        }
        if "request_digest" not in spend_hold_columns:
            self._db.execute("ALTER TABLE spend_holds ADD COLUMN request_digest TEXT")
        missing_request_digests = self._db.execute(
            "SELECT payer_keyid, client_nonce, session_id, model_id, billing_mode, "
            "max_prompt_tokens, max_output_tokens, hold_id FROM spend_holds "
            "WHERE request_digest IS NULL"
        ).fetchall()
        for hold in missing_request_digests:
            workers = self._db.execute(
                "SELECT worker_keyid, layer_start, layer_end "
                "FROM spend_hold_workers WHERE hold_id=? ORDER BY entry_index",
                (hold["hold_id"],),
            ).fetchall()
            request_digest = self._spend_request_digest(
                payer_keyid=str(hold["payer_keyid"]),
                client_nonce=str(hold["client_nonce"]),
                session_id=str(hold["session_id"]),
                model_id=str(hold["model_id"]),
                billing_mode=str(hold["billing_mode"]),
                max_prompt_tokens=int(hold["max_prompt_tokens"]),
                max_output_tokens=int(hold["max_output_tokens"]),
                workers=workers,
            )
            self._db.execute(
                "UPDATE spend_holds SET request_digest=? WHERE hold_id=?",
                (request_digest, hold["hold_id"]),
            )
        self._db.executescript(
            """
            CREATE TRIGGER IF NOT EXISTS spend_holds_request_digest_immutable
            BEFORE UPDATE OF request_digest ON spend_holds
            BEGIN
                SELECT RAISE(ABORT, 'spend hold request digest is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS spend_holds_request_digest_required
            BEFORE INSERT ON spend_holds
            WHEN NEW.request_digest IS NULL
            BEGIN
                SELECT RAISE(ABORT, 'spend hold request digest is required');
            END;
            """
        )
        # S3 adds the per-chain-account provenance required for account-scoped
        # reconciliation. Existing S1 databases are upgraded in place.
        chain_ref_columns = {
            str(row[1]) for row in self._db.execute("PRAGMA table_info(chain_refs)")
        }
        if "token_account" not in chain_ref_columns:
            self._db.execute("ALTER TABLE chain_refs ADD COLUMN token_account TEXT")
        # S4 payout state is additive so existing S1 databases open in place.
        withdrawal_columns = {
            str(row[1]) for row in self._db.execute("PRAGMA table_info(withdrawals)")
        }
        for name, definition in (
            ("approval_ts", "INTEGER"),
            ("presence_attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("expiry_count", "INTEGER NOT NULL DEFAULT 0"),
            ("blockhash", "TEXT"),
            ("last_valid_block_height", "INTEGER"),
            ("tx_wire", "TEXT"),
        ):
            if name not in withdrawal_columns:
                self._db.execute(
                    f"ALTER TABLE withdrawals ADD COLUMN {name} {definition}"
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
                total = self._db.execute(
                    "SELECT COALESCE(SUM(balance), 0) FROM accounts"
                ).fetchone()[0]
                if total != 0:
                    raise LedgerInvariantError(
                        f"ledger balance invariant violated: sum={total}"
                    )
                self._db.execute("COMMIT")
                return result
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def _now(self) -> int:
        return int(self._clock() if self._clock is not None else time.time())

    @staticmethod
    def _spend_request_digest(
        *,
        payer_keyid: str,
        client_nonce: str,
        session_id: str,
        model_id: str,
        billing_mode: str,
        max_prompt_tokens: int,
        max_output_tokens: int,
        workers: Iterable[Mapping[str, Any]],
    ) -> str:
        request = {
            "v": 1,
            "payer_keyid": payer_keyid,
            "client_nonce": client_nonce,
            "session_id": session_id,
            "model_id": model_id,
            "billing_mode": billing_mode,
            "max_prompt_tokens": max_prompt_tokens,
            "max_output_tokens": max_output_tokens,
            "workers": [
                {
                    "worker_keyid": str(worker["worker_keyid"]),
                    "layer_start": int(worker["layer_start"]),
                    "layer_end": int(worker["layer_end"]),
                }
                for worker in workers
            ],
        }
        canonical = json.dumps(request, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

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

    @staticmethod
    def _withdrawal_hold_account(withdrawal_id: str) -> str:
        return f"{_WITHDRAWAL_HOLD_PREFIX}{withdrawal_id}"

    @staticmethod
    def _spend_hold_account(hold_id: str) -> str:
        return f"{_SPEND_HOLD_PREFIX}{hold_id}"

    @staticmethod
    def _restricted_paid_earnings_in(
        db: sqlite3.Connection, account: str, now: int
    ) -> int:
        """Return earnings N1 must not treat as paid-hold collateral.

        N2 replaces this deliberately narrow compatibility query with the
        shared economic-receipt view.  Its additional per-spend-earn row query
        is provisional and must not remain once ledger history makes it
        authorization-lock-heavy.  Until then, legacy funded earnings use
        their existing journal timestamp maturity, spend earnings use the
        hold's terminal timestamp, and imported positive balances remain
        restricted until an explicit reconciliation proves their provenance.
        Unfunded, nonterminal, and disputed earnings remain restricted.
        """
        restricted = int(
            db.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM journal "
                "WHERE account=? AND kind='legacy_import' AND amount>0",
                (account,),
            ).fetchone()[0]
        )
        legacy_rows = db.execute(
            "SELECT j.ts, j.amount, j.detail, r.state FROM journal AS j "
            "JOIN receipts AS r ON r.receipt_id=j.receipt_id "
            "WHERE j.account=? AND j.kind='earn'",
            (account,),
        ).fetchall()
        for row in legacy_rows:
            if row["state"] != "settled":
                continue
            try:
                funded = json.loads(row["detail"]).get("funded") is True
            except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
                funded = False
            if not funded or now <= int(row["ts"]) + HOLD_S:
                restricted += int(row["amount"])

        spend_rows = db.execute(
            "SELECT amount, detail FROM journal "
            "WHERE account=? AND kind='spend_earn' AND amount>0",
            (account,),
        ).fetchall()
        for row in spend_rows:
            try:
                hold_id = json.loads(row["detail"])["hold_id"]
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                # Malformed economic provenance is never eligible collateral.
                restricted += int(row["amount"])
                continue
            hold = db.execute(
                "SELECT state, terminal_at FROM spend_holds WHERE hold_id=?",
                (hold_id,),
            ).fetchone()
            if (
                hold is None
                or hold["state"] == "disputed"
                or hold["terminal_at"] is None
                or now <= int(hold["terminal_at"]) + HOLD_S
            ):
                restricted += int(row["amount"])
        return restricted

    @staticmethod
    def _spend_liability_in(db: sqlite3.Connection, hold_id: str) -> int:
        return int(
            db.execute(
                "SELECT COALESCE(SUM(max_cost - cumulative_cost), 0) "
                "FROM spend_hold_workers WHERE hold_id=? "
                "AND state IN ('planned','claimed','final')",
                (hold_id,),
            ).fetchone()[0]
        )

    @classmethod
    def _assert_spend_hold_in(cls, db: sqlite3.Connection, hold_id: str) -> None:
        hold = db.execute(
            "SELECT state, escrow_account FROM spend_holds WHERE hold_id=?",
            (hold_id,),
        ).fetchone()
        if hold is None:
            raise SpendStateError(f"spend hold {hold_id!r} does not exist")
        balance = cls._balance_in(db, str(hold["escrow_account"]))
        expected = (
            0
            if hold["state"] in {"settled", "expired", "cancelled", "disputed"}
            else cls._spend_liability_in(db, hold_id)
        )
        if balance != expected:
            raise LedgerError(
                f"spend hold {hold_id!r} balance is {balance}, expected {expected}"
            )

    @classmethod
    def _move_spend_value(
        cls,
        db: sqlite3.Connection,
        *,
        source: str,
        destination: str,
        amount: int,
        timestamp: int,
        debit_kind: str,
        credit_kind: str,
        event_id: str,
        detail: Mapping[str, Any],
    ) -> None:
        if amount == 0:
            return
        source_new = cls._checked_balance(
            cls._balance_in(db, source) - amount, source
        )
        destination_new = cls._checked_balance(
            cls._balance_in(db, destination) + amount, destination
        )
        cls._ensure_account(db, source)
        cls._ensure_account(db, destination)
        cls._set_balance(db, source, source_new)
        cls._set_balance(db, destination, destination_new)
        encoded = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        db.execute(
            "INSERT INTO journal(ts, kind, receipt_id, account, counterparty, "
            "amount, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (timestamp, debit_kind, event_id, source, destination, -amount, encoded),
        )
        db.execute(
            "INSERT INTO journal(ts, kind, receipt_id, account, counterparty, "
            "amount, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                timestamp,
                credit_kind,
                event_id,
                destination,
                source,
                amount,
                encoded,
            ),
        )

    @staticmethod
    def _withdrawable_in(db: sqlite3.Connection, operator: str, now: int) -> int:
        balance = LedgerStore._balance_in(db, operator)
        deposited = int(
            db.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM chain_refs "
                "WHERE kind='deposit' AND account=?",
                (operator,),
            ).fetchone()[0]
        )
        withdrawn = int(
            db.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM withdrawals "
                "WHERE operator=? AND state='finalized'",
                (operator,),
            ).fetchone()[0]
        )
        held = int(
            db.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM withdrawals "
                "WHERE operator=? AND state IN ('pending','approved','sent','expired')",
                (operator,),
            ).fetchone()[0]
        )

        matured_earnings = 0
        rows = db.execute(
            "SELECT j.amount, j.detail FROM journal AS j "
            "JOIN receipts AS r ON r.receipt_id=j.receipt_id "
            "WHERE j.account=? AND j.kind='earn' AND j.ts<=? AND r.state='settled'",
            (operator, now - HOLD_S),
        ).fetchall()
        for row in rows:
            try:
                funded = json.loads(row["detail"]).get("funded") is True
            except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
                funded = False
            if funded:
                matured_earnings += int(row["amount"])

        entitlement = deposited - withdrawn - held + matured_earnings
        return max(0, min(balance, entitlement))

    @staticmethod
    def _net_deposits_in(db: sqlite3.Connection, operator: str) -> int:
        deposited = int(
            db.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM chain_refs "
                "WHERE kind='deposit' AND account=?",
                (operator,),
            ).fetchone()[0]
        )
        removed = int(
            db.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM withdrawals "
                "WHERE operator=? AND state IN "
                "('pending','approved','sent','finalized','expired')",
                (operator,),
            ).fetchone()[0]
        )
        return max(0, deposited - removed)

    def settle(
        self,
        receipt_id: str,
        requester: str,
        credited: dict[str, int],
        charged: int,
        tier: str,
        *,
        account_tiers: Mapping[str, str] | None = None,
    ) -> int:
        """Apply a verified receipt once and return the requester's delta.

        Replaying an already-settled ``receipt_id`` returns its stored delta and
        makes no writes.  A disputed or legacy receipt can never be settled.
        """
        receipt_id = _identifier(receipt_id, "receipt_id")
        requester = _identifier(requester, "requester")
        if is_reserved(requester):
            raise LedgerValueError("requester is reserved")
        # Work on the requester's OWN nodes is free (local = free) but is still recorded for the audit.
        charged = _amount(charged, "charged", allow_zero=True)
        tier = _tier(tier)
        if not isinstance(credited, dict):
            raise LedgerValueError("credited must be a dict of account to amount")
        clean_credits: dict[str, int] = {}
        for account, amount in credited.items():
            account = _identifier(account, "credited account")
            if is_reserved(account):
                raise LedgerValueError("credited account is reserved")
            clean_credits[account] = _amount(amount, f"credit for {account}")
        if sum(clean_credits.values()) != charged:
            raise LedgerValueError("credited amounts must sum to charged")
        clean_account_tiers = {
            account: _tier(account_tiers[account])
            for account in clean_credits
            if account != requester
            and account_tiers is not None
            and account in account_tiers
        }
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
            funded = old_requester_balance >= charged
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
                account_tier = (
                    tier if account == requester
                    else clean_account_tiers.get(account, "stranger")
                )
                self._ensure_account(db, account, account_tier)
            db.execute("UPDATE accounts SET tier=? WHERE id=?", (tier, requester))
            for account, account_tier in clean_account_tiers.items():
                db.execute("UPDATE accounts SET tier=? WHERE id=?", (account_tier, account))
            for account, balance in final.items():
                self._set_balance(db, account, balance)
            for account, amount in clean_credits.items():
                db.execute(
                    "INSERT INTO journal(ts, kind, receipt_id, account, counterparty, amount, detail) "
                    "VALUES (?, 'earn', ?, ?, ?, ?, ?)",
                    (
                        now,
                        receipt_id,
                        account,
                        requester,
                        amount,
                        json.dumps({"funded": funded}, separators=(",", ":")),
                    ),
                )
            if charged:  # a free own-node settle has no spend row; its receipts row is the record
                db.execute(
                    "INSERT INTO journal(ts, kind, receipt_id, account, amount, detail) "
                    "VALUES (?, 'spend', ?, ?, ?, ?)",
                    (now, receipt_id, requester, -charged, json.dumps({"tier": tier})),
                )
            return delta

        return self._tx(operation)

    def deposit(self, ref: str, operator: str, credits: int, slot: int) -> int:
        """Credit one finalized chain deposit exactly once and return its credits."""
        ref = _identifier(ref, "ref")
        operator = _identifier(operator, "operator")
        if is_reserved(operator):
            raise LedgerValueError("operator is reserved")
        credits = _amount(credits, "credits")
        if isinstance(slot, bool) or not isinstance(slot, int) or slot < 0:
            raise LedgerValueError("slot must be a non-negative integer")
        if slot > 2 ** 63 - 1:
            raise LedgerValueError("slot is outside SQLite integer bounds")
        now = int(time.time())

        def operation(db: sqlite3.Connection) -> int:
            existing = db.execute(
                "SELECT kind, account, amount, slot FROM chain_refs WHERE ref=?", (ref,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["kind"] != "deposit"
                    or existing["account"] != operator
                    or int(existing["amount"]) != credits
                    or int(existing["slot"]) != slot
                ):
                    raise DepositConflict(
                        f"deposit reference {ref!r} already has different details"
                    )
                return int(existing["amount"])

            treasury_new = self._checked_balance(
                self._balance_in(db, TREASURY_ACCOUNT) - credits,
                TREASURY_ACCOUNT,
            )
            operator_new = self._checked_balance(
                self._balance_in(db, operator) + credits,
                operator,
            )
            self._ensure_account(db, TREASURY_ACCOUNT, "self")
            self._ensure_account(db, operator)
            db.execute(
                "UPDATE accounts SET tier='self' WHERE id=?", (TREASURY_ACCOUNT,)
            )
            self._set_balance(db, TREASURY_ACCOUNT, treasury_new)
            self._set_balance(db, operator, operator_new)
            db.execute(
                "INSERT INTO chain_refs(ref, kind, account, amount, slot, ts) "
                "VALUES (?, 'deposit', ?, ?, ?, ?)",
                (ref, operator, credits, slot, now),
            )
            detail = json.dumps(
                {"rate": RATE, "ref": ref, "slot": slot},
                sort_keys=True,
                separators=(",", ":"),
            )
            db.execute(
                "INSERT INTO journal(ts, kind, account, counterparty, amount, detail) "
                "VALUES (?, 'deposit', ?, ?, ?, ?)",
                (now, operator, TREASURY_ACCOUNT, credits, detail),
            )
            return credits

        return self._tx(operation)

    def deposit_batch(
        self,
        operator: str,
        token_account: str,
        deposits: Iterable[tuple[str, int, int]],
        expected_total: int,
        *,
        cursor: str | None = None,
    ) -> int:
        """Reconcile and atomically credit finalized deposits for one account.

        ``deposits`` contains ``(ref, credits, slot)`` tuples.  The batch is
        committed only when this token account's already-indexed deposits plus
        the new, non-replayed candidates equal ``expected_total``.  When a
        signature ``cursor`` is supplied, its indexer cursor is advanced in the
        same SQLite transaction as the credits.

        Exact replays are idempotent.  A ref whose stored or repeated details
        differ still raises :class:`DepositConflict`, and all failure paths
        roll back the entire batch (including the cursor).
        """
        operator = _identifier(operator, "operator")
        if is_reserved(operator):
            raise LedgerValueError("operator is reserved")
        token_account = _identifier(token_account, "token_account")
        expected_total = _amount(expected_total, "expected_total", allow_zero=True)

        clean: dict[str, tuple[int, int]] = {}
        try:
            candidates = list(deposits)
        except TypeError as exc:
            raise LedgerValueError("deposits must be an iterable") from exc
        for index, candidate in enumerate(candidates):
            if not isinstance(candidate, (tuple, list)) or len(candidate) != 3:
                raise LedgerValueError(
                    f"deposit {index} must be a (ref, credits, slot) tuple"
                )
            ref = _identifier(candidate[0], f"deposit {index} ref")
            credits = _amount(candidate[1], f"deposit {index} credits")
            slot = candidate[2]
            if isinstance(slot, bool) or not isinstance(slot, int) or slot < 0:
                raise LedgerValueError(
                    f"deposit {index} slot must be a non-negative integer"
                )
            if slot > 2 ** 63 - 1:
                raise LedgerValueError(
                    f"deposit {index} slot is outside SQLite integer bounds"
                )
            previous = clean.get(ref)
            if previous is not None and previous != (credits, slot):
                raise DepositConflict(
                    f"deposit reference {ref!r} appears with different details"
                )
            clean[ref] = (credits, slot)

        clean_cursor = (
            _identifier(cursor, "cursor signature") if cursor is not None else None
        )

        now = int(time.time())

        def operation(db: sqlite3.Connection) -> int:
            already_indexed = int(
                db.execute(
                    "SELECT COALESCE(SUM(amount), 0) FROM chain_refs "
                    "WHERE kind='deposit' AND account=? AND token_account=?",
                    (operator, token_account),
                ).fetchone()[0]
            )
            pending: list[tuple[str, int, int]] = []
            for ref, (credits, slot) in clean.items():
                existing = db.execute(
                    "SELECT kind, account, token_account, amount, slot "
                    "FROM chain_refs WHERE ref=?",
                    (ref,),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["kind"] != "deposit"
                        or existing["account"] != operator
                        or existing["token_account"] != token_account
                        or int(existing["amount"]) != credits
                        or int(existing["slot"]) != slot
                    ):
                        raise DepositConflict(
                            f"deposit reference {ref!r} already has different details"
                        )
                    continue
                pending.append((ref, credits, slot))

            reconciled_total = already_indexed + sum(
                credits for _ref, credits, _slot in pending
            )
            if reconciled_total != expected_total:
                raise DepositBalanceMismatch(expected_total, reconciled_total)

            added = sum(credits for _ref, credits, _slot in pending)
            if added:
                treasury_new = self._checked_balance(
                    self._balance_in(db, TREASURY_ACCOUNT) - added,
                    TREASURY_ACCOUNT,
                )
                operator_new = self._checked_balance(
                    self._balance_in(db, operator) + added,
                    operator,
                )
                self._ensure_account(db, TREASURY_ACCOUNT, "self")
                self._ensure_account(db, operator)
                db.execute(
                    "UPDATE accounts SET tier='self' WHERE id=?", (TREASURY_ACCOUNT,)
                )
                self._set_balance(db, TREASURY_ACCOUNT, treasury_new)
                self._set_balance(db, operator, operator_new)
                for ref, credits, slot in pending:
                    db.execute(
                        "INSERT INTO chain_refs"
                        "(ref, kind, account, token_account, amount, slot, ts) "
                        "VALUES (?, 'deposit', ?, ?, ?, ?, ?)",
                        (ref, operator, token_account, credits, slot, now),
                    )
                    detail = json.dumps(
                        {"rate": RATE, "ref": ref, "slot": slot},
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    db.execute(
                        "INSERT INTO journal(ts, kind, account, counterparty, amount, detail) "
                        "VALUES (?, 'deposit', ?, ?, ?, ?)",
                        (now, operator, TREASURY_ACCOUNT, credits, detail),
                    )

            if clean_cursor is not None:
                updated = db.execute(
                    "UPDATE chain_indexer_accounts SET cursor=?, updated_ts=? "
                    "WHERE token_account=?",
                    (clean_cursor, now, token_account),
                ).rowcount
                if updated != 1:
                    raise LedgerValueError(
                        f"indexer state does not exist for {token_account!r}"
                    )
            return added

        return self._tx(operation)

    def queue_deposit_account(self, operator: str) -> bool:
        """Queue creation of a treasury-owned token account for *operator*.

        Returns ``True`` when a new queue row was written and ``False`` when
        the operator already has an account or an outstanding request.
        """
        operator = _identifier(operator, "operator")
        if is_reserved(operator):
            raise LedgerValueError("operator is reserved")
        now = int(time.time())

        def operation(db: sqlite3.Connection) -> bool:
            if db.execute(
                "SELECT 1 FROM deposit_accounts WHERE operator=?", (operator,)
            ).fetchone():
                return False
            result = db.execute(
                "INSERT OR IGNORE INTO deposit_account_queue(operator, requested_ts) "
                "VALUES (?, ?)",
                (operator, now),
            )
            return result.rowcount == 1

        return self._tx(operation)

    def pending_deposit_accounts(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return queued account requests in stable FIFO order."""
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise LedgerValueError("limit must be a positive integer")
        with self._lock:
            rows = self._db.execute(
                "SELECT operator, requested_ts, attempts, last_error "
                "FROM deposit_account_queue ORDER BY requested_ts, operator LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_deposit_account_error(self, operator: str, error: str) -> None:
        """Record a failed creation attempt without losing the queued request."""
        operator = _identifier(operator, "operator")
        error = _identifier(error, "error")[:500]

        def operation(db: sqlite3.Connection) -> None:
            updated = db.execute(
                "UPDATE deposit_account_queue SET attempts=attempts+1, last_error=? "
                "WHERE operator=?",
                (error, operator),
            ).rowcount
            if updated != 1:
                raise LedgerValueError(f"no queued deposit account for {operator!r}")

        self._tx(operation)

    def register_deposit_account(self, operator: str, token_account: str) -> str:
        """Atomically bind a created token account and consume its queue row."""
        operator = _identifier(operator, "operator")
        token_account = _identifier(token_account, "token_account")
        now = int(time.time())

        def operation(db: sqlite3.Connection) -> str:
            existing = db.execute(
                "SELECT token_account FROM deposit_accounts WHERE operator=?",
                (operator,),
            ).fetchone()
            if existing is not None:
                if existing[0] != token_account:
                    raise LedgerValueError(
                        f"operator {operator!r} already has a different deposit account"
                    )
                db.execute(
                    "DELETE FROM deposit_account_queue WHERE operator=?", (operator,)
                )
                return token_account
            if db.execute(
                "SELECT 1 FROM deposit_account_queue WHERE operator=?", (operator,)
            ).fetchone() is None:
                raise LedgerValueError(f"no queued deposit account for {operator!r}")
            try:
                db.execute(
                    "INSERT INTO deposit_accounts(operator, token_account, created_ts) "
                    "VALUES (?, ?, ?)",
                    (operator, token_account, now),
                )
            except sqlite3.IntegrityError as exc:
                raise LedgerValueError("token account is already bound") from exc
            db.execute("DELETE FROM deposit_account_queue WHERE operator=?", (operator,))
            return token_account

        return self._tx(operation)

    def withdrawable(self, operator: str) -> int:
        """Return cashable credits: net deposits plus funded, matured earnings."""
        operator = _identifier(operator, "operator")
        if is_reserved(operator):
            raise LedgerValueError("operator is reserved")
        with self._lock:
            return self._withdrawable_in(self._db, operator, int(time.time()))

    def wallet(self, operator: str) -> dict[str, Any]:
        """Return the deposit account, durably requesting treasury creation if absent."""
        operator = _identifier(operator, "operator")
        if is_reserved(operator):
            raise LedgerValueError("operator is reserved")
        now = int(time.time())

        def operation(db: sqlite3.Connection) -> dict[str, Any]:
            row = db.execute(
                "SELECT token_account, created_ts FROM deposit_accounts WHERE operator=?",
                (operator,),
            ).fetchone()
            if row is not None:
                return {
                    "status": "ready",
                    "deposit_address": str(row["token_account"]),
                    "created_ts": int(row["created_ts"]),
                }
            db.execute(
                "INSERT INTO deposit_account_requests(operator, requested_ts) VALUES (?, ?) "
                "ON CONFLICT(operator) DO NOTHING",
                (operator, now),
            )
            requested = db.execute(
                "SELECT requested_ts FROM deposit_account_requests WHERE operator=?",
                (operator,),
            ).fetchone()
            return {
                "status": "pending",
                "deposit_address": None,
                "requested_ts": int(requested["requested_ts"]),
            }

        return self._tx(operation)

    def bind_payout_address(self, operator: str, address: str) -> dict[str, Any]:
        """Bind a payout address; changing it starts the 48-hour cooling window."""
        operator = _identifier(operator, "operator")
        address = _identifier(address, "address")
        if is_reserved(operator):
            raise LedgerValueError("operator is reserved")
        now = int(time.time())

        def operation(db: sqlite3.Connection) -> dict[str, Any]:
            row = db.execute(
                "SELECT address, bound_ts, previous FROM payout_addresses WHERE operator=?",
                (operator,),
            ).fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO payout_addresses(operator, address, bound_ts, previous) "
                    "VALUES (?, ?, ?, NULL)",
                    (operator, address, now),
                )
                return {
                    "address": address,
                    "bound_ts": now,
                    "previous": None,
                    "changed": False,
                    "cooling_until": None,
                }
            if row["address"] == address:
                previous = row["previous"]
                bound_ts = int(row["bound_ts"])
                return {
                    "address": address,
                    "bound_ts": bound_ts,
                    "previous": previous,
                    "changed": False,
                    "cooling_until": (
                        bound_ts + PAYOUT_COOLING_S if previous is not None else None
                    ),
                }
            db.execute(
                "UPDATE payout_addresses SET address=?, bound_ts=?, previous=? "
                "WHERE operator=?",
                (address, now, row["address"], operator),
            )
            return {
                "address": address,
                "bound_ts": now,
                "previous": row["address"],
                "changed": True,
                "cooling_until": now + PAYOUT_COOLING_S,
            }

        return self._tx(operation)

    def wallet_status(self, operator: str) -> dict[str, Any]:
        """Return the signer's money-facing status without exposing internal hold accounts."""
        operator = _identifier(operator, "operator")
        if is_reserved(operator):
            raise LedgerValueError("operator is reserved")
        now = int(time.time())
        with self._lock:
            balance = self._balance_in(self._db, operator)
            withdrawable = self._withdrawable_in(self._db, operator, now)
            payout = self._db.execute(
                "SELECT address, bound_ts, previous FROM payout_addresses WHERE operator=?",
                (operator,),
            ).fetchone()
            rows = self._db.execute(
                "SELECT id, amount, address, state, tx_sig, created_ts, updated_ts "
                "FROM withdrawals WHERE operator=? AND state NOT IN ('finalized','released') "
                "ORDER BY created_ts, id",
                (operator,),
            ).fetchall()
            payout_value = None
            if payout is not None:
                bound_ts = int(payout["bound_ts"])
                payout_value = {
                    "address": str(payout["address"]),
                    "bound_ts": bound_ts,
                    "cooling_until": (
                        bound_ts + PAYOUT_COOLING_S
                        if payout["previous"] is not None else None
                    ),
                }
            return {
                "balance": balance,
                "withdrawable": withdrawable,
                "payout": payout_value,
                "pending_withdrawals": [dict(row) for row in rows],
            }

    def request_withdrawal(
        self,
        operator: str,
        amount: int,
        tier: str,
        *,
        address: str | None = None,
    ) -> str:
        """Apply withdrawal policy and create the pending hold in one transaction."""
        operator = _identifier(operator, "operator")
        if is_reserved(operator):
            raise LedgerValueError("operator is reserved")
        amount = _amount(amount)
        if amount < MIN_WITHDRAW_CREDITS:
            raise LedgerValueError(
                f"amount must be at least {MIN_WITHDRAW_CREDITS} credits (1 USDC)"
            )
        if amount % RATE:
            raise LedgerValueError(f"amount must be a multiple of {RATE} credits")
        if address is not None:
            address = _identifier(address, "address")
        tier = _tier(tier)
        now = int(time.time())
        withdrawal_id = uuid.uuid4().hex
        hold_account = self._withdrawal_hold_account(withdrawal_id)

        def operation(db: sqlite3.Connection) -> str:
            payout = db.execute(
                "SELECT address, bound_ts, previous FROM payout_addresses WHERE operator=?",
                (operator,),
            ).fetchone()
            if payout is None:
                raise PayoutAddressError("bind a payout address before withdrawing")
            bound_address = str(payout["address"])
            if address is not None and address != bound_address:
                raise PayoutAddressError("withdrawal address is not the bound payout address")
            if (
                payout["previous"] is not None
                and now < int(payout["bound_ts"]) + PAYOUT_COOLING_S
            ):
                raise PayoutAddressError("the changed payout address is still cooling")
            recent = db.execute(
                "SELECT 1 FROM withdrawals WHERE operator=? AND created_ts>? LIMIT 1",
                (operator, now - WITHDRAWAL_DAY_S),
            ).fetchone()
            if recent is not None:
                raise WithdrawalRateLimitError("only one withdrawal may be requested per day")
            available = self._withdrawable_in(db, operator, now)
            if amount > available:
                raise CreditLimitError(
                    f"withdrawal exceeds withdrawable balance {available}: {amount}"
                )
            balance = self._balance_in(db, operator)
            own_deposits = min(max(0, balance), self._net_deposits_in(db, operator))
            if amount > own_deposits and tier == "stranger":
                raise WithdrawalTierError("known tier or higher is required for earnings")

            operator_new = self._checked_balance(balance - amount, operator)
            hold_new = self._checked_balance(
                self._balance_in(db, hold_account) + amount, hold_account
            )
            self._ensure_account(db, operator)
            self._ensure_account(db, hold_account, "self")
            self._set_balance(db, operator, operator_new)
            self._set_balance(db, hold_account, hold_new)
            db.execute(
                "INSERT INTO withdrawals(id, operator, amount, address, state, "
                "created_ts, updated_ts) VALUES (?, ?, ?, ?, 'pending', ?, ?)",
                (withdrawal_id, operator, amount, bound_address, now, now),
            )
            detail = json.dumps(
                {
                    "address": bound_address,
                    "rate": RATE,
                    "withdrawal_id": withdrawal_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            db.execute(
                "INSERT INTO journal(ts, kind, account, counterparty, amount, detail) "
                "VALUES (?, 'withdraw_hold', ?, ?, ?, ?)",
                (now, operator, hold_account, -amount, detail),
            )
            return withdrawal_id

        return self._tx(operation)

    def withdraw_hold(
        self,
        operator: str,
        amount: int,
        address: str,
        withdrawal_id: str | None = None,
    ) -> str:
        """Debit an operator into a pending hold and return its withdrawal id."""
        operator = _identifier(operator, "operator")
        address = _identifier(address, "address")
        if is_reserved(operator):
            raise LedgerValueError("operator is reserved")
        amount = _amount(amount)
        if withdrawal_id is None:
            withdrawal_id = uuid.uuid4().hex
        withdrawal_id = _identifier(withdrawal_id, "withdrawal_id")
        now = int(time.time())
        hold_account = self._withdrawal_hold_account(withdrawal_id)

        def operation(db: sqlite3.Connection) -> str:
            existing = db.execute(
                "SELECT operator, amount, address FROM withdrawals WHERE id=?",
                (withdrawal_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["operator"] == operator
                    and int(existing["amount"]) == amount
                    and existing["address"] == address
                ):
                    return withdrawal_id
                raise LedgerValueError("withdrawal_id already has different details")

            available = self._withdrawable_in(db, operator, now)
            if amount > available:
                raise CreditLimitError(
                    f"withdrawal exceeds withdrawable balance {available}: {amount}"
                )
            # A stranger may recover only their own net deposits. Cashing
            # funded/matured earnings requires the decided known+ tier.
            deposited = int(
                db.execute(
                    "SELECT COALESCE(SUM(amount), 0) FROM chain_refs "
                    "WHERE kind='deposit' AND account=?",
                    (operator,),
                ).fetchone()[0]
            )
            committed = int(
                db.execute(
                    "SELECT COALESCE(SUM(amount), 0) FROM withdrawals "
                    "WHERE operator=? AND state IN "
                    "('pending','approved','sent','expired','finalized')",
                    (operator,),
                ).fetchone()[0]
            )
            deposit_cash = max(
                0,
                min(self._balance_in(db, operator), deposited - committed),
            )
            tier_row = db.execute(
                "SELECT tier FROM accounts WHERE id=?", (operator,)
            ).fetchone()
            tier = _tier(tier_row[0] if tier_row else "stranger")
            if amount > deposit_cash and tier == "stranger":
                raise CreditLimitError("cashing earnings requires tier known or higher")
            operator_new = self._checked_balance(
                self._balance_in(db, operator) - amount, operator
            )
            hold_new = self._checked_balance(
                self._balance_in(db, hold_account) + amount, hold_account
            )
            self._ensure_account(db, operator)
            self._ensure_account(db, hold_account, "self")
            self._set_balance(db, operator, operator_new)
            self._set_balance(db, hold_account, hold_new)
            db.execute(
                "INSERT INTO withdrawals(id, operator, amount, address, state, "
                "created_ts, updated_ts) VALUES (?, ?, ?, ?, 'pending', ?, ?)",
                (withdrawal_id, operator, amount, address, now, now),
            )
            detail = json.dumps(
                {"address": address, "rate": RATE, "withdrawal_id": withdrawal_id},
                sort_keys=True,
                separators=(",", ":"),
            )
            db.execute(
                "INSERT INTO journal(ts, kind, account, counterparty, amount, detail) "
                "VALUES (?, 'withdraw_hold', ?, ?, ?, ?)",
                (now, operator, hold_account, -amount, detail),
            )
            return withdrawal_id

        return self._tx(operation)

    def withdrawals(self, *states: str, limit: int = 100) -> list[dict[str, Any]]:
        """Return payout rows for the requested states, oldest first."""
        allowed = {"pending", "approved", "sent", "finalized", "released", "expired"}
        if not states or any(state not in allowed for state in states):
            raise LedgerValueError("one or more valid withdrawal states are required")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise LedgerValueError("limit must be a positive integer")
        placeholders = ",".join("?" for _ in states)
        with self._lock:
            rows = self._db.execute(
                f"SELECT * FROM withdrawals WHERE state IN ({placeholders}) "
                "ORDER BY created_ts, id LIMIT ?",
                (*states, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def approved_withdrawal_total_since(self, timestamp: int) -> int:
        """Return credits approved at or after *timestamp* (including terminal rows)."""
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
            raise LedgerValueError("timestamp must be a non-negative integer")
        with self._lock:
            return int(
                self._db.execute(
                    "SELECT COALESCE(SUM(amount), 0) FROM withdrawals "
                    "WHERE approval_ts IS NOT NULL AND approval_ts>=?",
                    (timestamp,),
                ).fetchone()[0]
            )

    def withdraw_approve(self, withdrawal_id: str, approval_ref: str) -> int:
        """Move one pending hold to approved, preserving the approval reference."""
        withdrawal_id = _identifier(withdrawal_id, "withdrawal_id")
        approval_ref = _identifier(approval_ref, "approval_ref")
        now = int(time.time())

        def operation(db: sqlite3.Connection) -> int:
            row = db.execute(
                "SELECT amount, state, approval_ref FROM withdrawals WHERE id=?",
                (withdrawal_id,),
            ).fetchone()
            if row is None:
                raise WithdrawalStateError(
                    f"withdrawal {withdrawal_id!r} does not exist"
                )
            if row["state"] == "approved" and row["approval_ref"] == approval_ref:
                return int(row["amount"])
            if row["state"] != "pending":
                raise WithdrawalStateError(
                    f"withdrawal {withdrawal_id!r} is {row['state']} and cannot approve"
                )
            db.execute(
                "UPDATE withdrawals SET state='approved', approval_ref=?, "
                "approval_ts=?, updated_ts=? WHERE id=?",
                (approval_ref, now, now, withdrawal_id),
            )
            return int(row["amount"])

        return self._tx(operation)

    def withdraw_presence_attempt(self, withdrawal_id: str) -> int:
        """Count one unanswered/declined human approval request."""
        withdrawal_id = _identifier(withdrawal_id, "withdrawal_id")
        now = int(time.time())

        def operation(db: sqlite3.Connection) -> int:
            row = db.execute(
                "SELECT state, presence_attempts FROM withdrawals WHERE id=?",
                (withdrawal_id,),
            ).fetchone()
            if row is None or row["state"] != "pending":
                state = "missing" if row is None else row["state"]
                raise WithdrawalStateError(
                    f"withdrawal {withdrawal_id!r} is {state} and cannot record presence"
                )
            attempts = int(row["presence_attempts"]) + 1
            db.execute(
                "UPDATE withdrawals SET presence_attempts=?, updated_ts=? WHERE id=?",
                (attempts, now, withdrawal_id),
            )
            return attempts

        return self._tx(operation)

    def withdraw_mark_sent(
        self,
        withdrawal_id: str,
        tx_sig: str,
        blockhash: str,
        last_valid_block_height: int,
        tx_wire: str,
    ) -> int:
        """Durably record a signed transaction before it may be broadcast."""
        withdrawal_id = _identifier(withdrawal_id, "withdrawal_id")
        tx_sig = _identifier(tx_sig, "tx_sig")
        blockhash = _identifier(blockhash, "blockhash")
        tx_wire = _identifier(tx_wire, "tx_wire")
        if (
            isinstance(last_valid_block_height, bool)
            or not isinstance(last_valid_block_height, int)
            or last_valid_block_height < 0
            or last_valid_block_height > 2 ** 63 - 1
        ):
            raise LedgerValueError("last_valid_block_height is invalid")
        now = int(time.time())

        def operation(db: sqlite3.Connection) -> int:
            row = db.execute(
                "SELECT state, tx_sig, expiry_count FROM withdrawals WHERE id=?",
                (withdrawal_id,),
            ).fetchone()
            if row is None:
                raise WithdrawalStateError(
                    f"withdrawal {withdrawal_id!r} does not exist"
                )
            if row["state"] == "sent" and row["tx_sig"] == tx_sig:
                return int(row["expiry_count"]) + 1
            if row["state"] not in ("approved", "expired"):
                raise WithdrawalStateError(
                    f"withdrawal {withdrawal_id!r} is {row['state']} and cannot send"
                )
            expiry_count = int(row["expiry_count"])
            if expiry_count >= 3:
                raise WithdrawalStateError(
                    f"withdrawal {withdrawal_id!r} exhausted three blockhashes"
                )
            attempt = expiry_count + 1
            try:
                db.execute(
                    "INSERT INTO withdrawal_attempts"
                    "(withdrawal_id, attempt, tx_sig, blockhash, "
                    "last_valid_block_height, tx_wire, state, created_ts, updated_ts) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'sent', ?, ?)",
                    (
                        withdrawal_id,
                        attempt,
                        tx_sig,
                        blockhash,
                        last_valid_block_height,
                        tx_wire,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise WithdrawalStateError("transaction signature was already recorded") from exc
            db.execute(
                "UPDATE withdrawals SET state='sent', tx_sig=?, blockhash=?, "
                "last_valid_block_height=?, tx_wire=?, updated_ts=? WHERE id=?",
                (
                    tx_sig,
                    blockhash,
                    last_valid_block_height,
                    tx_wire,
                    now,
                    withdrawal_id,
                ),
            )
            return attempt

        return self._tx(operation)

    def withdraw_mark_expired(self, withdrawal_id: str) -> int:
        """Mark the current sent attempt unable to land and return expiry count."""
        withdrawal_id = _identifier(withdrawal_id, "withdrawal_id")
        now = int(time.time())

        def operation(db: sqlite3.Connection) -> int:
            row = db.execute(
                "SELECT state, tx_sig, expiry_count FROM withdrawals WHERE id=?",
                (withdrawal_id,),
            ).fetchone()
            if row is None or row["state"] != "sent":
                state = "missing" if row is None else row["state"]
                raise WithdrawalStateError(
                    f"withdrawal {withdrawal_id!r} is {state} and cannot expire"
                )
            expiry_count = int(row["expiry_count"]) + 1
            updated = db.execute(
                "UPDATE withdrawal_attempts SET state='expired', updated_ts=? "
                "WHERE withdrawal_id=? AND tx_sig=? AND state='sent'",
                (now, withdrawal_id, row["tx_sig"]),
            ).rowcount
            if updated != 1:
                raise WithdrawalStateError("current sent attempt is missing")
            db.execute(
                "UPDATE withdrawals SET state='expired', expiry_count=?, updated_ts=? "
                "WHERE id=?",
                (expiry_count, now, withdrawal_id),
            )
            return expiry_count

        return self._tx(operation)

    def withdraw_finalize(self, withdrawal_id: str) -> int:
        """Finalize an active hold by moving it to the treasury."""
        withdrawal_id = _identifier(withdrawal_id, "withdrawal_id")
        now = int(time.time())
        hold_account = self._withdrawal_hold_account(withdrawal_id)

        def operation(db: sqlite3.Connection) -> int:
            row = db.execute(
                "SELECT operator, amount, address, state, tx_sig FROM withdrawals WHERE id=?",
                (withdrawal_id,),
            ).fetchone()
            if row is None:
                raise WithdrawalStateError(
                    f"withdrawal {withdrawal_id!r} does not exist"
                )
            amount = int(row["amount"])
            if row["state"] != "sent":
                raise WithdrawalStateError(
                    f"withdrawal {withdrawal_id!r} is {row['state']} and cannot finalize"
                )
            if self._balance_in(db, hold_account) != amount:
                raise LedgerError(f"withdrawal {withdrawal_id!r} hold balance is inconsistent")
            treasury_new = self._checked_balance(
                self._balance_in(db, TREASURY_ACCOUNT) + amount,
                TREASURY_ACCOUNT,
            )
            self._ensure_account(db, TREASURY_ACCOUNT, "self")
            db.execute(
                "UPDATE accounts SET tier='self' WHERE id=?", (TREASURY_ACCOUNT,)
            )
            self._set_balance(db, hold_account, 0)
            self._set_balance(db, TREASURY_ACCOUNT, treasury_new)
            db.execute(
                "UPDATE withdrawals SET state='finalized', updated_ts=? WHERE id=?",
                (now, withdrawal_id),
            )
            db.execute(
                "UPDATE withdrawal_attempts SET state='finalized', updated_ts=? "
                "WHERE withdrawal_id=? AND tx_sig=? AND state='sent'",
                (now, withdrawal_id, row["tx_sig"]),
            )
            detail = json.dumps(
                {
                    "address": row["address"],
                    "rate": RATE,
                    "withdrawal_id": withdrawal_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            db.execute(
                "INSERT INTO journal(ts, kind, account, counterparty, amount, detail) "
                "VALUES (?, 'withdraw', ?, ?, ?, ?)",
                (now, TREASURY_ACCOUNT, row["operator"], amount, detail),
            )
            return amount

        return self._tx(operation)

    def withdraw_release(self, withdrawal_id: str) -> int:
        """Release a non-sent withdrawal hold back to its operator."""
        withdrawal_id = _identifier(withdrawal_id, "withdrawal_id")
        now = int(time.time())
        hold_account = self._withdrawal_hold_account(withdrawal_id)

        def operation(db: sqlite3.Connection) -> int:
            row = db.execute(
                "SELECT operator, amount, address, state FROM withdrawals WHERE id=?",
                (withdrawal_id,),
            ).fetchone()
            if row is None:
                raise WithdrawalStateError(
                    f"withdrawal {withdrawal_id!r} does not exist"
                )
            amount = int(row["amount"])
            if row["state"] not in ("pending", "approved", "expired"):
                raise WithdrawalStateError(
                    f"withdrawal {withdrawal_id!r} is {row['state']} and cannot release"
                )
            if self._balance_in(db, hold_account) != amount:
                raise LedgerError(f"withdrawal {withdrawal_id!r} hold balance is inconsistent")
            operator_new = self._checked_balance(
                self._balance_in(db, row["operator"]) + amount,
                row["operator"],
            )
            self._set_balance(db, hold_account, 0)
            self._set_balance(db, row["operator"], operator_new)
            db.execute(
                "UPDATE withdrawals SET state='released', updated_ts=? WHERE id=?",
                (now, withdrawal_id),
            )
            detail = json.dumps(
                {
                    "address": row["address"],
                    "rate": RATE,
                    "withdrawal_id": withdrawal_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            db.execute(
                "INSERT INTO journal(ts, kind, account, counterparty, amount, detail) "
                "VALUES (?, 'withdraw_release', ?, ?, ?, ?)",
                (now, row["operator"], hold_account, amount, detail),
            )
            return amount

        return self._tx(operation)

    @staticmethod
    def _spend_status_in(
        db: sqlite3.Connection, hold_id: str
    ) -> dict[str, Any]:
        hold = db.execute(
            "SELECT * FROM spend_holds WHERE hold_id=?", (hold_id,)
        ).fetchone()
        if hold is None:
            raise SpendStateError(f"spend hold {hold_id!r} does not exist")
        workers = db.execute(
            "SELECT entry_index, worker_keyid, worker_account_at_authorize, "
            "billable, layer_start, layer_end, layers, price_multiplier, "
            "max_prompt_tokens, max_output_tokens, max_token_layers, max_cost, "
            "state, claim_instance, claimed_at, cumulative_prompt_tokens, "
            "cumulative_generated_tokens, cumulative_token_layers, "
            "cumulative_cost, final, final_receipt_id, finalized_at, updated_at "
            "FROM spend_hold_workers WHERE hold_id=? ORDER BY entry_index",
            (hold_id,),
        ).fetchall()
        result = dict(hold)
        result["release_requested"] = bool(result["release_requested"])
        result["escrow_balance"] = LedgerStore._balance_in(
            db, str(hold["escrow_account"])
        )
        result["workers"] = []
        for row in workers:
            item = dict(row)
            item["billable"] = bool(item["billable"])
            item["final"] = bool(item["final"])
            result["workers"].append(item)
        return result

    @classmethod
    def _finish_spend_hold_if_ready(
        cls, db: sqlite3.Connection, hold_id: str, now: int
    ) -> bool:
        hold = db.execute(
            "SELECT payer_account_at_authorize, escrow_account, state "
            "FROM spend_holds WHERE hold_id=?",
            (hold_id,),
        ).fetchone()
        if hold is None:
            raise SpendStateError(f"spend hold {hold_id!r} does not exist")
        if hold["state"] in {"settled", "expired", "cancelled", "disputed"}:
            return False
        unfinished = db.execute(
            "SELECT 1 FROM spend_hold_workers WHERE hold_id=? "
            "AND state IN ('planned','claimed') LIMIT 1",
            (hold_id,),
        ).fetchone()
        if unfinished is not None:
            return False
        remainder = cls._balance_in(db, str(hold["escrow_account"]))
        cls._move_spend_value(
            db,
            source=str(hold["escrow_account"]),
            destination=str(hold["payer_account_at_authorize"]),
            amount=remainder,
            timestamp=now,
            debit_kind="spend_release_debit",
            credit_kind="spend_release_credit",
            event_id=f"spend-release:{hold_id}:settled",
            detail={"hold_id": hold_id, "reason": "settled"},
        )
        db.execute(
            "UPDATE spend_holds SET state='settled', terminal_at=?, updated_at=? "
            "WHERE hold_id=?",
            (now, now, hold_id),
        )
        cls._assert_spend_hold_in(db, hold_id)
        return True

    @classmethod
    def _advance_spend_hold_in(
        cls, db: sqlite3.Connection, hold_id: str, now: int
    ) -> bool:
        """Apply every deadline transition due at authoritative transaction time."""
        hold = db.execute(
            "SELECT payer_account_at_authorize, escrow_account, state, "
            "execution_deadline, settlement_deadline FROM spend_holds "
            "WHERE hold_id=?",
            (hold_id,),
        ).fetchone()
        if hold is None:
            raise SpendStateError(f"spend hold {hold_id!r} does not exist")
        if hold["state"] in {"settled", "expired", "cancelled", "disputed"}:
            return False

        if now >= int(hold["settlement_deadline"]):
            remainder = cls._balance_in(db, str(hold["escrow_account"]))
            cls._move_spend_value(
                db,
                source=str(hold["escrow_account"]),
                destination=str(hold["payer_account_at_authorize"]),
                amount=remainder,
                timestamp=now,
                debit_kind="spend_release_debit",
                credit_kind="spend_release_credit",
                event_id=f"spend-release:{hold_id}:expired",
                detail={"hold_id": hold_id, "reason": "settlement_deadline"},
            )
            db.execute(
                "UPDATE spend_hold_workers SET state='expired', finalized_at=?, "
                "updated_at=? WHERE hold_id=? AND state IN ('planned','claimed')",
                (now, now, hold_id),
            )
            db.execute(
                "UPDATE spend_holds SET state='expired', terminal_at=?, updated_at=? "
                "WHERE hold_id=?",
                (now, now, hold_id),
            )
            cls._assert_spend_hold_in(db, hold_id)
            return True

        if now < int(hold["execution_deadline"]):
            return False

        planned = int(
            db.execute(
                "SELECT COALESCE(SUM(max_cost - cumulative_cost), 0) "
                "FROM spend_hold_workers WHERE hold_id=? AND state='planned'",
                (hold_id,),
            ).fetchone()[0]
        )
        planned_entry = db.execute(
            "SELECT 1 FROM spend_hold_workers WHERE hold_id=? "
            "AND state='planned' LIMIT 1",
            (hold_id,),
        ).fetchone()
        if planned_entry is None and hold["state"] == "closing":
            return False

        cls._move_spend_value(
            db,
            source=str(hold["escrow_account"]),
            destination=str(hold["payer_account_at_authorize"]),
            amount=planned,
            timestamp=now,
            debit_kind="spend_release_debit",
            credit_kind="spend_release_credit",
            event_id=f"spend-release:{hold_id}:execution-expiry",
            detail={"hold_id": hold_id, "reason": "execution_deadline"},
        )
        db.execute(
            "UPDATE spend_hold_workers SET state='abandoned', finalized_at=?, "
            "updated_at=? WHERE hold_id=? AND state='planned'",
            (now, now, hold_id),
        )
        claimed = db.execute(
            "SELECT 1 FROM spend_hold_workers WHERE hold_id=? "
            "AND state='claimed' LIMIT 1",
            (hold_id,),
        ).fetchone()
        if claimed is not None:
            db.execute(
                "UPDATE spend_holds SET state='closing', updated_at=? WHERE hold_id=?",
                (now, hold_id),
            )
        else:
            any_claim = db.execute(
                "SELECT 1 FROM spend_hold_workers WHERE hold_id=? "
                "AND claimed_at IS NOT NULL LIMIT 1",
                (hold_id,),
            ).fetchone()
            if any_claim is None:
                db.execute(
                    "UPDATE spend_holds SET state='cancelled', terminal_at=?, "
                    "updated_at=? WHERE hold_id=?",
                    (now, now, hold_id),
                )
            else:
                cls._finish_spend_hold_if_ready(db, hold_id, now)
        cls._assert_spend_hold_in(db, hold_id)
        return True

    @staticmethod
    def _spend_lifecycle_expired_in(
        db: sqlite3.Connection, hold_id: str, worker_keyid: str
    ) -> bool:
        """Return whether a worker operation was rejected by a hold deadline."""
        hold = db.execute(
            "SELECT state, execution_deadline, terminal_at, release_requested "
            "FROM spend_holds WHERE hold_id=?",
            (hold_id,),
        ).fetchone()
        if hold is None:
            raise SpendStateError(f"spend hold {hold_id!r} does not exist")
        if hold["state"] == "expired":
            return True
        worker = db.execute(
            "SELECT state, finalized_at FROM spend_hold_workers "
            "WHERE hold_id=? AND worker_keyid=?",
            (hold_id, worker_keyid),
        ).fetchone()
        if worker is None:
            raise SpendStateError("worker is not part of the spend hold")
        if worker["state"] == "expired":
            return True
        finalized_at = worker["finalized_at"]
        if (
            worker["state"] == "abandoned"
            and finalized_at is not None
            and int(finalized_at) >= int(hold["execution_deadline"])
        ):
            return True
        return (
            hold["state"] == "cancelled"
            and not bool(hold["release_requested"])
            and hold["terminal_at"] is not None
            and int(hold["terminal_at"]) >= int(hold["execution_deadline"])
        )

    def eligible_spend_capacity(self, account: str, tier: str) -> int | None:
        """Return N1 paid-hold capacity, or ``None`` for an unlimited tier.

        This is advisory. ``authorize_spend`` recomputes it while holding a
        ``BEGIN IMMEDIATE`` write transaction.
        """
        account = _identifier(account, "account")
        if is_reserved(account):
            raise LedgerValueError("account is reserved")
        tier = _tier(tier)
        with self._lock:
            now = self._now()
            balance = self._balance_in(self._db, account)
            restricted = self._restricted_paid_earnings_in(self._db, account, now)
        limit = TIER_LIMITS[tier]
        if limit is None:
            return None
        return max(0, balance - restricted + limit)

    def authorize_spend(
        self,
        *,
        payer_keyid: str,
        payer_account: str,
        tier: str,
        client_nonce: str,
        session_id: str,
        model_id: str,
        billing_mode: str,
        max_prompt_tokens: int,
        max_output_tokens: int,
        workers: Iterable[Mapping[str, Any]],
        hold_id: str | None = None,
    ) -> dict[str, Any]:
        """Reserve one immutable, worst-case-priced paid execution plan.

        The caller supplies an already authenticated roster snapshot.  N1 has
        no HTTP route and no token claim surface; N3 will bind this primitive
        to its opaque authorization token.
        """
        # Parse only fields covered by the authenticated wire request before
        # looking up its idempotency key.  Roster accounts, tiers, billability,
        # and prices are derived snapshots and must not invalidate a replay.
        payer_keyid = _identifier(payer_keyid, "payer_keyid")
        client_nonce = _identifier(client_nonce, "client_nonce")
        session_id = _identifier(session_id, "session_id")
        model_id = _identifier(model_id, "model_id")
        billing_mode = _identifier(billing_mode, "billing_mode")
        max_prompt_tokens = _nonnegative_integer(
            max_prompt_tokens, "max_prompt_tokens"
        )
        max_output_tokens = _nonnegative_integer(
            max_output_tokens, "max_output_tokens"
        )
        if max_prompt_tokens + max_output_tokens == 0:
            raise LedgerValueError("prompt and output caps cannot both be zero")
        if hold_id is not None:
            hold_id = _identifier(hold_id, "hold_id")
        proposed_hold_id = hold_id or uuid.uuid4().hex

        if isinstance(workers, (str, bytes, Mapping)):
            raise LedgerValueError("workers must be an iterable of mappings")
        try:
            raw_workers = list(workers)
        except TypeError as exc:
            raise LedgerValueError("workers must be an iterable of mappings") from exc
        if not raw_workers:
            raise LedgerValueError("workers must not be empty")

        wire_workers: list[dict[str, Any]] = []
        seen_workers: set[str] = set()
        for index, raw in enumerate(raw_workers):
            if not isinstance(raw, Mapping):
                raise LedgerValueError(f"worker {index} must be a mapping")
            worker_keyid = _identifier(raw.get("worker_keyid"), "worker_keyid")
            if worker_keyid in seen_workers:
                raise LedgerValueError(f"duplicate worker_keyid {worker_keyid!r}")
            seen_workers.add(worker_keyid)
            layer_start = _nonnegative_integer(raw.get("layer_start"), "layer_start")
            layer_end = _nonnegative_integer(raw.get("layer_end"), "layer_end")
            if layer_end <= layer_start:
                raise LedgerValueError("layer_end must be greater than layer_start")
            wire_workers.append(
                {
                    "entry_index": index,
                    "worker_keyid": worker_keyid,
                    "layer_start": layer_start,
                    "layer_end": layer_end,
                }
            )
        request_digest = self._spend_request_digest(
            payer_keyid=payer_keyid,
            client_nonce=client_nonce,
            session_id=session_id,
            model_id=model_id,
            billing_mode=billing_mode,
            max_prompt_tokens=max_prompt_tokens,
            max_output_tokens=max_output_tokens,
            workers=wire_workers,
        )
        escrow_account = self._spend_hold_account(proposed_hold_id)

        def operation(db: sqlite3.Connection) -> dict[str, Any]:
            existing = db.execute(
                "SELECT hold_id, request_digest FROM spend_holds "
                "WHERE payer_keyid=? AND client_nonce=?",
                (payer_keyid, client_nonce),
            ).fetchone()
            if existing is not None:
                if (
                    existing["request_digest"] != request_digest
                    or (hold_id is not None and existing["hold_id"] != hold_id)
                ):
                    raise SpendConflict(
                        "client_nonce already authorizes a different spend plan"
                    )
                now = self._now()
                self._advance_spend_hold_in(db, str(existing["hold_id"]), now)
                self._assert_spend_hold_in(db, str(existing["hold_id"]))
                return self._spend_status_in(db, str(existing["hold_id"]))

            session = db.execute(
                "SELECT hold_id FROM spend_holds "
                "WHERE payer_keyid=? AND session_id=?",
                (payer_keyid, session_id),
            ).fetchone()
            if session is not None:
                raise SpendConflict("session_id already belongs to another authorization")
            if db.execute(
                "SELECT 1 FROM spend_holds WHERE hold_id=?", (proposed_hold_id,)
            ).fetchone():
                raise SpendConflict("hold_id already exists")

            resolved_payer_account = _identifier(payer_account, "payer_account")
            if is_reserved(resolved_payer_account):
                raise LedgerValueError("payer_account is reserved")
            resolved_tier = _tier(tier)
            clean_workers: list[dict[str, Any]] = []
            total_token_layers = 0
            total_cost = 0
            token_cap = max_prompt_tokens + max_output_tokens
            for raw, wire in zip(raw_workers, wire_workers):
                worker_account = raw.get(
                    "worker_account_at_authorize", raw.get("worker_account")
                )
                worker_account = _identifier(worker_account, "worker_account")
                if is_reserved(worker_account):
                    raise LedgerValueError("worker_account is reserved")
                layers = wire["layer_end"] - wire["layer_start"]
                price_multiplier = _amount(
                    raw.get("price_multiplier"), "price_multiplier"
                )
                max_token_layers = _bounded_product(
                    token_cap, layers, name="worker max_token_layers"
                )
                billable = worker_account != resolved_payer_account
                if "billable" in raw and raw["billable"] is not billable:
                    raise LedgerValueError(
                        "billable must match the payer/worker account snapshot policy"
                    )
                max_cost = (
                    _bounded_product(
                        max_token_layers,
                        price_multiplier,
                        name="worker max_cost",
                    )
                    if billable
                    else 0
                )
                total_token_layers += max_token_layers
                total_cost += max_cost
                if total_token_layers > MAX_UNITS or total_cost > MAX_UNITS:
                    raise LedgerValueError("aggregate spend cap exceeds ledger bounds")
                clean_workers.append(
                    {
                        **wire,
                        "worker_account_at_authorize": worker_account,
                        "billable": billable,
                        "layers": layers,
                        "price_multiplier": price_multiplier,
                        "max_token_layers": max_token_layers,
                        "max_cost": max_cost,
                    }
                )

            authorization = {
                "v": 1,
                "payer_keyid": payer_keyid,
                "payer_account_at_authorize": resolved_payer_account,
                "payer_tier_at_authorize": resolved_tier,
                "client_nonce": client_nonce,
                "session_id": session_id,
                "model_id": model_id,
                "billing_mode": billing_mode,
                "max_prompt_tokens": max_prompt_tokens,
                "max_output_tokens": max_output_tokens,
                "workers": clean_workers,
            }
            canonical = json.dumps(
                authorization, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            authorization_digest = (
                "sha256:" + hashlib.sha256(canonical).hexdigest()
            )
            now = self._now()

            balance = self._balance_in(db, resolved_payer_account)
            restricted = self._restricted_paid_earnings_in(
                db, resolved_payer_account, now
            )
            limit = TIER_LIMITS[resolved_tier]
            if limit is not None and total_cost > balance - restricted + limit:
                raise CreditLimitError(
                    f"authorization exceeds eligible capacity "
                    f"{max(0, balance - restricted + limit)}: {total_cost}"
                )
            self._checked_balance(balance - total_cost, resolved_payer_account)
            self._checked_balance(
                self._balance_in(db, escrow_account) + total_cost, escrow_account
            )
            execution_deadline = now + SPEND_EXECUTION_S
            settlement_deadline = execution_deadline + SPEND_SETTLEMENT_GRACE_S
            db.execute(
                "INSERT INTO spend_holds(hold_id, payer_keyid, "
                "payer_account_at_authorize, payer_tier_at_authorize, client_nonce, "
                "session_id, model_id, billing_mode, max_prompt_tokens, "
                "max_output_tokens, max_token_layers, max_cost, "
                "authorization_digest, request_digest, escrow_account, state, authorized_at, "
                "execution_deadline, settlement_deadline, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)",
                (
                    proposed_hold_id,
                    payer_keyid,
                    resolved_payer_account,
                    resolved_tier,
                    client_nonce,
                    session_id,
                    model_id,
                    billing_mode,
                    max_prompt_tokens,
                    max_output_tokens,
                    total_token_layers,
                    total_cost,
                    authorization_digest,
                    request_digest,
                    escrow_account,
                    now,
                    execution_deadline,
                    settlement_deadline,
                    now,
                ),
            )
            for worker in clean_workers:
                db.execute(
                    "INSERT INTO spend_hold_workers(hold_id, entry_index, "
                    "worker_keyid, worker_account_at_authorize, billable, "
                    "layer_start, layer_end, layers, price_multiplier, "
                    "max_prompt_tokens, max_output_tokens, max_token_layers, "
                    "max_cost, state, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', ?)",
                    (
                        proposed_hold_id,
                        worker["entry_index"],
                        worker["worker_keyid"],
                        worker["worker_account_at_authorize"],
                        int(worker["billable"]),
                        worker["layer_start"],
                        worker["layer_end"],
                        worker["layers"],
                        worker["price_multiplier"],
                        max_prompt_tokens,
                        max_output_tokens,
                        worker["max_token_layers"],
                        worker["max_cost"],
                        now,
                    ),
                )
            self._ensure_account(db, resolved_payer_account, resolved_tier)
            self._ensure_account(db, escrow_account, "self")
            self._move_spend_value(
                db,
                source=resolved_payer_account,
                destination=escrow_account,
                amount=total_cost,
                timestamp=now,
                debit_kind="spend_authorize_debit",
                credit_kind="spend_authorize_credit",
                event_id=f"spend-authorize:{proposed_hold_id}",
                detail={"hold_id": proposed_hold_id},
            )
            db.execute(
                "UPDATE accounts SET tier=? WHERE id=?",
                (resolved_tier, resolved_payer_account),
            )
            db.execute(
                "UPDATE accounts SET tier='self' WHERE id=?", (escrow_account,)
            )
            self._assert_spend_hold_in(db, proposed_hold_id)
            return self._spend_status_in(db, proposed_hold_id)

        return self._tx(operation)

    def claim_spend_worker(
        self, hold_id: str, worker_keyid: str, claim_instance: str
    ) -> dict[str, Any]:
        """Claim one planned entry by stable instance (internal N1 primitive)."""
        hold_id = _identifier(hold_id, "hold_id")
        worker_keyid = _identifier(worker_keyid, "worker_keyid")
        claim_instance = _identifier(claim_instance, "claim_instance")

        def operation(db: sqlite3.Connection) -> dict[str, Any] | SpendExpired:
            now = self._now()
            self._advance_spend_hold_in(db, hold_id, now)
            hold = db.execute(
                "SELECT state, execution_deadline FROM spend_holds WHERE hold_id=?",
                (hold_id,),
            ).fetchone()
            if hold is None:
                raise SpendStateError(f"spend hold {hold_id!r} does not exist")
            entry = db.execute(
                "SELECT state, claim_instance FROM spend_hold_workers "
                "WHERE hold_id=? AND worker_keyid=?",
                (hold_id, worker_keyid),
            ).fetchone()
            if entry is None:
                raise SpendStateError("worker is not part of the spend hold")
            if self._spend_lifecycle_expired_in(db, hold_id, worker_keyid):
                return SpendExpired("spend hold deadline has expired")
            if entry["claim_instance"] is not None:
                if entry["claim_instance"] != claim_instance:
                    raise SpendConflict("worker entry was claimed by another instance")
                return self._spend_status_in(db, hold_id)
            if hold["state"] != "open":
                raise SpendStateError(f"spend hold is {hold['state']}")
            if now >= int(hold["execution_deadline"]):
                raise SpendStateError("spend execution deadline has passed")
            if entry["state"] != "planned":
                raise SpendStateError(f"worker entry is {entry['state']}")
            db.execute(
                "UPDATE spend_hold_workers SET state='claimed', claim_instance=?, "
                "claimed_at=?, updated_at=? WHERE hold_id=? AND worker_keyid=?",
                (claim_instance, now, now, hold_id, worker_keyid),
            )
            self._assert_spend_hold_in(db, hold_id)
            return self._spend_status_in(db, hold_id)

        result = self._tx(operation)
        if isinstance(result, SpendExpired):
            raise result
        return result

    def settle_spend_usage(
        self,
        hold_id: str,
        worker_keyid: str,
        cumulative_prompt_tokens: int,
        cumulative_generated_tokens: int,
        *,
        final: bool = False,
        final_receipt_id: str | None = None,
    ) -> dict[str, Any]:
        """Price cumulative usage and atomically move only its new delta.

        N2 will put strict signed receipt validation and sequence handling in
        front of this accounting transition.  N1 intentionally accepts only
        already-resolved hold and worker identities.
        """
        hold_id = _identifier(hold_id, "hold_id")
        worker_keyid = _identifier(worker_keyid, "worker_keyid")
        cumulative_prompt_tokens = _nonnegative_integer(
            cumulative_prompt_tokens, "cumulative_prompt_tokens"
        )
        cumulative_generated_tokens = _nonnegative_integer(
            cumulative_generated_tokens, "cumulative_generated_tokens"
        )
        if not isinstance(final, bool):
            raise LedgerValueError("final must be a boolean")
        if final_receipt_id is not None:
            final_receipt_id = _identifier(final_receipt_id, "final_receipt_id")
        if not final and final_receipt_id is not None:
            raise LedgerValueError("final_receipt_id requires final=true")

        def operation(db: sqlite3.Connection) -> dict[str, Any] | SpendExpired:
            now = self._now()
            self._advance_spend_hold_in(db, hold_id, now)
            hold = db.execute(
                "SELECT payer_account_at_authorize, escrow_account, state, "
                "settlement_deadline FROM spend_holds WHERE hold_id=?",
                (hold_id,),
            ).fetchone()
            if hold is None:
                raise SpendStateError(f"spend hold {hold_id!r} does not exist")
            entry = db.execute(
                "SELECT * FROM spend_hold_workers WHERE hold_id=? AND worker_keyid=?",
                (hold_id, worker_keyid),
            ).fetchone()
            if entry is None:
                raise SpendStateError("worker is not part of the spend hold")
            if self._spend_lifecycle_expired_in(db, hold_id, worker_keyid):
                return SpendExpired("spend hold deadline has expired")
            if entry["state"] == "final":
                same = (
                    int(entry["cumulative_prompt_tokens"])
                    == cumulative_prompt_tokens
                    and int(entry["cumulative_generated_tokens"])
                    == cumulative_generated_tokens
                    and final
                    and entry["final_receipt_id"] == final_receipt_id
                )
                if same:
                    result = self._spend_status_in(db, hold_id)
                    result["accepted_delta"] = 0
                    return result
                raise SpendStateError("worker entry is already final")
            if hold["state"] not in {"open", "closing"}:
                raise SpendStateError(f"spend hold is {hold['state']}")
            if now >= int(hold["settlement_deadline"]):
                raise SpendStateError("spend settlement deadline has passed")
            if entry["state"] != "claimed":
                raise SpendStateError(f"worker entry is {entry['state']}")
            old_prompt = int(entry["cumulative_prompt_tokens"])
            old_generated = int(entry["cumulative_generated_tokens"])
            if old_prompt and cumulative_prompt_tokens != old_prompt:
                raise SpendConflict("prompt token count is immutable after first usage")
            if cumulative_prompt_tokens < old_prompt:
                raise SpendConflict("prompt token count regressed")
            if cumulative_generated_tokens < old_generated:
                raise SpendConflict("generated token count regressed")
            if cumulative_prompt_tokens > int(entry["max_prompt_tokens"]):
                raise CreditLimitError("prompt token cap exceeded")
            if cumulative_generated_tokens > int(entry["max_output_tokens"]):
                raise CreditLimitError("output token cap exceeded")
            cumulative_token_layers = _bounded_product(
                cumulative_prompt_tokens + cumulative_generated_tokens,
                int(entry["layers"]),
                name="cumulative_token_layers",
            )
            cumulative_cost = (
                _bounded_product(
                    cumulative_token_layers,
                    int(entry["price_multiplier"]),
                    name="cumulative_cost",
                )
                if bool(entry["billable"])
                else 0
            )
            if cumulative_token_layers > int(entry["max_token_layers"]):
                raise CreditLimitError("token-layer cap exceeded")
            if cumulative_cost > int(entry["max_cost"]):
                raise CreditLimitError("entry cost cap exceeded")
            old_cost = int(entry["cumulative_cost"])
            if cumulative_cost < old_cost:
                raise SpendConflict("cumulative cost regressed")
            delta = cumulative_cost - old_cost
            worker_account = str(entry["worker_account_at_authorize"])
            if delta:
                if self._balance_in(db, str(hold["escrow_account"])) < delta:
                    raise LedgerError("spend hold is undercollateralized")
                self._move_spend_value(
                    db,
                    source=str(hold["escrow_account"]),
                    destination=worker_account,
                    amount=delta,
                    timestamp=now,
                    debit_kind="spend_settle_debit",
                    credit_kind="spend_earn",
                    event_id=(
                        f"spend-settle:{hold_id}:{worker_keyid}:"
                        f"{cumulative_prompt_tokens}:{cumulative_generated_tokens}"
                    ),
                    detail={
                        "hold_id": hold_id,
                        "worker_keyid": worker_keyid,
                        "prompt_tokens": cumulative_prompt_tokens,
                        "generated_tokens": cumulative_generated_tokens,
                        "token_layers": cumulative_token_layers,
                        "cumulative_cost": cumulative_cost,
                    },
                )
            state = "final" if final else "claimed"
            db.execute(
                "UPDATE spend_hold_workers SET state=?, "
                "cumulative_prompt_tokens=?, cumulative_generated_tokens=?, "
                "cumulative_token_layers=?, cumulative_cost=?, final=?, "
                "final_receipt_id=?, finalized_at=?, updated_at=? "
                "WHERE hold_id=? AND worker_keyid=?",
                (
                    state,
                    cumulative_prompt_tokens,
                    cumulative_generated_tokens,
                    cumulative_token_layers,
                    cumulative_cost,
                    int(final),
                    final_receipt_id,
                    now if final else None,
                    now,
                    hold_id,
                    worker_keyid,
                ),
            )
            self._finish_spend_hold_if_ready(db, hold_id, now)
            self._assert_spend_hold_in(db, hold_id)
            result = self._spend_status_in(db, hold_id)
            result["accepted_delta"] = delta
            return result

        result = self._tx(operation)
        if isinstance(result, SpendExpired):
            raise result
        return result

    def abandon_spend_worker(
        self, hold_id: str, worker_keyid: str, payer_keyid: str
    ) -> dict[str, Any]:
        """Mark one unclaimed entry unused and return its cap to the payer."""
        hold_id = _identifier(hold_id, "hold_id")
        worker_keyid = _identifier(worker_keyid, "worker_keyid")
        payer_keyid = _identifier(payer_keyid, "payer_keyid")

        def operation(db: sqlite3.Connection) -> dict[str, Any] | SpendExpired:
            now = self._now()
            self._advance_spend_hold_in(db, hold_id, now)
            hold = db.execute(
                "SELECT payer_keyid, payer_account_at_authorize, escrow_account, state "
                "FROM spend_holds WHERE hold_id=?",
                (hold_id,),
            ).fetchone()
            if hold is None:
                raise SpendStateError(f"spend hold {hold_id!r} does not exist")
            if hold["payer_keyid"] != payer_keyid:
                raise SpendStateError("payer does not own the spend hold")
            entry = db.execute(
                "SELECT state, max_cost, cumulative_cost FROM spend_hold_workers "
                "WHERE hold_id=? AND worker_keyid=?",
                (hold_id, worker_keyid),
            ).fetchone()
            if entry is None:
                raise SpendStateError("worker is not part of the spend hold")
            if self._spend_lifecycle_expired_in(db, hold_id, worker_keyid):
                return SpendExpired("spend hold deadline has expired")
            if entry["state"] == "abandoned":
                return self._spend_status_in(db, hold_id)
            if hold["state"] not in {"open", "closing"}:
                raise SpendStateError(f"spend hold is {hold['state']}")
            if entry["state"] != "planned":
                raise SpendStateError("only an unclaimed worker entry may be abandoned")
            remainder = int(entry["max_cost"]) - int(entry["cumulative_cost"])
            self._move_spend_value(
                db,
                source=str(hold["escrow_account"]),
                destination=str(hold["payer_account_at_authorize"]),
                amount=remainder,
                timestamp=now,
                debit_kind="spend_release_debit",
                credit_kind="spend_release_credit",
                event_id=f"spend-release:{hold_id}:{worker_keyid}:abandoned",
                detail={
                    "hold_id": hold_id,
                    "worker_keyid": worker_keyid,
                    "reason": "abandoned",
                },
            )
            db.execute(
                "UPDATE spend_hold_workers SET state='abandoned', finalized_at=?, "
                "updated_at=? WHERE hold_id=? AND worker_keyid=?",
                (now, now, hold_id, worker_keyid),
            )
            self._finish_spend_hold_if_ready(db, hold_id, now)
            self._assert_spend_hold_in(db, hold_id)
            return self._spend_status_in(db, hold_id)

        result = self._tx(operation)
        if isinstance(result, SpendExpired):
            raise result
        return result

    def request_spend_release(
        self, hold_id: str, payer_keyid: str
    ) -> dict[str, Any]:
        """Cancel a wholly unclaimed hold, otherwise record a release request."""
        hold_id = _identifier(hold_id, "hold_id")
        payer_keyid = _identifier(payer_keyid, "payer_keyid")

        def operation(db: sqlite3.Connection) -> dict[str, Any]:
            now = self._now()
            self._advance_spend_hold_in(db, hold_id, now)
            hold = db.execute(
                "SELECT payer_keyid, payer_account_at_authorize, escrow_account, state, "
                "release_requested FROM spend_holds WHERE hold_id=?",
                (hold_id,),
            ).fetchone()
            if hold is None:
                raise SpendStateError(f"spend hold {hold_id!r} does not exist")
            if hold["payer_keyid"] != payer_keyid:
                raise SpendStateError("payer does not own the spend hold")
            if hold["state"] in {"settled", "expired", "cancelled", "disputed"}:
                return self._spend_status_in(db, hold_id)
            claimed = db.execute(
                "SELECT 1 FROM spend_hold_workers WHERE hold_id=? "
                "AND claimed_at IS NOT NULL LIMIT 1",
                (hold_id,),
            ).fetchone()
            if claimed is not None:
                db.execute(
                    "UPDATE spend_holds SET release_requested=1, updated_at=? "
                    "WHERE hold_id=?",
                    (now, hold_id),
                )
                self._assert_spend_hold_in(db, hold_id)
                return self._spend_status_in(db, hold_id)

            remainder = self._balance_in(db, str(hold["escrow_account"]))
            self._move_spend_value(
                db,
                source=str(hold["escrow_account"]),
                destination=str(hold["payer_account_at_authorize"]),
                amount=remainder,
                timestamp=now,
                debit_kind="spend_release_debit",
                credit_kind="spend_release_credit",
                event_id=f"spend-release:{hold_id}:cancelled",
                detail={"hold_id": hold_id, "reason": "cancelled"},
            )
            db.execute(
                "UPDATE spend_hold_workers SET state='abandoned', finalized_at=?, "
                "updated_at=? WHERE hold_id=? AND state='planned'",
                (now, now, hold_id),
            )
            db.execute(
                "UPDATE spend_holds SET state='cancelled', release_requested=1, "
                "terminal_at=?, updated_at=? WHERE hold_id=?",
                (now, now, hold_id),
            )
            self._assert_spend_hold_in(db, hold_id)
            return self._spend_status_in(db, hold_id)

        return self._tx(operation)

    def spend_status(self, hold_id: str) -> dict[str, Any]:
        hold_id = _identifier(hold_id, "hold_id")
        with self._lock:
            return self._spend_status_in(self._db, hold_id)

    def expire_spend_holds_batch(
        self,
        batch_size: int = SPEND_EXPIRY_BATCH_SIZE,
        *,
        cutoff: int | None = None,
    ) -> SpendExpiryBatch:
        """Advance one bounded, ordered batch at a fixed cutoff."""
        if (
            isinstance(batch_size, bool)
            or not isinstance(batch_size, int)
            or batch_size < 1
        ):
            raise LedgerValueError("batch_size must be a positive integer")
        if batch_size > SPEND_EXPIRY_BATCH_SIZE:
            raise LedgerValueError(
                f"batch_size must not exceed {SPEND_EXPIRY_BATCH_SIZE}"
            )
        if cutoff is not None:
            cutoff = _nonnegative_integer(cutoff, "cutoff")

        def operation(db: sqlite3.Connection) -> SpendExpiryBatch:
            sweep_cutoff = self._now() if cutoff is None else cutoff
            rows = db.execute(
                "SELECT hold_id FROM spend_holds "
                "WHERE (state='open' AND execution_deadline<=?) "
                "OR (state='closing' AND settlement_deadline<=?) "
                "ORDER BY CASE state WHEN 'open' THEN execution_deadline "
                "ELSE settlement_deadline END, authorized_at, hold_id LIMIT ?",
                (sweep_cutoff, sweep_cutoff, batch_size + 1),
            ).fetchall()
            affected: list[str] = []
            for hold in rows[:batch_size]:
                hold_id = str(hold["hold_id"])
                if self._advance_spend_hold_in(db, hold_id, sweep_cutoff):
                    affected.append(hold_id)
            return SpendExpiryBatch(
                affected=tuple(affected),
                remaining=len(rows) > batch_size,
                cutoff=sweep_cutoff,
            )

        return self._tx(operation)

    def expire_spend_holds(
        self, batch_size: int = SPEND_EXPIRY_BATCH_SIZE
    ) -> list[str]:
        """Sweep every due hold, committing and yielding between batches."""
        affected: list[str] = []
        cutoff: int | None = None
        while True:
            batch = self.expire_spend_holds_batch(batch_size, cutoff=cutoff)
            cutoff = batch.cutoff
            affected.extend(batch.affected)
            if not batch.remaining:
                return affected
            # Give a writer already waiting on SQLite's lock a scheduling
            # point before the next bounded BEGIN IMMEDIATE.
            time.sleep(0)

    def transfer(self, src: str, dst: str, amount: int, tier: str) -> int:
        """Move units atomically, allowing debt only within ``src``'s tier."""
        src = _identifier(src, "src")
        dst = _identifier(dst, "dst")
        if is_reserved(src) or is_reserved(dst):
            raise LedgerValueError("cannot transfer to or from a reserved account")
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
        if is_reserved(account):
            raise LedgerValueError("account is reserved")
        with self._lock:
            return self._balance_in(self._db, account)

    def history(self, account: str, limit: int = 50) -> list[dict[str, Any]]:
        account = _identifier(account, "account")
        if is_reserved(account):
            raise LedgerValueError("account is reserved")
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
        if is_reserved(account):
            raise LedgerValueError("legacy account is reserved")
        balances[account] = _stored_integer(value, f"legacy balance for {account}")
    if sum(balances.values()) != 0:
        raise LedgerValueError("legacy balances must sum to zero")

    receipts: list[tuple[str, str, str, int, int]] = []
    for receipt_id, raw in raw_settled.items():
        receipt_id = _identifier(receipt_id, "legacy receipt id")
        if not isinstance(raw, dict):
            raise LedgerValueError(f"legacy receipt {receipt_id!r} must be a dict")
        requester = _identifier(raw.get("requester"), "legacy requester")
        if is_reserved(requester):
            raise LedgerValueError("legacy requester is reserved")
        charged = _stored_integer(raw.get("debited"), "legacy debited")
        if charged < 0:
            raise LedgerValueError("legacy debited must not be negative")
        raw_credited = raw.get("credited", {})
        if not isinstance(raw_credited, dict):
            raise LedgerValueError("legacy credited must be a dict")
        credited: dict[str, int] = {}
        for account, amount in raw_credited.items():
            account = _identifier(account, "legacy credited account")
            if is_reserved(account):
                raise LedgerValueError("legacy credited account is reserved")
            credited[account] = _amount(amount, f"legacy credit for {account}")
        if sum(credited.values()) != charged:
            raise LedgerValueError(
                f"legacy receipt {receipt_id!r} credited amounts must sum to debited"
            )
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
    "RATE",
    "HOLD_S",
    "SPEND_EXECUTION_S",
    "SPEND_SETTLEMENT_GRACE_S",
    "SPEND_EXPIRY_BATCH_SIZE",
    "TREASURY_ACCOUNT",
    "TIER_LIMITS",
    "is_reserved",
    "LedgerError",
    "LedgerInvariantError",
    "LedgerValueError",
    "CreditLimitError",
    "ReceiptStateError",
    "DepositConflict",
    "DepositBalanceMismatch",
    "WithdrawalStateError",
    "SpendConflict",
    "SpendStateError",
    "SpendExpired",
    "SpendExpiryBatch",
    "LedgerStore",
    "import_legacy_snapshot",
]
