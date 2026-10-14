"""Finalized Solana deposit indexer for the Neuron ledger.

The process is read-only on Solana: it has no private-key or transaction APIs.
It discovers ordinary SPL transfers into known per-operator token accounts and
credits them exactly once through an account-scoped, reconciled ledger batch.

Unless ``NAK_SOLANA_RPC_CONFIRM`` is configured, the primary RPC is a trust
root for minting ledger credit: an endpoint that fabricates both transaction
history and balances consistently can cause false credit.  With a confirm RPC,
every candidate transaction and account balance must agree before commit.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

if __package__ in {None, ""}:  # Permit the systemd unit to execute this file directly.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from chain.solana_rpc import (
        MAINNET_BETA_GENESIS_HASH,
        RPCError,
        SolanaRPC,
        validate_pubkey,
    )
else:
    from .solana_rpc import (
        MAINNET_BETA_GENESIS_HASH,
        RPCError,
        SolanaRPC,
        validate_pubkey,
    )

from core.ledger_store import (
    RATE,
    DepositBalanceMismatch,
    LedgerError,
    LedgerStore,
)


LOG = logging.getLogger("nak-indexer")
USDC_DECIMALS = 6
DEFAULT_STORE = "~/.neuron/credits/ledger.sqlite"
DEFAULT_INTERVAL_S = 15.0
TOKEN_PROGRAM = "spl-token"
TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
DEVNET_GENESIS_HASH = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
MAINNET_GENESIS_HASH = MAINNET_BETA_GENESIS_HASH


class RPCBudgetExceeded(RuntimeError):
    """One polling pass reached its configured RPC-call ceiling."""


class BacklogTooLarge(RuntimeError):
    """A safe cursor cannot be advanced within the pagination ceiling."""


class RPCDisagreement(RuntimeError):
    """The primary and confirmation RPCs returned different durable data."""


def _is_loopback_rpc(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_rpc_url(url: str, *, cluster: str, name: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{name} must be an http(s) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError(f"{name} must not contain credentials or a fragment")
    loopback = _is_loopback_rpc(url)
    if cluster == "localnet" and not loopback:
        raise ValueError(f"{name} for localnet must use a loopback host")
    if not loopback and parsed.scheme != "https":
        raise ValueError(f"non-loopback {name} must use https")


@dataclass(frozen=True)
class IndexerConfig:
    cluster: str
    mint: str
    rpc_url: str
    confirm_rpc_url: str | None = None
    devnet_genesis: str = DEVNET_GENESIS_HASH
    page_size: int = 1000
    max_pages_per_account: int = 10
    max_rpc_calls_per_poll: int = 200

    def __post_init__(self) -> None:
        if self.cluster not in {"devnet", "localnet"}:
            raise ValueError(
                "NAK_SOLANA_CLUSTER must be devnet or localnet; mainnet-beta is refused in v1"
            )
        _validate_rpc_url(
            self.rpc_url, cluster=self.cluster, name="NAK_SOLANA_RPC"
        )
        if self.confirm_rpc_url is not None:
            _validate_rpc_url(
                self.confirm_rpc_url,
                cluster=self.cluster,
                name="NAK_SOLANA_RPC_CONFIRM",
            )
            if self.confirm_rpc_url.rstrip("/") == self.rpc_url.rstrip("/"):
                raise ValueError("NAK_SOLANA_RPC_CONFIRM must be a different endpoint")
        validate_pubkey(self.mint, "NAK_USDC_MINT")
        validate_pubkey(self.devnet_genesis, "NAK_SOLANA_DEVNET_GENESIS")
        if not 1 <= self.page_size <= 1000:
            raise ValueError("page_size must be between 1 and 1000")
        if self.max_pages_per_account < 1:
            raise ValueError("max_pages_per_account must be positive")
        if self.max_rpc_calls_per_poll < 1:
            raise ValueError("max_rpc_calls_per_poll must be positive")

    @classmethod
    def from_env(cls) -> "IndexerConfig":
        missing = [
            name
            for name in ("NAK_SOLANA_CLUSTER", "NAK_USDC_MINT", "NAK_SOLANA_RPC")
            if not os.environ.get(name)
        ]
        if missing:
            raise ValueError(f"missing required environment: {', '.join(missing)}")
        return cls(
            cluster=os.environ["NAK_SOLANA_CLUSTER"],
            mint=os.environ["NAK_USDC_MINT"],
            rpc_url=os.environ["NAK_SOLANA_RPC"],
            confirm_rpc_url=os.environ.get("NAK_SOLANA_RPC_CONFIRM") or None,
            devnet_genesis=os.environ.get(
                "NAK_SOLANA_DEVNET_GENESIS", DEVNET_GENESIS_HASH
            ),
            max_pages_per_account=int(os.environ.get("NAK_INDEXER_MAX_PAGES", "10")),
            max_rpc_calls_per_poll=int(os.environ.get("NAK_INDEXER_RPC_BUDGET", "200")),
        )


@dataclass(frozen=True)
class DepositAccount:
    operator: str
    token_account: str
    cursor: str | None
    paused: bool


def _flatten_instructions(transaction: dict[str, Any]) -> Iterable[tuple[int, dict[str, Any]]]:
    """Yield outer instructions and their inner instructions in execution order."""
    try:
        outer = transaction["transaction"]["message"]["instructions"]
        inner_groups = transaction.get("meta", {}).get("innerInstructions") or []
    except (KeyError, TypeError):
        return
    by_outer: dict[int, list[dict[str, Any]]] = {}
    for group in inner_groups:
        try:
            by_outer.setdefault(int(group["index"]), []).extend(group["instructions"])
        except (KeyError, TypeError, ValueError):
            continue
    flat_index = 0
    for outer_index, instruction in enumerate(outer):
        if isinstance(instruction, dict):
            yield flat_index, instruction
        flat_index += 1
        for instruction in by_outer.get(outer_index, []):
            if isinstance(instruction, dict):
                yield flat_index, instruction
            flat_index += 1


def _deposit_amount(
    instruction: dict[str, Any], *, destination: str, mint: str
) -> int | None:
    """Return raw micro-USDC for an accepted parsed SPL transfer, else ``None``."""
    if (
        instruction.get("program") != TOKEN_PROGRAM
        or instruction.get("programId") != TOKEN_PROGRAM_ID
    ):
        return None
    parsed = instruction.get("parsed")
    if not isinstance(parsed, dict):
        return None
    kind = parsed.get("type")
    if kind not in {"transfer", "transferChecked"}:
        return None
    info = parsed.get("info")
    if not isinstance(info, dict) or info.get("destination") != destination:
        return None
    if kind == "transferChecked":
        token_amount = info.get("tokenAmount")
        if info.get("mint") != mint or not isinstance(token_amount, dict):
            return None
        if token_amount.get("decimals") != USDC_DECIMALS:
            return None
        raw = token_amount.get("amount")
    else:
        # A successful SPL transfer cannot cross mints. The destination token
        # account is independently verified against the configured mint.
        raw = info.get("amount")
    try:
        amount = int(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    return amount if amount > 0 and str(amount) == str(raw) else None


class DepositIndexer:
    def __init__(
        self,
        store: LedgerStore,
        rpc: Any,
        config: IndexerConfig,
        confirm_rpc: Any | None = None,
    ):
        self.store = store
        self.rpc = rpc
        self.confirm_rpc = confirm_rpc
        self.config = config
        self._rpc_calls = 0
        if (config.confirm_rpc_url is None) != (confirm_rpc is None):
            raise ValueError(
                "confirmation RPC client must be supplied exactly when "
                "NAK_SOLANA_RPC_CONFIRM is configured"
            )
        primary_genesis = self._pin_rpc(
            self.rpc,
            config.devnet_genesis if config.cluster == "devnet" else None,
            "primary",
        )
        if primary_genesis == MAINNET_GENESIS_HASH:
            raise ValueError("mainnet-beta genesis is explicitly refused")
        if config.cluster == "devnet" and primary_genesis != config.devnet_genesis:
            raise ValueError(
                f"primary RPC genesis {primary_genesis} is not configured devnet "
                f"genesis {config.devnet_genesis}"
            )
        self.genesis_hash = primary_genesis
        if self.confirm_rpc is not None:
            confirm_genesis = self._pin_rpc(
                self.confirm_rpc, primary_genesis, "confirmation"
            )
            if confirm_genesis == MAINNET_GENESIS_HASH:
                raise ValueError("mainnet-beta confirmation RPC is explicitly refused")
        self._ensure_state_schema()

    @staticmethod
    def _pin_rpc(rpc: Any, expected: str | None, label: str) -> str:
        try:
            if hasattr(rpc, "pin_genesis"):
                # Read first so mainnet receives an explicit refusal instead
                # of being reported only as a generic expected-hash mismatch.
                actual = rpc.pin_genesis(None)
            else:
                actual = rpc.get_genesis_hash()
        except (RPCError, OSError) as exc:
            raise ValueError(f"could not verify {label} RPC genesis: {exc}") from exc
        if not isinstance(actual, str) or not actual:
            raise ValueError(f"{label} RPC returned an invalid genesis hash")
        if actual == MAINNET_GENESIS_HASH:
            raise ValueError(f"{label} RPC mainnet-beta genesis is explicitly refused")
        if expected is not None and actual != expected:
            raise ValueError(
                f"{label} RPC genesis {actual} does not match expected {expected}"
            )
        return actual

    def _ensure_state_schema(self) -> None:
        def operation(db: sqlite3.Connection) -> None:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_indexer_accounts (
                    token_account TEXT PRIMARY KEY,
                    cursor TEXT,
                    paused INTEGER NOT NULL DEFAULT 0 CHECK(paused IN (0, 1)),
                    updated_ts INTEGER NOT NULL
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_indexer_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    token_account TEXT NOT NULL,
                    operator TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    expected INTEGER,
                    actual INTEGER,
                    detail TEXT NOT NULL
                )
                """
            )

        self.store._tx(operation)

    def _call(self, method: str, *args: Any, **kwargs: Any) -> Any:
        if self._rpc_calls >= self.config.max_rpc_calls_per_poll:
            raise RPCBudgetExceeded(
                f"poll RPC budget {self.config.max_rpc_calls_per_poll} exhausted"
            )
        self._rpc_calls += 1
        return getattr(self.rpc, method)(*args, **kwargs)

    def _accounts(self) -> list[DepositAccount]:
        with self.store._lock:
            now = int(time.time())
            self.store._db.execute(
                "INSERT OR IGNORE INTO chain_indexer_accounts(token_account, updated_ts) "
                "SELECT token_account, ? FROM deposit_accounts",
                (now,),
            )
            rows = self.store._db.execute(
                "SELECT d.operator, d.token_account, s.cursor, s.paused "
                "FROM deposit_accounts AS d JOIN chain_indexer_accounts AS s "
                "ON s.token_account=d.token_account ORDER BY d.operator"
            ).fetchall()
        return [
            DepositAccount(
                operator=row["operator"],
                token_account=row["token_account"],
                cursor=row["cursor"],
                paused=bool(row["paused"]),
            )
            for row in rows
        ]

    def _record_alert(
        self,
        account: DepositAccount,
        *,
        pause: bool,
        kind: str,
        detail: str,
        expected: int | None = None,
        actual: int | None = None,
    ) -> None:
        now = int(time.time())

        def operation(db: sqlite3.Connection) -> None:
            if pause:
                db.execute(
                    "UPDATE chain_indexer_accounts SET paused=1, updated_ts=? "
                    "WHERE token_account=?",
                    (now, account.token_account),
                )
            db.execute(
                "INSERT INTO chain_indexer_alerts"
                "(ts, token_account, operator, kind, expected, actual, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    now,
                    account.token_account,
                    account.operator,
                    kind,
                    expected,
                    actual,
                    detail,
                ),
            )

        self.store._tx(operation)
        record = {
            "event": "chain_indexer_alert",
            "kind": kind,
            "operator": account.operator,
            "token_account": account.token_account,
            "expected": expected,
            "actual": actual,
            "detail": detail,
        }
        LOG.error("%s", json.dumps(record, sort_keys=True, separators=(",", ":")))

    def _pause(
        self,
        account: DepositAccount,
        *,
        kind: str,
        detail: str,
        expected: int | None = None,
        actual: int | None = None,
    ) -> None:
        self._record_alert(
            account,
            pause=True,
            kind=kind,
            detail=detail,
            expected=expected,
            actual=actual,
        )

    def _alert(self, account: DepositAccount, *, kind: str, detail: str) -> None:
        self._record_alert(
            account,
            pause=False,
            kind=kind,
            detail=detail,
        )

    def _signatures(self, account: DepositAccount) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        before = None
        for page_number in range(self.config.max_pages_per_account):
            page = self._call(
                "get_signatures_for_address",
                account.token_account,
                before=before,
                until=account.cursor,
                limit=self.config.page_size,
            )
            records.extend(page)
            if len(page) < self.config.page_size:
                break
            try:
                next_before = page[-1]["signature"]
            except (IndexError, KeyError, TypeError) as exc:
                raise RPCError("signature page has no pagination cursor") from exc
            if next_before == before:
                raise RPCError("signature pagination did not advance")
            before = next_before
            if page_number + 1 == self.config.max_pages_per_account:
                raise BacklogTooLarge(
                    f"{account.token_account} exceeded "
                    f"{self.config.max_pages_per_account} signature pages; cursor unchanged"
                )
        unique: dict[str, dict[str, Any]] = {}
        for record in records:
            signature = record.get("signature") if isinstance(record, dict) else None
            if not isinstance(signature, str) or not signature:
                raise RPCError("signature record is malformed")
            unique.setdefault(signature, record)
        return list(reversed(unique.values()))

    def _validate_snapshot(self, account: DepositAccount) -> dict[str, Any]:
        snapshot = self._call("get_token_account", account.token_account)
        if self.confirm_rpc is not None:
            confirmed = self._call_on(
                self.confirm_rpc, "get_token_account", account.token_account
            )
            comparable = ("mint", "amount", "decimals")
            if any(snapshot.get(key) != confirmed.get(key) for key in comparable):
                raise RPCDisagreement(
                    f"account balance differs between RPCs: primary={snapshot!r} "
                    f"confirmation={confirmed!r}"
                )
        if snapshot["mint"] != self.config.mint:
            raise ValueError(
                f"token account mint {snapshot['mint']} != configured {self.config.mint}"
            )
        if snapshot["decimals"] != USDC_DECIMALS:
            raise ValueError(
                f"configured USDC token account has {snapshot['decimals']} decimals, expected 6"
            )
        if snapshot["amount"] < 0:
            raise ValueError("token account balance is negative")
        return snapshot

    def _call_on(self, rpc: Any, method: str, *args: Any, **kwargs: Any) -> Any:
        if self._rpc_calls >= self.config.max_rpc_calls_per_poll:
            raise RPCBudgetExceeded(
                f"poll RPC budget {self.config.max_rpc_calls_per_poll} exhausted"
            )
        self._rpc_calls += 1
        return getattr(rpc, method)(*args, **kwargs)

    def _transaction(self, signature: str) -> dict[str, Any]:
        transaction = self._call("get_transaction", signature)
        if self.confirm_rpc is not None:
            confirmed = self._call_on(
                self.confirm_rpc, "get_transaction", signature
            )
            if transaction != confirmed:
                raise RPCDisagreement(
                    f"transaction {signature} differs between primary and confirmation RPCs"
                )
        if transaction is None:
            raise RPCError(f"finalized transaction {signature} is temporarily unavailable")
        return transaction

    def poll_account(self, account: DepositAccount) -> int:
        """Index one account and return the number of accepted instructions."""
        if account.paused:
            return 0
        try:
            validate_pubkey(account.token_account, "deposit token account")
            before_snapshot = self._validate_snapshot(account)
        except RPCError:
            raise
        except (ValueError, KeyError, TypeError) as exc:
            self._pause(account, kind="account_config", detail=str(exc))
            return 0

        candidates: list[tuple[str, int, int]] = []
        summaries = self._signatures(account)
        for summary in summaries:
            signature = summary["signature"]
            transaction = self._transaction(signature)
            meta = transaction.get("meta")
            if not isinstance(meta, dict):
                self._alert(
                    account,
                    kind="malformed_transaction",
                    detail=f"transaction {signature} has no meta object",
                )
                continue
            if "err" not in meta:
                self._alert(
                    account,
                    kind="malformed_transaction",
                    detail=f"transaction {signature} meta has no err field",
                )
                continue
            if meta["err"] is None:
                try:
                    slot = int(transaction.get("slot", summary.get("slot")))
                except (TypeError, ValueError, OverflowError) as exc:
                    raise RPCError(f"transaction {signature} has an invalid slot") from exc
                for instruction_index, instruction in _flatten_instructions(transaction):
                    amount = _deposit_amount(
                        instruction,
                        destination=account.token_account,
                        mint=self.config.mint,
                    )
                    if amount is None:
                        continue
                    candidates.append(
                        (f"{signature}:{instruction_index}", amount * RATE, slot)
                    )

        try:
            after_snapshot = self._validate_snapshot(account)
        except (RPCError, RPCDisagreement):
            raise
        except (ValueError, KeyError, TypeError) as exc:
            self._pause(account, kind="account_config", detail=str(exc))
            return 0
        if before_snapshot["amount"] != after_snapshot["amount"]:
            LOG.info(
                "balance changed during poll for %s; reconciliation deferred",
                account.token_account,
            )
            return 0
        cursor = summaries[-1]["signature"] if summaries else None
        try:
            self.store.deposit_batch(
                account.operator,
                account.token_account,
                candidates,
                int(after_snapshot["amount"]) * RATE,
                cursor=cursor,
            )
        except DepositBalanceMismatch as exc:
            self._pause(
                account,
                kind="balance_mismatch",
                detail="on-chain balance does not equal indexed deposits",
                expected=exc.actual // RATE,
                actual=exc.expected // RATE,
            )
            return 0
        except LedgerError as exc:
            self._pause(account, kind="deposit_refused", detail=str(exc))
            return 0
        return len(candidates)

    def poll_once(self) -> int:
        """Poll every active deposit account once within the configured RPC budget."""
        self._rpc_calls = 0
        accepted = 0
        for account in self._accounts():
            if account.paused:
                continue
            try:
                accepted += self.poll_account(account)
            except RPCDisagreement as exc:
                self._pause(
                    account,
                    kind="rpc_disagreement",
                    detail=str(exc),
                )
            except (RPCError, RPCBudgetExceeded, BacklogTooLarge, OSError) as exc:
                LOG.warning(
                    "deposit poll deferred operator=%s account=%s: %s",
                    account.operator,
                    account.token_account,
                    exc,
                )
                if isinstance(exc, RPCBudgetExceeded):
                    break
            except Exception:
                LOG.exception(
                    "deposit poll failed operator=%s account=%s",
                    account.operator,
                    account.token_account,
                )
        return accepted


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", default=DEFAULT_STORE, help="ledger SQLite path")
    parser.add_argument("--once", action="store_true", help="poll once and exit")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_S)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.interval <= 0:
        raise SystemExit("--interval must be positive")
    logging.basicConfig(
        level=os.environ.get("NAK_INDEXER_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        config = IndexerConfig.from_env()
        rpc = SolanaRPC(config.rpc_url)
        confirm_rpc = (
            SolanaRPC(config.confirm_rpc_url) if config.confirm_rpc_url else None
        )
    except ValueError as exc:
        LOG.error("configuration refused: %s", exc)
        return 2
    path = Path(os.path.expanduser(args.store))
    with LedgerStore(path) as store:
        try:
            indexer = DepositIndexer(store, rpc, config, confirm_rpc)
        except ValueError as exc:
            LOG.error("RPC cluster refused: %s", exc)
            return 2
        while True:
            indexer.poll_once()
            if args.once:
                return 0
            time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
