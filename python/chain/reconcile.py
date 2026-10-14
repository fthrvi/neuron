#!/usr/bin/env python3
"""Daily, signed, read-only Solana/ledger reconciliation.

The backing invariant is exactly::

    -balance(treasury) == RATE * sum(finalized treasury-owned micro-USDC)
                          - sum(sent-not-finalized hold amounts)

``sent-not-finalized hold amounts`` are the signed S1 ``withdraw_hold`` journal
amounts, hence they are negative.  S1 makes a deposit debit ``treasury`` and
credit the operator, so ``-balance(treasury)`` is the ledger's outstanding
USDC-backed liability.  S4 moves an approved withdrawal into a positive hold
account without changing ``treasury`` and records the operator-side hold as a
negative journal amount.  Once that transaction is finalized on Solana but S4
has not yet run ``withdraw_finalize``, the finalized token-account total has
already fallen while the treasury liability has not; subtracting that negative
hold adds the in-flight amount back exactly once.  A row merely marked ``sent``
is *not* adjusted until its transaction is proven finalized, because S4 stores
``sent`` before broadcast.  ``withdraw_finalize`` then credits ``treasury`` and
removes the hold, restoring the unadjusted equation.

The other invariants are: all ledger balances sum to zero; deposit credits in
``chain_refs`` equal deposit rows in the append-only journal; and every
finalized withdrawal (all rows, never a sample) has a successful finalized
transaction containing exactly the configured vault-to-recipient transfer.

No balance is ever changed here.  A mismatch writes the payout kill file,
emits a durable alert record, optionally calls Trisul's existing Buzz helper,
and writes a report signed by the hub node's Ed25519 key.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import json
import logging
import os
import sqlite3
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

if __package__ in {None, ""}:  # Permit direct execution by the systemd unit.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from chain.indexer import (  # type: ignore
        DEVNET_GENESIS_HASH,
        MAINNET_GENESIS_HASH,
        TOKEN_PROGRAM,
        TOKEN_PROGRAM_ID,
        USDC_DECIMALS,
        DepositIndexer,
        IndexerConfig,
        _flatten_instructions,
    )
    from chain.solana_rpc import RPCError, SolanaRPC, validate_pubkey  # type: ignore
else:
    from .indexer import (
        DEVNET_GENESIS_HASH,
        MAINNET_GENESIS_HASH,
        TOKEN_PROGRAM,
        TOKEN_PROGRAM_ID,
        USDC_DECIMALS,
        DepositIndexer,
        IndexerConfig,
        _flatten_instructions,
    )
    from .solana_rpc import RPCError, SolanaRPC, validate_pubkey

from core.ledger_store import RATE, TREASURY_ACCOUNT, LedgerStore
from ledger_auth import canonical_string, verify_request


LOG = logging.getLogger("nak-reconcile")
DEFAULT_STORE = "~/.neuron/credits/ledger.sqlite"
DEFAULT_REPORT_DIR = "~/.neuron/credits/reconcile"
DEFAULT_KILL_FILE = "~/.neuron/credits/payout.off"
DEFAULT_SIGNING_KEY = "~/.nakshatra/keys/worker.ed25519"
DEFAULT_BUZZ_HELPER = Path("/home/prithvi/trisul/infra/mesh-agent/buzz-say.sh")
REPORT_METHOD = "REPORT"
REPORT_PATH_PREFIX = "/credits/reconcile/"


class ReconcileError(RuntimeError):
    """The reconciliation proof could not be collected safely."""


def _expanded(value: str) -> Path:
    return Path(os.path.expanduser(value))


@dataclass(frozen=True)
class ReconcileConfig:
    cluster: str
    mint: str
    rpc_url: str
    vault_account: str
    confirm_rpc_url: str | None = None
    devnet_genesis: str = DEVNET_GENESIS_HASH
    report_dir: Path = Path(DEFAULT_REPORT_DIR).expanduser()
    kill_file: Path = Path(DEFAULT_KILL_FILE).expanduser()
    signing_key: Path = Path(DEFAULT_SIGNING_KEY).expanduser()
    buzz_helper: Path | None = DEFAULT_BUZZ_HELPER

    def __post_init__(self) -> None:
        # S3 owns the cluster, URL, independent-confirmation, and mint policy.
        IndexerConfig(
            cluster=self.cluster,
            mint=self.mint,
            rpc_url=self.rpc_url,
            confirm_rpc_url=self.confirm_rpc_url,
            devnet_genesis=self.devnet_genesis,
        )
        validate_pubkey(self.vault_account, "NAK_TREASURY_USDC_ACCOUNT")

    @classmethod
    def from_env(cls) -> "ReconcileConfig":
        required = (
            "NAK_SOLANA_CLUSTER",
            "NAK_USDC_MINT",
            "NAK_SOLANA_RPC",
            "NAK_TREASURY_USDC_ACCOUNT",
        )
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise ValueError(f"missing required environment: {', '.join(missing)}")
        helper = os.environ.get("NAK_RECONCILE_BUZZ_HELPER")
        return cls(
            cluster=os.environ["NAK_SOLANA_CLUSTER"],
            mint=os.environ["NAK_USDC_MINT"],
            rpc_url=os.environ["NAK_SOLANA_RPC"],
            vault_account=os.environ["NAK_TREASURY_USDC_ACCOUNT"],
            confirm_rpc_url=os.environ.get("NAK_SOLANA_RPC_CONFIRM") or None,
            devnet_genesis=os.environ.get(
                "NAK_SOLANA_DEVNET_GENESIS", DEVNET_GENESIS_HASH
            ),
            report_dir=_expanded(
                os.environ.get("NAK_RECONCILE_REPORT_DIR", DEFAULT_REPORT_DIR)
            ),
            kill_file=_expanded(
                os.environ.get("NAK_PAYOUT_KILL_FILE", DEFAULT_KILL_FILE)
            ),
            signing_key=_expanded(
                os.environ.get("NAK_RECONCILE_SIGNING_KEY", DEFAULT_SIGNING_KEY)
            ),
            buzz_helper=_expanded(helper) if helper else DEFAULT_BUZZ_HELPER,
        )


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _load_signing_key(path: Path) -> ed25519.Ed25519PrivateKey:
    """Load a 0600, user-owned, regular 32-byte seed without following links."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReconcileError(f"could not open report signing key {path}: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ReconcileError(f"report signing key is not a regular file: {path}")
        if info.st_uid != os.getuid():
            raise ReconcileError(
                f"report signing key is owned by uid {info.st_uid}, not {os.getuid()}"
            )
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o077:
            raise ReconcileError(
                f"report signing key mode is {mode:04o}, expected no group/other access"
            )
        raw = os.read(fd, 33)
    finally:
        os.close(fd)
    if len(raw) != 32:
        raise ReconcileError("report signing key must be a raw 32-byte Ed25519 seed")
    try:
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:
        raise ReconcileError("report signing key is not a valid Ed25519 seed") from exc


def sign_report(report: dict[str, Any], key_path: Path) -> dict[str, Any]:
    """Return a self-contained envelope using ledger_auth's wire signature contract."""
    private = _load_signing_key(key_path)
    public_hex = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    timestamp = int(report["generated_at_unix"])
    signed_path = f"{REPORT_PATH_PREFIX}{report['date']}"
    body = _canonical_json(report)
    signature = private.sign(canonical_string(REPORT_METHOD, signed_path, body, timestamp))
    return {
        "report": report,
        "signature": {
            "algorithm": "Ed25519",
            "scheme": "Sthambha-Ed25519",
            "keyid": public_hex,
            "method": REPORT_METHOD,
            "path": signed_path,
            "timestamp": timestamp,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_report(envelope: dict[str, Any]) -> bool:
    """Verify an envelope produced by :func:`sign_report`.  Never raises."""
    try:
        report = envelope["report"]
        signature = envelope["signature"]
        body = _canonical_json(report)
        if signature["body_sha256"] != hashlib.sha256(body).hexdigest():
            return False
        if signature["timestamp"] != report["generated_at_unix"]:
            return False
        return verify_request(
            signature["keyid"],
            signature["method"],
            signature["path"],
            body,
            signature["timestamp"],
            signature["value"],
        )
    except (KeyError, TypeError, ValueError):
        return False


def _secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError as exc:
        raise ReconcileError(f"could not secure directory {path}: {exc}") from exc


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    _secure_directory(path.parent)
    payload = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(temporary, flags, 0o600)
        try:
            os.write(fd, payload.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_kill_file(path: Path, alert: dict[str, Any]) -> bool:
    """Create, never replace, the S4 kill switch.  Return whether it was new."""
    _secure_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return False
    try:
        os.write(fd, _canonical_json(alert) + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    return True


def _append_alert(path: Path, alert: dict[str, Any]) -> None:
    _secure_directory(path.parent)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ReconcileError(f"alert log is not a regular file: {path}")
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, _canonical_json(alert) + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)


def _buzz_notify(helper: Path | None, message: str) -> dict[str, Any]:
    if helper is None or not helper.is_file():
        return {"attempted": False, "delivered": False, "detail": "helper unavailable"}
    try:
        result = subprocess.run(
            ["bash", str(helper), message],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "attempted": True,
            "delivered": False,
            "detail": f"{type(exc).__name__}: {exc}",
        }
    detail = "ok" if result.returncode == 0 else (result.stderr.strip()[:300] or "failed")
    return {
        "attempted": True,
        "delivered": result.returncode == 0,
        "detail": detail,
    }


class Reconciler:
    """Collect all four proofs and apply only the fail-closed side effects."""

    def __init__(
        self,
        store: LedgerStore,
        rpc: Any,
        config: ReconcileConfig,
        confirm_rpc: Any | None = None,
        *,
        notify: Callable[[Path | None, str], dict[str, Any]] = _buzz_notify,
        now: Callable[[], float] = time.time,
    ):
        self.store = store
        self.rpc = rpc
        self.confirm_rpc = confirm_rpc
        self.config = config
        self.notify = notify
        self.now = now
        if (config.confirm_rpc_url is None) != (confirm_rpc is None):
            raise ValueError(
                "confirmation RPC client must be supplied exactly when configured"
            )
        expected = config.devnet_genesis if config.cluster == "devnet" else None
        genesis = DepositIndexer._pin_rpc(rpc, expected, "reconcile")
        if genesis == MAINNET_GENESIS_HASH:
            raise ValueError("mainnet-beta genesis is explicitly refused")
        self.genesis_hash = genesis
        if confirm_rpc is not None:
            confirm_genesis = DepositIndexer._pin_rpc(
                confirm_rpc, genesis, "reconcile confirmation"
            )
            if confirm_genesis != genesis:
                raise ValueError("confirmation RPC genesis differs from primary")

    def _account(self, address: str) -> dict[str, Any]:
        primary = self.rpc.get_token_account(address)
        if self.confirm_rpc is not None:
            confirmed = self.confirm_rpc.get_token_account(address)
            comparable = ("mint", "amount", "decimals", "owner")
            if any(primary.get(key) != confirmed.get(key) for key in comparable):
                raise ReconcileError(
                    f"token account {address} differs between primary and confirmation RPCs"
                )
        return primary

    def _status(self, signature: str) -> dict[str, Any] | None:
        primary = self.rpc.get_signature_status(signature)
        if self.confirm_rpc is not None:
            confirmed = self.confirm_rpc.get_signature_status(signature)
            if primary != confirmed:
                raise ReconcileError(
                    f"signature {signature} differs between primary and confirmation RPCs"
                )
        return primary

    def _transaction(self, signature: str) -> dict[str, Any] | None:
        primary = self.rpc.get_transaction(signature)
        if self.confirm_rpc is not None:
            confirmed = self.confirm_rpc.get_transaction(signature)
            if primary != confirmed:
                raise ReconcileError(
                    f"transaction {signature} differs between primary and confirmation RPCs"
                )
        return primary

    def _ledger_snapshot(self) -> dict[str, Any]:
        with self.store._lock:
            db = self.store._db
            treasury = db.execute(
                "SELECT balance FROM accounts WHERE id=?", (TREASURY_ACCOUNT,)
            ).fetchone()
            accounts = [
                dict(row)
                for row in db.execute(
                    "SELECT operator, token_account FROM deposit_accounts "
                    "ORDER BY operator"
                ).fetchall()
            ]
            sent = [
                dict(row)
                for row in db.execute(
                    "SELECT id, operator, amount, address, tx_sig, state "
                    "FROM withdrawals WHERE state='sent' ORDER BY id"
                ).fetchall()
            ]
            finalized = [
                dict(row)
                for row in db.execute(
                    "SELECT id, operator, amount, address, tx_sig, state "
                    "FROM withdrawals WHERE state='finalized' ORDER BY id"
                ).fetchall()
            ]
            hold_rows = [
                dict(row)
                for row in db.execute(
                    "SELECT account, counterparty, amount, detail FROM journal "
                    "WHERE kind='withdraw_hold'"
                ).fetchall()
            ]
            return {
                "treasury_balance": int(treasury[0]) if treasury else 0,
                "balance_sum": int(
                    db.execute(
                        "SELECT COALESCE(SUM(balance), 0) FROM accounts"
                    ).fetchone()[0]
                ),
                "chain_ref_deposits": int(
                    db.execute(
                        "SELECT COALESCE(SUM(amount), 0) FROM chain_refs "
                        "WHERE kind='deposit'"
                    ).fetchone()[0]
                ),
                "journal_deposits": int(
                    db.execute(
                        "SELECT COALESCE(SUM(amount), 0) FROM journal "
                        "WHERE kind='deposit'"
                    ).fetchone()[0]
                ),
                "deposit_accounts": accounts,
                "sent": sent,
                "finalized": finalized,
                "hold_rows": hold_rows,
            }

    @staticmethod
    def _holds_by_withdrawal(rows: list[dict[str, Any]]) -> tuple[dict[str, list[dict]], list[str]]:
        holds: dict[str, list[dict]] = {}
        errors: list[str] = []
        for row in rows:
            try:
                detail = json.loads(row["detail"])
                withdrawal_id = detail["withdrawal_id"]
                if not isinstance(withdrawal_id, str) or not withdrawal_id:
                    raise ValueError("invalid withdrawal_id")
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                errors.append("withdraw_hold journal row has malformed detail")
                continue
            holds.setdefault(withdrawal_id, []).append(row)
        return holds, errors

    def _token_accounts(self, deposit_accounts: list[dict[str, Any]]) -> tuple[list[dict], list[str]]:
        roles: dict[str, dict[str, Any]] = {
            self.config.vault_account: {"roles": ["vault"], "operators": []}
        }
        for row in deposit_accounts:
            entry = roles.setdefault(
                row["token_account"], {"roles": [], "operators": []}
            )
            if "deposit" not in entry["roles"]:
                entry["roles"].append("deposit")
            entry["operators"].append(row["operator"])

        records: list[dict[str, Any]] = []
        errors: list[str] = []
        treasury_owner: str | None = None
        for address in [self.config.vault_account, *sorted(
            item for item in roles if item != self.config.vault_account
        )]:
            record = {"token_account": address, **roles[address]}
            try:
                snapshot = self._account(address)
                record.update(
                    amount_micro_usdc=int(snapshot["amount"]),
                    mint=snapshot.get("mint"),
                    decimals=snapshot.get("decimals"),
                    owner=snapshot.get("owner"),
                    slot=snapshot.get("slot"),
                )
                if snapshot.get("mint") != self.config.mint:
                    errors.append(f"{address}: mint differs from configured USDC mint")
                if snapshot.get("decimals") != USDC_DECIMALS:
                    errors.append(f"{address}: token decimals are not {USDC_DECIMALS}")
                if not isinstance(snapshot.get("owner"), str):
                    errors.append(f"{address}: token authority is absent")
                if address == self.config.vault_account:
                    treasury_owner = snapshot.get("owner")
                elif treasury_owner is not None and snapshot.get("owner") != treasury_owner:
                    errors.append(f"{address}: token account is not treasury-owned")
            except (KeyError, OSError, RPCError, ReconcileError, TypeError, ValueError) as exc:
                record["error"] = f"{type(exc).__name__}: {exc}"
                errors.append(f"{address}: could not read finalized token account")
            records.append(record)
        if treasury_owner is None:
            errors.append("vault token authority could not establish treasury ownership")
        return records, errors

    def _transfer_proof(self, row: dict[str, Any]) -> dict[str, Any]:
        proof: dict[str, Any] = {
            "withdrawal_id": row["id"],
            "tx_sig": row["tx_sig"],
            "amount_credits": int(row["amount"]),
            "recipient": row["address"],
            "ok": False,
        }
        try:
            signature = row["tx_sig"]
            if not isinstance(signature, str) or not signature:
                raise ReconcileError("withdrawal has no transaction signature")
            amount_micro, remainder = divmod(int(row["amount"]), RATE)
            if remainder:
                raise ReconcileError("withdrawal is not an exact micro-USDC amount")
            status = self._status(signature)
            if not isinstance(status, dict):
                raise ReconcileError("transaction has no chain status")
            proof["confirmation_status"] = status.get("confirmationStatus")
            if status.get("confirmationStatus") != "finalized" or status.get("err") is not None:
                raise ReconcileError("transaction is not successfully finalized")
            transaction = self._transaction(signature)
            if not isinstance(transaction, dict):
                raise ReconcileError("finalized transaction body is unavailable")
            meta = transaction.get("meta")
            if not isinstance(meta, dict) or meta.get("err") is not None:
                raise ReconcileError("transaction metadata is absent or failed")

            transfers: list[dict[str, Any]] = []
            for _index, instruction in _flatten_instructions(transaction):
                if (
                    instruction.get("program") != TOKEN_PROGRAM
                    or instruction.get("programId") != TOKEN_PROGRAM_ID
                ):
                    continue
                parsed = instruction.get("parsed")
                if not isinstance(parsed, dict) or parsed.get("type") not in {
                    "transfer", "transferChecked"
                }:
                    continue
                info = parsed.get("info")
                if isinstance(info, dict):
                    transfers.append(info)
            if len(transfers) != 1:
                raise ReconcileError(
                    f"expected exactly one parsed SPL transfer, found {len(transfers)}"
                )
            transfer = transfers[0]
            token_amount = transfer.get("tokenAmount")
            if not isinstance(token_amount, dict):
                raise ReconcileError("payout is not a TransferChecked instruction")
            if (
                transfer.get("source") != self.config.vault_account
                or transfer.get("mint") != self.config.mint
                or token_amount.get("decimals") != USDC_DECIMALS
                or str(token_amount.get("amount")) != str(amount_micro)
            ):
                raise ReconcileError("payout source, mint, decimals, or amount differs")
            destination = transfer.get("destination")
            if not isinstance(destination, str):
                raise ReconcileError("payout destination token account is absent")
            try:
                account_keys = transaction["transaction"]["message"]["accountKeys"]
                resolved_keys = [
                    item.get("pubkey") if isinstance(item, dict) else item
                    for item in account_keys
                ]
                destination_index = resolved_keys.index(destination)
                post_balances = meta["postTokenBalances"]
            except (KeyError, TypeError, ValueError) as exc:
                raise ReconcileError(
                    "transaction cannot resolve the historical payout destination"
                ) from exc
            historical_destination = [
                balance
                for balance in post_balances
                if isinstance(balance, dict)
                and balance.get("accountIndex") == destination_index
                and balance.get("mint") == self.config.mint
                and balance.get("owner") == row["address"]
                and isinstance(balance.get("uiTokenAmount"), dict)
                and balance["uiTokenAmount"].get("decimals") == USDC_DECIMALS
            ]
            if len(historical_destination) != 1:
                raise ReconcileError(
                    "transaction post-balances do not bind destination to recipient"
                )
            proof.update(destination_token_account=destination, ok=True)
        except (KeyError, OSError, RPCError, ReconcileError, TypeError, ValueError) as exc:
            proof["error"] = f"{type(exc).__name__}: {exc}"
        return proof

    def collect(self) -> dict[str, Any]:
        """Collect a proof without writing the report, kill switch, or balances."""
        generated = int(self.now())
        stamp = dt.datetime.fromtimestamp(generated, tz=dt.timezone.utc)
        ledger = self._ledger_snapshot()
        token_accounts, token_errors = self._token_accounts(
            ledger["deposit_accounts"]
        )
        chain_micro = sum(
            int(row.get("amount_micro_usdc", 0)) for row in token_accounts
        )

        holds, hold_errors = self._holds_by_withdrawal(ledger["hold_rows"])
        sent_proofs: list[dict[str, Any]] = []
        sent_signed_adjustment = 0
        for row in ledger["sent"]:
            matching = holds.get(row["id"], [])
            hold_ok = (
                len(matching) == 1
                and int(matching[0]["amount"]) == -int(row["amount"])
                and matching[0]["account"] == row["operator"]
                and matching[0]["counterparty"]
                == self.store._withdrawal_hold_account(row["id"])
            )
            entry: dict[str, Any] = {
                "withdrawal_id": row["id"],
                "tx_sig": row["tx_sig"],
                "amount_credits": int(row["amount"]),
                "hold_journal_ok": hold_ok,
                "signed_hold_amount_credits": (
                    int(matching[0]["amount"]) if hold_ok else None
                ),
                "chain_state": "not_finalized",
                "adjustment_credits": 0,
            }
            if not hold_ok:
                hold_errors.append(f"{row['id']}: sent withdrawal hold is inconsistent")
            try:
                status = self._status(row["tx_sig"])
                if isinstance(status, dict) and status.get("confirmationStatus") == "finalized":
                    if status.get("err") is not None:
                        entry["chain_state"] = "finalized_failed"
                        entry["error"] = "sent withdrawal has a finalized failed transaction"
                        hold_errors.append(f"{row['id']}: finalized transaction failed")
                    else:
                        transfer = self._transfer_proof(row)
                        entry["transfer"] = transfer
                        if transfer["ok"] and hold_ok:
                            entry["chain_state"] = "finalized_pending_ledger"
                            entry["adjustment_credits"] = int(matching[0]["amount"])
                            sent_signed_adjustment += int(matching[0]["amount"])
                        else:
                            hold_errors.append(
                                f"{row['id']}: finalized sent transfer does not match"
                            )
            except (OSError, RPCError, ReconcileError, TypeError, ValueError) as exc:
                entry["error"] = f"{type(exc).__name__}: {exc}"
                hold_errors.append(f"{row['id']}: sent transaction status unavailable")
            sent_proofs.append(entry)

        finalized_proofs = [self._transfer_proof(row) for row in ledger["finalized"]]
        treasury_liability = -int(ledger["treasury_balance"])
        chain_credits = chain_micro * RATE
        backing_rhs = chain_credits - sent_signed_adjustment
        checks = [
            {
                "id": "treasury_backing",
                "ok": not token_errors and not hold_errors and treasury_liability == backing_rhs,
                "left_credits": treasury_liability,
                "right_credits": backing_rhs,
                "detail": (
                    "-treasury == RATE*finalized_chain_micro_usdc "
                    "- finalized_sent_signed_hold_amounts"
                ),
                "errors": [*token_errors, *hold_errors],
            },
            {
                "id": "zero_sum_balances",
                "ok": ledger["balance_sum"] == 0,
                "actual_credits": ledger["balance_sum"],
                "expected_credits": 0,
            },
            {
                "id": "deposit_journal",
                "ok": ledger["chain_ref_deposits"] == ledger["journal_deposits"],
                "chain_ref_credits": ledger["chain_ref_deposits"],
                "journal_credits": ledger["journal_deposits"],
            },
            {
                "id": "finalized_withdrawals",
                "ok": all(item["ok"] for item in finalized_proofs),
                "verification": "all",
                "checked": len(finalized_proofs),
                "failed": sum(not item["ok"] for item in finalized_proofs),
            },
        ]
        return {
            "schema_version": 1,
            "kind": "nak_reconcile",
            "generated_at": stamp.isoformat().replace("+00:00", "Z"),
            "generated_at_unix": generated,
            "date": stamp.date().isoformat(),
            "cluster": self.config.cluster,
            "genesis_hash": self.genesis_hash,
            "mint": self.config.mint,
            "vault_account": self.config.vault_account,
            "rate_credits_per_micro_usdc": RATE,
            "formula": (
                "-balance(treasury) == RATE * sum(finalized treasury-owned micro-USDC) "
                "- sum(finalized sent-not-ledger-finalized signed hold amounts)"
            ),
            "ok": all(check["ok"] for check in checks),
            "checks": checks,
            "totals": {
                "treasury_balance_credits": ledger["treasury_balance"],
                "treasury_liability_credits": treasury_liability,
                "chain_micro_usdc": chain_micro,
                "chain_credits": chain_credits,
                "sent_signed_hold_adjustment_credits": sent_signed_adjustment,
                "backing_right_credits": backing_rhs,
                "all_balances_credits": ledger["balance_sum"],
                "chain_ref_deposit_credits": ledger["chain_ref_deposits"],
                "journal_deposit_credits": ledger["journal_deposits"],
            },
            "token_accounts": token_accounts,
            "sent_withdrawals": sent_proofs,
            "finalized_withdrawals": finalized_proofs,
            "finalized_withdrawal_verification": "all",
            "alerts": [],
        }

    def run(self) -> tuple[dict[str, Any], Path]:
        report = self.collect()
        report_path = self.config.report_dir / f"{report['date']}.json"
        if not report["ok"]:
            failed = [check["id"] for check in report["checks"] if not check["ok"]]
            alert = {
                "event": "nak_reconcile_mismatch",
                "timestamp": report["generated_at"],
                "date": report["date"],
                "failed_checks": failed,
                "report": str(report_path),
                "kill_file": str(self.config.kill_file),
            }
            alert["kill_file_created"] = _write_kill_file(self.config.kill_file, alert)
            message = (
                "🔴 Nakshatra credit reconciliation failed: "
                f"{', '.join(failed)}. Payouts are off. Report: {report_path}"
            )
            alert["buzz"] = self.notify(self.config.buzz_helper, message)
            _append_alert(self.config.report_dir / "alerts.jsonl", alert)
            report["alerts"].append(alert)
            LOG.error("%s", _canonical_json(alert).decode("utf-8"))
        envelope = sign_report(report, self.config.signing_key)
        _atomic_json(report_path, envelope)
        return envelope, report_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", default=DEFAULT_STORE, help="ledger SQLite path")
    parser.add_argument("--report-dir", help="override signed report directory")
    parser.add_argument("--kill-file", help="override the S4 payout kill file")
    parser.add_argument("--signing-key", help="override the hub Ed25519 seed")
    parser.add_argument("--verify-report", type=Path, help="verify a report and exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=os.environ.get("NAK_RECONCILE_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if args.verify_report is not None:
        try:
            envelope = json.loads(args.verify_report.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            LOG.error("could not read report: %s", exc)
            return 2
        valid = verify_report(envelope)
        print(json.dumps({"path": str(args.verify_report), "signature_valid": valid}))
        return 0 if valid else 1

    try:
        config = ReconcileConfig.from_env()
        overrides: dict[str, Path] = {}
        if args.report_dir:
            overrides["report_dir"] = _expanded(args.report_dir)
        if args.kill_file:
            overrides["kill_file"] = _expanded(args.kill_file)
        if args.signing_key:
            overrides["signing_key"] = _expanded(args.signing_key)
        if overrides:
            config = replace(config, **overrides)
        rpc = SolanaRPC(config.rpc_url)
        confirm_rpc = SolanaRPC(config.confirm_rpc_url) if config.confirm_rpc_url else None
        with LedgerStore(_expanded(args.store)) as store:
            envelope, path = Reconciler(store, rpc, config, confirm_rpc).run()
        print(
            json.dumps(
                {
                    "ok": envelope["report"]["ok"],
                    "report": str(path),
                    "signature_valid": verify_report(envelope),
                },
                sort_keys=True,
            )
        )
        return 0 if envelope["report"]["ok"] else 1
    except (OSError, RPCError, ReconcileError, sqlite3.Error, ValueError) as exc:
        LOG.error("reconciliation could not run: %s: %s", type(exc).__name__, exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
