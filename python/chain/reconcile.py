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

The collector deliberately uses a double-bracketed snapshot.  It reads all
treasury token accounts in one finalized ``getMultipleAccounts`` call and all
withdrawal statuses in one call, takes the entire ledger image in one explicit
read-only SQLite transaction, and then reads all token accounts again.  It
retries when either side changes.  A chain balance newer than its indexed
deposit provenance is also transient, not a mismatch.  Only a discrepancy
that survives a stable bracket is a MISMATCH.  Exhausting the retry budget is
INCONCLUSIVE: alert but do not kill payouts until the configured number of
consecutive inconclusive runs (three by default), when fail-closed escalation
creates the kill file.

The other invariants are: all ledger balances sum to zero; every deposit
``chain_ref`` has exactly one matching append-only journal row and vice versa;
every withdrawal state has its exact S1/S4 hold balance and lifecycle journal;
and every treasury-liability-reducing journal row is backed by a successful
finalized vault-to-recipient transaction proof.

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
import signal
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

from core.ledger_store import RATE, TREASURY_ACCOUNT
from ledger_auth import canonical_string, verify_request


LOG = logging.getLogger("nak-reconcile")
DEFAULT_STORE = "~/.neuron/credits/ledger.sqlite"
DEFAULT_REPORT_DIR = "~/.neuron/credits/reconcile"
DEFAULT_KILL_FILE = "~/.neuron/credits/payout.off"
DEFAULT_SIGNING_KEY = "~/.nakshatra/keys/worker.ed25519"
DEFAULT_BUZZ_HELPER = Path("/home/prithvi/trisul/infra/mesh-agent/buzz-say.sh")
REPORT_METHOD = "REPORT"
REPORT_PATH_PREFIX = "/credits/reconcile/"
REPORT_SCHEME = "Sthambha-Ed25519"
REPORT_PURPOSE = "nak-credit-reconciliation-v1"
WITHDRAWAL_HOLD_PREFIX = "__withdrawal_hold__:"


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
    snapshot_attempts: int = 3
    snapshot_retry_delay_s: float = 0.25
    inconclusive_kill_runs: int = 3

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
        if self.snapshot_attempts < 1:
            raise ValueError("snapshot_attempts must be positive")
        if self.snapshot_retry_delay_s < 0:
            raise ValueError("snapshot_retry_delay_s must not be negative")
        if self.inconclusive_kill_runs < 1:
            raise ValueError("inconclusive_kill_runs must be positive")

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
            snapshot_attempts=int(os.environ.get("NAK_RECONCILE_SNAPSHOT_ATTEMPTS", "3")),
            snapshot_retry_delay_s=float(
                os.environ.get("NAK_RECONCILE_RETRY_DELAY_S", "0.25")
            ),
            inconclusive_kill_runs=int(
                os.environ.get("NAK_RECONCILE_INCONCLUSIVE_KILL_RUNS", "3")
            ),
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
    """Return a signed envelope using ledger_auth's wire signature contract."""
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
            "scheme": REPORT_SCHEME,
            "keyid": public_hex,
            "method": REPORT_METHOD,
            "path": signed_path,
            "timestamp": timestamp,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_report(envelope: dict[str, Any], expected_public_key: str | None) -> bool:
    """Verify against an independently pinned hub public key.  Never raises."""
    try:
        report = envelope["report"]
        signature = envelope["signature"]
        body = _canonical_json(report)
        expected_bytes = bytes.fromhex(expected_public_key or "")
        if len(expected_bytes) != 32:
            return False
        if report["signature_contract"] != {
            "scheme": REPORT_SCHEME,
            "purpose": REPORT_PURPOSE,
        }:
            return False
        expected_path = f"{REPORT_PATH_PREFIX}{report['date']}"
        if signature.get("algorithm") != "Ed25519":
            return False
        if signature.get("scheme") != REPORT_SCHEME:
            return False
        if signature.get("keyid") != expected_public_key.lower():
            return False
        if signature.get("method") != REPORT_METHOD:
            return False
        if signature.get("path") != expected_path:
            return False
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
    """Create the S4 kill switch without following links.

    An existing regular file remains untouched.  A symlink or other special
    file cannot stop payout while masquerading as the switch, so it is removed
    from the private parent directory and replaced using ``O_EXCL``.
    """
    _secure_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    for _attempt in range(3):
        try:
            fd = os.open(path, flags, 0o600)
            break
        except FileExistsError:
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode):
                return False
            try:
                path.unlink()
            except FileNotFoundError:
                continue
    else:
        raise ReconcileError(f"could not create a real payout kill file at {path}")
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ReconcileError(f"payout kill file is not regular: {path}")
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
        process = subprocess.Popen(
            ["bash", str(helper), message],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            returncode = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            return {
                "attempted": True,
                "delivered": False,
                "detail": "helper timed out",
            }
    except OSError as exc:
        return {
            "attempted": True,
            "delivered": False,
            "detail": type(exc).__name__,
        }
    return {
        "attempted": True,
        "delivered": returncode == 0,
        "detail": "ok" if returncode == 0 else f"helper exited {returncode}",
    }


class Reconciler:
    """Collect a stable proof and apply only fail-closed side effects."""

    def __init__(
        self,
        ledger_path: str | Path,
        rpc: Any,
        config: ReconcileConfig,
        confirm_rpc: Any | None = None,
        *,
        notify: Callable[[Path | None, str], dict[str, Any]] = _buzz_notify,
        now: Callable[[], float] = time.time,
    ):
        self.ledger_path = Path(ledger_path)
        self.rpc = rpc
        self.confirm_rpc = confirm_rpc
        self.config = config
        self.notify = notify
        self.now = now
        if (config.confirm_rpc_url is None) != (confirm_rpc is None):
            raise ValueError(
                "confirmation RPC client must be supplied exactly when configured"
            )
        self.genesis_hash: str | None = None

    def _pin_rpcs(self) -> None:
        if self.genesis_hash is not None:
            return
        config = self.config
        expected = config.devnet_genesis if config.cluster == "devnet" else None
        genesis = DepositIndexer._pin_rpc(self.rpc, expected, "reconcile")
        if genesis == MAINNET_GENESIS_HASH:
            raise ValueError("mainnet-beta genesis is explicitly refused")
        self.genesis_hash = genesis
        if self.confirm_rpc is not None:
            confirm_genesis = DepositIndexer._pin_rpc(
                self.confirm_rpc, genesis, "reconcile confirmation"
            )
            if confirm_genesis != genesis:
                raise ValueError("confirmation RPC genesis differs from primary")

    @staticmethod
    def _hold_account(withdrawal_id: str) -> str:
        return f"{WITHDRAWAL_HOLD_PREFIX}{withdrawal_id}"

    def _ledger_snapshot(self) -> dict[str, Any]:
        """Read the complete reconciliation image in one read-only transaction."""
        try:
            resolved = self.ledger_path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ReconcileError(f"ledger does not exist: {self.ledger_path}") from exc
        uri = f"{resolved.as_uri()}?mode=ro"
        try:
            db = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=30.0)
        except sqlite3.Error as exc:
            raise ReconcileError(f"could not open ledger read-only: {exc}") from exc
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA busy_timeout=30000")
            db.execute("BEGIN")
            try:
                quick = db.execute("PRAGMA quick_check").fetchone()
                if quick is None or quick[0] != "ok":
                    raise sqlite3.DatabaseError("ledger integrity check failed")
                snapshot = {
                    "accounts": [
                        dict(row)
                        for row in db.execute(
                            "SELECT id, balance, tier FROM accounts ORDER BY id"
                        )
                    ],
                    "deposit_accounts": [
                        dict(row)
                        for row in db.execute(
                            "SELECT operator, token_account, created_ts "
                            "FROM deposit_accounts ORDER BY operator"
                        )
                    ],
                    "chain_refs": [
                        dict(row)
                        for row in db.execute(
                            "SELECT ref, kind, account, token_account, amount, slot, ts "
                            "FROM chain_refs ORDER BY ref"
                        )
                    ],
                    "journal": [
                        dict(row)
                        for row in db.execute(
                            "SELECT seq, ts, kind, receipt_id, account, counterparty, "
                            "amount, detail FROM journal ORDER BY seq"
                        )
                    ],
                    "withdrawals": [
                        dict(row)
                        for row in db.execute("SELECT * FROM withdrawals ORDER BY id")
                    ],
                    "withdrawal_attempts": [
                        dict(row)
                        for row in db.execute(
                            "SELECT * FROM withdrawal_attempts "
                            "ORDER BY withdrawal_id, attempt"
                        )
                    ],
                }
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        except sqlite3.Error as exc:
            raise ReconcileError(f"could not read ledger snapshot: {exc}") from exc
        finally:
            db.close()
        return snapshot

    def _addresses(self, ledger: dict[str, Any]) -> list[str]:
        return [
            self.config.vault_account,
            *sorted(
                {
                    row["token_account"]
                    for row in ledger["deposit_accounts"]
                    if row["token_account"] != self.config.vault_account
                }
            ),
        ]

    @staticmethod
    def _signatures(ledger: dict[str, Any]) -> list[str]:
        return sorted(
            {
                row["tx_sig"]
                for row in ledger["withdrawals"]
                if isinstance(row.get("tx_sig"), str) and row["tx_sig"]
            }
        )

    def _token_accounts(self, addresses: list[str]) -> dict[str, Any]:
        primary = self.rpc.get_token_accounts(addresses)
        if self.confirm_rpc is not None:
            confirmed = self.confirm_rpc.get_token_accounts(addresses)
            if primary.get("accounts") != confirmed.get("accounts"):
                raise ReconcileError(
                    "token accounts differ between primary and confirmation RPCs"
                )
        return primary

    def _statuses(self, signatures: list[str]) -> dict[str, dict[str, Any] | None]:
        primary = self.rpc.get_signature_statuses(signatures)
        if self.confirm_rpc is not None:
            confirmed = self.confirm_rpc.get_signature_statuses(signatures)
            if primary != confirmed:
                raise ReconcileError(
                    "withdrawal statuses differ between primary and confirmation RPCs"
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

    def _transfer_proof(
        self, row: dict[str, Any], status: dict[str, Any] | None
    ) -> dict[str, Any]:
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

    @staticmethod
    def _detail(row: dict[str, Any]) -> dict[str, Any] | None:
        try:
            value = json.loads(row["detail"])
        except (json.JSONDecodeError, KeyError, TypeError):
            return None
        return value if isinstance(value, dict) else None

    def _deposit_provenance(
        self,
        ledger: dict[str, Any],
        token_amounts: dict[str, int],
        verified_vault_outflow: int,
    ) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        lag: list[str] = []
        refs = [row for row in ledger["chain_refs"] if row["kind"] == "deposit"]
        journals = [row for row in ledger["journal"] if row["kind"] == "deposit"]
        accounts = {
            row["operator"]: row["token_account"] for row in ledger["deposit_accounts"]
        }
        used: set[int] = set()
        for ref in refs:
            matching = [
                row
                for row in journals
                if (detail := self._detail(row)) is not None
                and detail.get("ref") == ref["ref"]
            ]
            if len(matching) != 1:
                errors.append(
                    f"deposit ref {ref['ref']}: expected one journal row, found {len(matching)}"
                )
                continue
            row = matching[0]
            used.add(int(row["seq"]))
            detail = self._detail(row) or {}
            if (
                row["account"] != ref["account"]
                or row["counterparty"] != TREASURY_ACCOUNT
                or int(row["amount"]) != int(ref["amount"])
                or detail.get("slot") != ref["slot"]
                or detail.get("rate") != RATE
                or not isinstance(ref.get("token_account"), str)
                or accounts.get(ref["account"]) != ref.get("token_account")
            ):
                errors.append(f"deposit ref {ref['ref']}: journal/account provenance differs")
        for row in journals:
            if int(row["seq"]) not in used:
                errors.append(f"deposit journal seq {row['seq']}: no unique chain ref")

        indexed: dict[str, int] = {}
        for ref in refs:
            token_account = ref.get("token_account")
            if isinstance(token_account, str):
                indexed[token_account] = indexed.get(token_account, 0) + int(ref["amount"])
        for row in ledger["deposit_accounts"]:
            address = row["token_account"]
            on_chain = token_amounts.get(address, 0) * RATE
            expected = indexed.get(address, 0)
            if address == self.config.vault_account:
                expected -= verified_vault_outflow
            if expected < 0:
                errors.append(
                    f"{address}: verified withdrawals exceed indexed deposits"
                )
                continue
            if on_chain > expected:
                lag.append(
                    f"{address}: chain balance {on_chain} exceeds indexed net deposits {expected}"
                )
            elif on_chain < expected:
                errors.append(
                    f"{address}: indexed net deposits {expected} exceed chain balance {on_chain}"
                )
        return errors, lag

    def _withdrawal_lifecycle(
        self,
        ledger: dict[str, Any],
        statuses: dict[str, dict[str, Any] | None],
    ) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]], int]:
        errors: list[str] = []
        balances = {row["id"]: int(row["balance"]) for row in ledger["accounts"]}
        attempts: dict[str, list[dict[str, Any]]] = {}
        for attempt in ledger["withdrawal_attempts"]:
            attempts.setdefault(attempt["withdrawal_id"], []).append(attempt)
        lifecycle: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for kind in ("withdraw_hold", "withdraw_release", "withdraw"):
            for journal in (row for row in ledger["journal"] if row["kind"] == kind):
                detail = self._detail(journal)
                withdrawal_id = detail.get("withdrawal_id") if detail else None
                if not isinstance(withdrawal_id, str) or not withdrawal_id:
                    errors.append(f"{kind} journal seq {journal['seq']}: malformed detail")
                    continue
                lifecycle.setdefault(withdrawal_id, {}).setdefault(kind, []).append(journal)

        withdrawal_ids = {row["id"] for row in ledger["withdrawals"]}
        for withdrawal_id in lifecycle:
            if withdrawal_id not in withdrawal_ids:
                errors.append(f"orphan lifecycle journal rows for {withdrawal_id}")
        for withdrawal_id in attempts:
            if withdrawal_id not in withdrawal_ids:
                errors.append(f"orphan withdrawal attempts for {withdrawal_id}")

        sent_proofs: list[dict[str, Any]] = []
        finalized_proofs: list[dict[str, Any]] = []
        sent_adjustment = 0
        active_states = {"pending", "approved", "sent", "expired"}
        for row in ledger["withdrawals"]:
            withdrawal_id = row["id"]
            amount = int(row["amount"])
            hold_account = self._hold_account(withdrawal_id)
            rows = lifecycle.get(withdrawal_id, {})
            holds = rows.get("withdraw_hold", [])
            releases = rows.get("withdraw_release", [])
            withdrawals = rows.get("withdraw", [])
            hold_ok = len(holds) == 1
            if hold_ok:
                detail = self._detail(holds[0]) or {}
                hold_ok = (
                    holds[0]["account"] == row["operator"]
                    and holds[0]["counterparty"] == hold_account
                    and int(holds[0]["amount"]) == -amount
                    and detail.get("address") == row["address"]
                    and detail.get("rate") == RATE
                )
            if not hold_ok:
                errors.append(f"{withdrawal_id}: withdraw_hold journal is inconsistent")

            expected_hold = amount if row["state"] in active_states else 0
            if balances.get(hold_account, 0) != expected_hold:
                errors.append(
                    f"{withdrawal_id}: hold balance is {balances.get(hold_account, 0)}, "
                    f"expected {expected_hold} for {row['state']}"
                )

            if row["state"] == "released":
                release_ok = len(releases) == 1 and not withdrawals
                if release_ok:
                    detail = self._detail(releases[0]) or {}
                    release_ok = (
                        releases[0]["account"] == row["operator"]
                        and releases[0]["counterparty"] == hold_account
                        and int(releases[0]["amount"]) == amount
                        and detail.get("address") == row["address"]
                        and detail.get("rate") == RATE
                    )
                if not release_ok:
                    errors.append(f"{withdrawal_id}: released withdrawal was not returned")
            elif row["state"] == "finalized":
                withdraw_ok = len(withdrawals) == 1 and not releases
                if withdraw_ok:
                    detail = self._detail(withdrawals[0]) or {}
                    withdraw_ok = (
                        withdrawals[0]["account"] == TREASURY_ACCOUNT
                        and withdrawals[0]["counterparty"] == row["operator"]
                        and int(withdrawals[0]["amount"]) == amount
                        and detail.get("address") == row["address"]
                        and detail.get("rate") == RATE
                    )
                if not withdraw_ok:
                    errors.append(f"{withdrawal_id}: finalized journal is inconsistent")
            elif releases or withdrawals:
                errors.append(f"{withdrawal_id}: {row['state']} has terminal journal rows")

            own_attempts = attempts.get(withdrawal_id, [])
            attempt_states = [attempt["state"] for attempt in own_attempts]
            state = row["state"]
            approval_absent = (
                row.get("approval_ref") is None and row.get("approval_ts") is None
            )
            approval_present = (
                isinstance(row.get("approval_ref"), str)
                and bool(row["approval_ref"])
                and isinstance(row.get("approval_ts"), int)
            )
            transaction_absent = all(
                row.get(field) is None
                for field in (
                    "tx_sig",
                    "blockhash",
                    "last_valid_block_height",
                    "tx_wire",
                )
            )
            transaction_present = all(
                (
                    isinstance(row.get("tx_sig"), str) and bool(row["tx_sig"]),
                    isinstance(row.get("blockhash"), str) and bool(row["blockhash"]),
                    isinstance(row.get("last_valid_block_height"), int),
                    isinstance(row.get("tx_wire"), str) and bool(row["tx_wire"]),
                )
            )
            if state == "pending" and (
                not approval_absent or not transaction_absent or own_attempts
            ):
                errors.append(f"{withdrawal_id}: pending metadata is inconsistent")
            if state == "approved" and (
                not approval_present or not transaction_absent
            ):
                errors.append(f"{withdrawal_id}: approved metadata is inconsistent")
            if state in {"sent", "expired", "finalized"} and (
                not approval_present or not transaction_present
            ):
                errors.append(f"{withdrawal_id}: {state} metadata is inconsistent")
            if state == "released" and (
                not (approval_absent or approval_present)
                or (own_attempts and not transaction_present)
                or (not own_attempts and not transaction_absent)
            ):
                errors.append(f"{withdrawal_id}: released metadata is inconsistent")
            expected_attempts = list(range(1, len(own_attempts) + 1))
            if [int(item["attempt"]) for item in own_attempts] != expected_attempts:
                errors.append(f"{withdrawal_id}: attempt numbering is inconsistent")
            if int(row["expiry_count"]) != attempt_states.count("expired"):
                errors.append(f"{withdrawal_id}: expiry count is inconsistent")
            if own_attempts and transaction_present and (
                own_attempts[-1]["tx_sig"] != row["tx_sig"]
                or own_attempts[-1]["blockhash"] != row["blockhash"]
                or int(own_attempts[-1]["last_valid_block_height"])
                != int(row["last_valid_block_height"])
                or own_attempts[-1]["tx_wire"] != row["tx_wire"]
            ):
                errors.append(f"{withdrawal_id}: current attempt metadata differs")
            if row["state"] in {"pending", "approved"} and own_attempts:
                errors.append(f"{withdrawal_id}: {row['state']} has transaction attempts")
            if row["state"] == "sent" and (
                not own_attempts
                or own_attempts[-1]["state"] != "sent"
                or own_attempts[-1]["tx_sig"] != row["tx_sig"]
                or attempt_states.count("sent") != 1
            ):
                errors.append(f"{withdrawal_id}: sent attempt state is inconsistent")
            if row["state"] == "expired" and (
                not own_attempts or any(state != "expired" for state in attempt_states)
            ):
                errors.append(f"{withdrawal_id}: expired attempt state is inconsistent")
            if row["state"] == "finalized" and (
                not own_attempts
                or own_attempts[-1]["state"] != "finalized"
                or own_attempts[-1]["tx_sig"] != row["tx_sig"]
                or attempt_states.count("finalized") != 1
            ):
                errors.append(f"{withdrawal_id}: finalized attempt state is inconsistent")
            if row["state"] == "released" and own_attempts and (
                any(state != "expired" for state in attempt_states)
                or own_attempts[-1]["tx_sig"] != row["tx_sig"]
            ):
                errors.append(f"{withdrawal_id}: released attempt state is inconsistent")

            if row["state"] == "sent":
                status = statuses.get(row["tx_sig"])
                entry: dict[str, Any] = {
                    "withdrawal_id": withdrawal_id,
                    "tx_sig": row["tx_sig"],
                    "amount_credits": amount,
                    "hold_journal_ok": hold_ok,
                    "signed_hold_amount_credits": -amount if hold_ok else None,
                    "chain_state": "not_finalized",
                    "adjustment_credits": 0,
                }
                if isinstance(status, dict) and status.get("confirmationStatus") == "finalized":
                    if status.get("err") is not None:
                        entry["chain_state"] = "finalized_failed"
                        errors.append(f"{withdrawal_id}: finalized transaction failed")
                    else:
                        transfer = self._transfer_proof(row, status)
                        entry["transfer"] = transfer
                        if transfer["ok"] and hold_ok:
                            entry["chain_state"] = "finalized_pending_ledger"
                            entry["adjustment_credits"] = -amount
                            sent_adjustment -= amount
                        else:
                            errors.append(
                                f"{withdrawal_id}: finalized sent transfer does not match"
                            )
                sent_proofs.append(entry)
            elif row["state"] == "finalized":
                finalized_proofs.append(
                    self._transfer_proof(row, statuses.get(row["tx_sig"]))
                )

        for account, balance in balances.items():
            if account.startswith(WITHDRAWAL_HOLD_PREFIX):
                withdrawal_id = account[len(WITHDRAWAL_HOLD_PREFIX):]
                if withdrawal_id not in withdrawal_ids:
                    errors.append(f"orphan hold account {account} has balance {balance}")
        return errors, sent_proofs, finalized_proofs, sent_adjustment

    def _format_token_accounts(
        self, ledger: dict[str, Any], chain: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], list[str], dict[str, int]]:
        roles: dict[str, dict[str, Any]] = {
            self.config.vault_account: {"roles": ["vault"], "operators": []}
        }
        for row in ledger["deposit_accounts"]:
            entry = roles.setdefault(
                row["token_account"], {"roles": [], "operators": []}
            )
            if "deposit" not in entry["roles"]:
                entry["roles"].append("deposit")
            entry["operators"].append(row["operator"])
        records: list[dict[str, Any]] = []
        errors: list[str] = []
        amounts: dict[str, int] = {}
        owner: str | None = None
        for account in chain["accounts"]:
            address = account["token_account"]
            record = {
                **account,
                **roles[address],
                "amount_micro_usdc": int(account["amount"]),
                "slot": int(chain["slot"]),
            }
            record.pop("amount", None)
            records.append(record)
            amounts[address] = int(account["amount"])
            if account.get("mint") != self.config.mint:
                errors.append(f"{address}: mint differs from configured USDC mint")
            if account.get("decimals") != USDC_DECIMALS:
                errors.append(f"{address}: token decimals are not {USDC_DECIMALS}")
            if address == self.config.vault_account:
                owner = account.get("owner")
        if not isinstance(owner, str):
            errors.append("vault token authority could not establish treasury ownership")
        else:
            for account in chain["accounts"]:
                if account.get("owner") != owner:
                    errors.append(
                        f"{account['token_account']}: token account is not treasury-owned"
                    )
        return records, errors, amounts

    def _build_report(
        self,
        ledger: dict[str, Any],
        chain: dict[str, Any],
        statuses: dict[str, dict[str, Any] | None],
        *,
        generated: int,
        attempt: int,
        before_slot: int,
    ) -> tuple[dict[str, Any], list[str]]:
        stamp = dt.datetime.fromtimestamp(generated, tz=dt.timezone.utc)
        token_accounts, token_errors, token_amounts = self._format_token_accounts(
            ledger, chain
        )
        lifecycle_errors, sent_proofs, finalized_proofs, sent_adjustment = (
            self._withdrawal_lifecycle(ledger, statuses)
        )
        verified_vault_outflow = sum(
            int(item["amount_credits"])
            for item in finalized_proofs
            if item["ok"]
        ) + sum(
            int(item["amount_credits"])
            for item in sent_proofs
            if item["chain_state"] == "finalized_pending_ledger"
        )
        deposit_errors, lag = self._deposit_provenance(
            ledger, token_amounts, verified_vault_outflow
        )
        balances = {row["id"]: int(row["balance"]) for row in ledger["accounts"]}
        treasury_balance = balances.get(TREASURY_ACCOUNT, 0)
        balance_sum = sum(balances.values())
        chain_ref_deposits = sum(
            int(row["amount"])
            for row in ledger["chain_refs"]
            if row["kind"] == "deposit"
        )
        journal_deposits = sum(
            int(row["amount"])
            for row in ledger["journal"]
            if row["kind"] == "deposit"
        )
        finalized_total = sum(
            int(row["amount"])
            for row in ledger["withdrawals"]
            if row["state"] == "finalized"
        )
        treasury_provenance_errors: list[str] = []
        expected_treasury = -chain_ref_deposits + finalized_total
        if treasury_balance != expected_treasury:
            treasury_provenance_errors.append(
                f"treasury balance {treasury_balance} != deposits/finalized provenance "
                f"{expected_treasury}"
            )
        finalized_ids = {
            row["id"] for row in ledger["withdrawals"] if row["state"] == "finalized"
        }
        for row in ledger["journal"]:
            if row["account"] == TREASURY_ACCOUNT and int(row["amount"]) > 0:
                detail = self._detail(row)
                if (
                    row["kind"] != "withdraw"
                    or not detail
                    or detail.get("withdrawal_id") not in finalized_ids
                ):
                    treasury_provenance_errors.append(
                        f"treasury-reducing journal seq {row['seq']} has no finalized proof"
                    )

        chain_micro = sum(token_amounts.values())
        treasury_liability = -treasury_balance
        chain_credits = chain_micro * RATE
        backing_rhs = chain_credits - sent_adjustment
        checks = [
            {
                "id": "treasury_backing",
                "ok": not token_errors
                and not lifecycle_errors
                and treasury_liability == backing_rhs,
                "left_credits": treasury_liability,
                "right_credits": backing_rhs,
                "detail": (
                    "-treasury == RATE*finalized_chain_micro_usdc "
                    "- finalized_sent_signed_hold_amounts"
                ),
                "errors": [*token_errors, *lifecycle_errors],
            },
            {
                "id": "zero_sum_balances",
                "ok": balance_sum == 0,
                "actual_credits": balance_sum,
                "expected_credits": 0,
            },
            {
                "id": "deposit_provenance",
                "ok": not deposit_errors,
                "chain_ref_credits": chain_ref_deposits,
                "journal_credits": journal_deposits,
                "errors": deposit_errors,
            },
            {
                "id": "withdrawal_lifecycle",
                "ok": not lifecycle_errors,
                "checked": len(ledger["withdrawals"]),
                "errors": lifecycle_errors,
            },
            {
                "id": "treasury_provenance",
                "ok": not treasury_provenance_errors,
                "expected_balance_credits": expected_treasury,
                "actual_balance_credits": treasury_balance,
                "errors": treasury_provenance_errors,
            },
            {
                "id": "finalized_withdrawals",
                "ok": all(item["ok"] for item in finalized_proofs),
                "verification": "all",
                "checked": len(finalized_proofs),
                "failed": sum(not item["ok"] for item in finalized_proofs),
            },
        ]
        ok = all(check["ok"] for check in checks)
        report = {
            "schema_version": 2,
            "kind": "nak_reconcile",
            "signature_contract": {
                "scheme": REPORT_SCHEME,
                "purpose": REPORT_PURPOSE,
            },
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
            "outcome": "match" if ok else "mismatch",
            "ok": ok,
            "snapshot": {
                "stable": True,
                "attempt": attempt,
                "balance_slot_before": before_slot,
                "balance_slot_after": int(chain["slot"]),
                "commitment": "finalized",
                "balance_rpc": "getMultipleAccounts",
                "status_rpc": "getSignatureStatuses",
            },
            "checks": checks,
            "totals": {
                "treasury_balance_credits": treasury_balance,
                "treasury_liability_credits": treasury_liability,
                "chain_micro_usdc": chain_micro,
                "chain_credits": chain_credits,
                "sent_signed_hold_adjustment_credits": sent_adjustment,
                "backing_right_credits": backing_rhs,
                "all_balances_credits": balance_sum,
                "chain_ref_deposit_credits": chain_ref_deposits,
                "journal_deposit_credits": journal_deposits,
            },
            "token_accounts": token_accounts,
            "sent_withdrawals": sent_proofs,
            "finalized_withdrawals": finalized_proofs,
            "finalized_withdrawal_verification": "all",
            "alerts": [],
        }
        return report, lag

    def collect(self) -> dict[str, Any]:
        """Collect a stable proof without writing balances or operational files."""
        generated = int(self.now())
        baseline = self._ledger_snapshot()
        self._pin_rpcs()
        reasons: list[str] = []
        last_report: dict[str, Any] | None = None
        for attempt in range(1, self.config.snapshot_attempts + 1):
            addresses = self._addresses(baseline)
            signatures = self._signatures(baseline)
            before = self._token_accounts(addresses)
            statuses = self._statuses(signatures)
            ledger = self._ledger_snapshot()
            after_addresses = self._addresses(ledger)
            after_signatures = self._signatures(ledger)
            after = self._token_accounts(after_addresses)
            reasons = []
            if addresses != after_addresses or signatures != after_signatures:
                reasons.append("ledger collection targets changed during snapshot")
            if _canonical_json(baseline) != _canonical_json(ledger):
                reasons.append("ledger changed during snapshot")
            if addresses == after_addresses and before.get("accounts") != after.get("accounts"):
                reasons.append("finalized token balances changed during snapshot")
            if reasons:
                baseline = ledger
            else:
                last_report, lag = self._build_report(
                    ledger,
                    after,
                    statuses,
                    generated=generated,
                    attempt=attempt,
                    before_slot=int(before["slot"]),
                )
                reasons.extend(lag)
                if not reasons:
                    return last_report
                baseline = ledger
            if attempt < self.config.snapshot_attempts:
                time.sleep(self.config.snapshot_retry_delay_s)

        if last_report is None:
            # Targets may have changed every time; take one coherent final image
            # for diagnostics, but keep the outcome explicitly inconclusive.
            addresses = self._addresses(baseline)
            before = self._token_accounts(addresses)
            statuses = self._statuses(self._signatures(baseline))
            after = self._token_accounts(addresses)
            last_report, lag = self._build_report(
                baseline,
                after,
                statuses,
                generated=generated,
                attempt=self.config.snapshot_attempts,
                before_slot=int(before["slot"]),
            )
            reasons.extend(lag)
        last_report["outcome"] = "inconclusive"
        last_report["ok"] = False
        last_report["snapshot"].update(stable=False, reasons=sorted(set(reasons)))
        return last_report

    def _inconclusive_count(self) -> int:
        path = self.config.report_dir / ".inconclusive-state.json"
        # Only a missing file means "no streak". Anything unreadable raises, and run() turns that into a
        # kill: a counter we cannot trust must never be what keeps payouts on.
        if not path.exists() and not path.is_symlink():
            return 0
        value = json.loads(path.read_text(encoding="utf-8"))
        count = value.get("consecutive") if isinstance(value, dict) else None
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError(f"corrupt inconclusive counter in {path}")
        return count

    def _set_inconclusive_count(self, count: int) -> None:
        _atomic_json(
            self.config.report_dir / ".inconclusive-state.json",
            {"consecutive": count},
        )

    def _alert(
        self,
        alert: dict[str, Any],
        message: str,
        *,
        kill: bool,
    ) -> dict[str, Any]:
        if kill:
            alert["kill_file_created"] = _write_kill_file(
                self.config.kill_file, alert
            )
        alert["buzz"] = self.notify(self.config.buzz_helper, message)
        _append_alert(self.config.report_dir / "alerts.jsonl", alert)
        LOG.error("%s", _canonical_json(alert).decode("utf-8"))
        return alert

    def run(self) -> tuple[dict[str, Any], Path]:
        try:
            report = self.collect()
        except Exception as exc:
            generated = int(self.now())
            stamp = dt.datetime.fromtimestamp(generated, tz=dt.timezone.utc)
            alert = {
                "event": "nak_reconcile_collection_error",
                "timestamp": stamp.isoformat().replace("+00:00", "Z"),
                "error_type": type(exc).__name__,
                "detail": str(exc),
                "kill_file": str(self.config.kill_file),
            }
            self._alert(
                alert,
                "🔴 Nakshatra reconciliation collection failed. Payouts are off.",
                kill=True,
            )
            raise

        try:
            return self._finish(report)
        except Exception as exc:
            # Fail closed after collection too: a counter/report/signing failure must leave payouts OFF.
            generated = int(self.now())
            stamp = dt.datetime.fromtimestamp(generated, tz=dt.timezone.utc)
            self._alert(
                {
                    "event": "nak_reconcile_post_collection_error",
                    "timestamp": stamp.isoformat().replace("+00:00", "Z"),
                    "error_type": type(exc).__name__,
                    "detail": str(exc),
                    "kill_file": str(self.config.kill_file),
                },
                "🔴 Nakshatra reconciliation failed after collection. Payouts are off.",
                kill=True,
            )
            raise

    def _finish(self, report: dict[str, Any]) -> tuple[dict[str, Any], Path]:
        report_path = self.config.report_dir / f"{report['date']}.json"
        outcome = report["outcome"]
        if outcome == "inconclusive":
            count = self._inconclusive_count() + 1
            self._set_inconclusive_count(count)
            report["consecutive_inconclusive_runs"] = count
            kill = count >= self.config.inconclusive_kill_runs
            alert = {
                "event": "nak_reconcile_inconclusive",
                "timestamp": report["generated_at"],
                "date": report["date"],
                "consecutive_runs": count,
                "kill_threshold": self.config.inconclusive_kill_runs,
                "report": str(report_path),
                "kill_file": str(self.config.kill_file),
            }
            message = (
                "🔴 Nakshatra reconciliation repeatedly inconclusive; payouts are off."
                if kill
                else "🟡 Nakshatra reconciliation inconclusive; retry scheduled."
            )
            report["alerts"].append(self._alert(alert, message, kill=kill))
        else:
            if outcome == "mismatch":
                failed = [
                    check["id"] for check in report["checks"] if not check["ok"]
                ]
                alert = {
                    "event": "nak_reconcile_mismatch",
                    "timestamp": report["generated_at"],
                    "date": report["date"],
                    "failed_checks": failed,
                    "report": str(report_path),
                    "kill_file": str(self.config.kill_file),
                }
                message = (
                    "🔴 Nakshatra credit reconciliation failed: "
                    f"{', '.join(failed)}. Payouts are off. Report: {report_path}"
                )
                report["alerts"].append(self._alert(alert, message, kill=True))
            # reset the streak only AFTER any kill for this run is already on disk
            self._set_inconclusive_count(0)
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
    expected = parser.add_mutually_exclusive_group()
    expected.add_argument(
        "--expect-pubkey",
        help="independently pinned 32-byte hub Ed25519 public key (hex)",
    )
    expected.add_argument(
        "--expect-pubkey-file",
        type=Path,
        help="file containing the independently pinned hub public key hex",
    )
    return parser


def _expected_public_key(args: argparse.Namespace) -> str | None:
    value = args.expect_pubkey or os.environ.get("NAK_RECONCILE_EXPECT_PUBKEY")
    path = args.expect_pubkey_file
    if path is None:
        configured = os.environ.get("NAK_RECONCILE_EXPECT_PUBKEY_FILE")
        path = _expanded(configured) if configured else None
    if value and path is not None:
        raise ValueError("configure only one expected public key source")
    if path is not None:
        value = path.read_text(encoding="ascii").strip()
    if value is None:
        return None
    raw = bytes.fromhex(value)
    if len(raw) != 32:
        raise ValueError("expected public key must be 32 bytes of hex")
    return value.lower()


def _signing_public_key(path: Path) -> str:
    return _load_signing_key(path).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=os.environ.get("NAK_RECONCILE_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if args.verify_report is not None:
        try:
            envelope = json.loads(args.verify_report.read_text(encoding="utf-8"))
            expected_public_key = _expected_public_key(args)
            if expected_public_key is None:
                raise ValueError(
                    "verification requires --expect-pubkey or --expect-pubkey-file"
                )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            LOG.error("could not read report: %s", exc)
            return 2
        valid = verify_report(envelope, expected_public_key)
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
        envelope, path = Reconciler(
            _expanded(args.store), rpc, config, confirm_rpc
        ).run()
        expected_public_key = _signing_public_key(config.signing_key)
        print(
            json.dumps(
                {
                    "ok": envelope["report"]["ok"],
                    "outcome": envelope["report"]["outcome"],
                    "report": str(path),
                    "signature_valid": verify_report(envelope, expected_public_key),
                },
                sort_keys=True,
            )
        )
        if envelope["report"]["outcome"] == "inconclusive":
            return 2
        return 0 if envelope["report"]["ok"] else 1
    except Exception as exc:
        LOG.error("reconciliation could not run: %s: %s", type(exc).__name__, exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
