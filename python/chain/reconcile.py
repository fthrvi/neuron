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
every spend usage delta has exact pricing, escrow, journal, and shared-economic
provenance; and every treasury-liability-reducing journal row is backed by a
successful finalized vault-to-recipient transaction proof.

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

from core.ledger_store import (
    HOLD_S,
    RATE,
    SPEND_RECEIPT_DOMAIN,
    SPEND_USAGE_FIELDS,
    TREASURY_ACCOUNT,
)
from ledger_auth import canonical_string, verify_request


LOG = logging.getLogger("nak-reconcile")
DEFAULT_STORE = "~/.neuron/credits/ledger.sqlite"
DEFAULT_REPORT_DIR = "~/.neuron/credits/reconcile"
DEFAULT_KILL_FILE = "~/.neuron/credits/payout.off"
DEFAULT_SIGNING_KEY = "~/.nakshatra/keys/worker.ed25519"
DEFAULT_GRANDFATHERED_HOLDS_FILE = (
    "~/.config/nakshatra/reconcile-grandfathered-holds.txt"
)
DEFAULT_BUZZ_HELPER = Path("/home/prithvi/trisul/infra/mesh-agent/buzz-say.sh")
DEFAULT_SWEEP_STALE_BLOCKS = 300
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
    grandfathered_holds_file: Path = Path(
        DEFAULT_GRANDFATHERED_HOLDS_FILE
    ).expanduser()
    buzz_helper: Path | None = DEFAULT_BUZZ_HELPER
    snapshot_attempts: int = 3
    snapshot_retry_delay_s: float = 0.25
    inconclusive_kill_runs: int = 3
    sweep_stale_blocks: int = DEFAULT_SWEEP_STALE_BLOCKS

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
        if (
            isinstance(self.sweep_stale_blocks, bool)
            or not isinstance(self.sweep_stale_blocks, int)
            or self.sweep_stale_blocks < 0
        ):
            raise ValueError("sweep stale block allowance must be a non-negative integer")

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
            grandfathered_holds_file=_expanded(
                os.environ.get(
                    "NAK_RECONCILE_GRANDFATHERED_HOLDS",
                    DEFAULT_GRANDFATHERED_HOLDS_FILE,
                )
            ),
            buzz_helper=_expanded(helper) if helper else DEFAULT_BUZZ_HELPER,
            snapshot_attempts=int(os.environ.get("NAK_RECONCILE_SNAPSHOT_ATTEMPTS", "3")),
            snapshot_retry_delay_s=float(
                os.environ.get("NAK_RECONCILE_RETRY_DELAY_S", "0.25")
            ),
            inconclusive_kill_runs=int(
                os.environ.get("NAK_RECONCILE_INCONCLUSIVE_KILL_RUNS", "3")
            ),
            sweep_stale_blocks=int(
                os.environ.get(
                    "NAK_SWEEP_STALE_BLOCKS", str(DEFAULT_SWEEP_STALE_BLOCKS)
                )
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


@dataclass(frozen=True)
class GrandfatheredHold:
    hold_id: str
    amount: int
    payer_account: str
    worker_account: str


def _load_grandfathered_holds(path: Path) -> dict[str, GrandfatheredHold]:
    """Read an operator-pinned exception list without following links."""
    try:
        parent = path.parent.stat()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ReconcileError(
            f"could not inspect grandfathered task hold directory {path.parent}: {exc}"
        ) from exc
    parent_mode = stat.S_IMODE(parent.st_mode)
    if not stat.S_ISDIR(parent.st_mode) or parent_mode & 0o022:
        raise ReconcileError(
            f"grandfathered task hold directory mode is {parent_mode:04o}; "
            "a real, non-group/world-writable directory is required"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ReconcileError(
            f"could not open grandfathered task hold file {path}: {exc}"
        ) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ReconcileError(
                f"grandfathered task hold file is not regular: {path}"
            )
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022:
            raise ReconcileError(
                f"grandfathered task hold file mode is {mode:04o}; "
                "group/world write access is forbidden"
            )
        if info.st_uid != os.getuid():
            raise ReconcileError(
                f"grandfathered task hold file is owned by uid {info.st_uid}; "
                f"expected current uid {os.getuid()}"
            )
        raw = os.read(fd, 1_048_577)
    finally:
        os.close(fd)
    if len(raw) > 1_048_576:
        raise ReconcileError("grandfathered task hold file exceeds 1 MiB")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ReconcileError(
            "grandfathered task hold file must contain ASCII text"
        ) from exc
    holds: dict[str, GrandfatheredHold] = {}
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 4:
            raise ReconcileError(
                f"invalid grandfathered hold on line {line_number} of {path}; "
                "expected: hold_id amount payer_account worker_account"
            )
        hold_id, raw_amount, payer_account, worker_account = fields
        if len(hold_id) != 32 or any(
            character not in "0123456789abcdef" for character in hold_id
        ):
            raise ReconcileError(
                f"invalid hold id on line {line_number} of {path}"
            )
        try:
            amount = int(raw_amount)
        except ValueError as exc:
            raise ReconcileError(
                f"invalid amount on line {line_number} of {path}"
            ) from exc
        if amount <= 0 or str(amount) != raw_amount:
            raise ReconcileError(
                f"invalid amount on line {line_number} of {path}"
            )
        entry = GrandfatheredHold(
            hold_id, amount, payer_account, worker_account
        )
        if hold_id in holds:
            raise ReconcileError(
                f"duplicate hold id on line {line_number} of {path}"
            )
        holds[hold_id] = entry
    return holds


def _replay_funding_backed_balance(
    ledger: dict[str, Any], operator: str, authorization_seq: int,
    authorized_at: int,
) -> int:
    """Replay the store's funding-backed balance immediately before one debit.

    This intentionally uses only raw ledger tables and journal ordering.  It does
    not use ``economic_receipts`` or any LedgerStore calculation, keeping the
    reconciliation proof independent from the implementation it audits.
    """
    prior = [
        row for row in ledger["journal"]
        if int(row["seq"]) < authorization_seq
    ]
    by_seq = {int(row["seq"]): row for row in prior}

    def detail(row: dict[str, Any]) -> dict[str, Any]:
        try:
            value = json.loads(row["detail"])
        except (TypeError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    balance = sum(
        int(row["amount"]) for row in prior if row["account"] == operator
    )

    deposit_journals = {
        (detail(row).get("ref"), row["account"], int(row["amount"]))
        for row in prior if row["kind"] == "deposit"
    }
    deposited = sum(
        int(row["amount"])
        for row in ledger["chain_refs"]
        if row["kind"] == "deposit"
        and row["account"] == operator
        and (row["ref"], row["account"], int(row["amount"])) in deposit_journals
    )

    withdrawal_events: dict[str, set[str]] = {}
    for row in prior:
        if row["kind"] not in {"withdraw_hold", "withdraw", "withdraw_release"}:
            continue
        withdrawal_id = detail(row).get("withdrawal_id")
        if isinstance(withdrawal_id, str):
            withdrawal_events.setdefault(withdrawal_id, set()).add(str(row["kind"]))
    withdrawn = 0
    held = 0
    for row in ledger["withdrawals"]:
        if row["operator"] != operator:
            continue
        events = withdrawal_events.get(str(row["id"]), set())
        if "withdraw_hold" not in events:
            continue
        if "withdraw" in events:
            withdrawn += int(row["amount"])
        elif "withdraw_release" not in events:
            held += int(row["amount"])

    journals_by_receipt: dict[str | None, list[dict[str, Any]]] = {}
    for row in prior:
        journals_by_receipt.setdefault(row["receipt_id"], []).append(row)

    legacy_projection = {
        row["receipt_id"]: int(row["funded"])
        for row in ledger["legacy_funding_projection"]
    }
    legacy_earnings = 0
    legacy_spending = 0
    for receipt in ledger["receipts"]:
        receipt_id = receipt["receipt_id"]
        rows = journals_by_receipt.get(receipt_id, [])
        earns = [row for row in rows if row["kind"] == "earn"]
        spends = [row for row in rows if row["kind"] == "spend"]
        disputed = any(
            row["kind"] in {"dispute_clawback", "dispute_refund"}
            for row in rows
        )
        charged = int(receipt["charged"])
        exact_spend = (
            (charged == 0 and not spends)
            or (
                len(spends) == 1
                and spends[0]["account"] == receipt["requester"]
                and spends[0]["counterparty"] is None
                and int(spends[0]["amount"]) == -charged
                and int(spends[0]["ts"]) == int(receipt["created_at"])
            )
        )
        if (
            receipt["state"] == "legacy_unsigned"
            or legacy_projection.get(receipt_id) != 1
            or disputed
            or not exact_spend
        ):
            continue
        if receipt["requester"] == operator:
            legacy_spending += charged
        legacy_earnings += sum(
            int(row["amount"])
            for row in earns
            if row["account"] == operator
            and int(row["amount"]) > 0
            and authorized_at > int(row["ts"]) + HOLD_S
        )

    spend_holds = {row["hold_id"]: row for row in ledger["spend_holds"]}
    spend_disputed_before: set[str] = set()
    for row in prior:
        if row["kind"] in {"spend_dispute_clawback", "spend_dispute_refund"}:
            hold_id = detail(row).get("hold_id")
            if isinstance(hold_id, str):
                spend_disputed_before.add(hold_id)

    def spend_terminal_before(hold: dict[str, Any]) -> bool:
        terminal = hold["terminal_at"]
        if terminal is None:
            return False
        if int(terminal) < authorized_at:
            return True
        hold_id = str(hold["hold_id"])
        if any(
            isinstance(row["receipt_id"], str)
            and row["receipt_id"].startswith(f"spend-release:{hold_id}:")
            for row in prior
        ):
            return True
        return any(
            row["hold_id"] == hold_id
            and bool(row["final"])
            and int(row["accepted_at"]) == int(terminal)
            and (
                row["credit_journal_seq"] is None
                or int(row["credit_journal_seq"]) < authorization_seq
            )
            for row in ledger["spend_usage_receipts"]
        )

    v2_earnings = 0
    spend_spending = 0
    spend_economic = {
        row["receipt_id"]: row for row in ledger["spend_economic_receipts"]
    }
    usage = {row["receipt_id"]: row for row in ledger["spend_usage_receipts"]}
    workers = {
        (row["hold_id"], row["worker_keyid"]): row
        for row in ledger["spend_hold_workers"]
    }
    for hold_id, hold in spend_holds.items():
        auth_rows = journals_by_receipt.get(f"spend-authorize:{hold_id}", [])
        if (
            hold["payer_account_at_authorize"] != operator
            or int(hold["funded"]) != 1
            or not any(row["kind"] == "spend_authorize_debit" for row in auth_rows)
            or hold_id in spend_disputed_before
        ):
            continue
        accepted = sum(
            int(row["amount"])
            for row in ledger["spend_economic_receipts"]
            if row["hold_id"] == hold_id
            and row["credit_journal_seq"] is not None
            and int(row["credit_journal_seq"]) < authorization_seq
        )
        spend_spending += accepted if spend_terminal_before(hold) else int(hold["max_cost"])

    for receipt_id, economic in spend_economic.items():
        stored = usage.get(receipt_id)
        if stored is None or int(stored["accepted_delta"]) <= 0:
            continue
        hold = spend_holds.get(stored["hold_id"])
        worker = workers.get((stored["hold_id"], stored["worker_keyid"]))
        debit_seq = stored["debit_journal_seq"]
        credit_seq = stored["credit_journal_seq"]
        if (
            hold is None or worker is None or int(hold["funded"]) != 1
            or stored["hold_id"] in spend_disputed_before
            or not spend_terminal_before(hold)
            or hold["terminal_at"] is None
            or authorized_at <= int(hold["terminal_at"]) + HOLD_S
            or debit_seq is None or credit_seq is None
            or int(debit_seq) not in by_seq or int(credit_seq) not in by_seq
        ):
            continue
        try:
            receipt = json.loads(stored["receipt_json"])
            if not isinstance(receipt, dict) or set(receipt) != SPEND_USAGE_FIELDS:
                continue
            canonical = json.dumps(
                receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            )
            unsigned = {key: value for key, value in receipt.items() if key != "receipt_id"}
            expected_id = "sha256:" + hashlib.sha256(
                SPEND_RECEIPT_DOMAIN
                + json.dumps(
                    unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                ).encode()
            ).hexdigest()
            if (
                canonical != stored["receipt_json"]
                or receipt["receipt_id"] != receipt_id
                or expected_id != receipt_id
            ):
                continue
            ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(str(stored["worker_keyid"]))
            ).verify(bytes.fromhex(str(stored["signature"])), canonical.encode())
        except Exception:
            continue
        immutable = {
            "v": 2,
            "kind": "nakshatra-worker-usage",
            "hold_id": stored["hold_id"],
            "claim_response_sha256": worker["claim_response_sha256"],
            "payer_keyid": hold["payer_keyid"],
            "payer_account_at_authorize": hold["payer_account_at_authorize"],
            "worker_keyid": stored["worker_keyid"],
            "worker_account_at_authorize": worker["worker_account_at_authorize"],
            "billable": bool(worker["billable"]),
            "session_id": hold["session_id"],
            "model_id": hold["model_id"],
            "billing_mode": hold["billing_mode"],
            "layer_start": int(worker["layer_start"]),
            "layer_end": int(worker["layer_end"]),
        }
        columns = {
            "sequence": receipt.get("sequence"),
            "cumulative_prompt_tokens": receipt.get("cumulative_prompt_tokens"),
            "cumulative_generated_tokens": receipt.get("cumulative_generated_tokens"),
            "cumulative_token_layers": receipt.get("cumulative_token_layers"),
            "cumulative_cost": receipt.get("cumulative_cost"),
            "final": int(bool(receipt.get("final"))),
        }
        if (
            any(receipt.get(field) != value for field, value in immutable.items())
            or any(stored[field] != value for field, value in columns.items())
        ):
            continue
        try:
            sequence = int(receipt["sequence"])
            prompt = int(receipt["cumulative_prompt_tokens"])
            generated = int(receipt["cumulative_generated_tokens"])
            token_layers = (prompt + generated) * int(worker["layers"])
            cost = token_layers * int(worker["price_multiplier"]) if worker["billable"] else 0
            previous = next(
                (
                    row for row in ledger["spend_usage_receipts"]
                    if row["hold_id"] == stored["hold_id"]
                    and row["worker_keyid"] == stored["worker_keyid"]
                    and int(row["sequence"]) == sequence - 1
                ),
                None,
            ) if sequence > 1 else None
            if sequence < 1 or (
                sequence > 1
                and (
                    previous is None
                    or prompt != int(previous["cumulative_prompt_tokens"])
                    or generated < int(previous["cumulative_generated_tokens"])
                )
            ):
                continue
            previous_cost = 0 if previous is None else int(previous["cumulative_cost"])
            amount = cost - previous_cost
        except (KeyError, TypeError, ValueError):
            continue
        if (
            prompt < 0 or generated < 0 or amount <= 0
            or token_layers != int(stored["cumulative_token_layers"])
            or cost != int(stored["cumulative_cost"])
            or amount != int(stored["accepted_delta"])
            or cost > int(worker["max_cost"])
            or token_layers > int(worker["max_token_layers"])
            or not isinstance(receipt.get("work_completed_at"), int)
            or int(receipt["work_completed_at"]) < int(worker["claimed_at"] or 0)
            or int(receipt["work_completed_at"]) > int(hold["execution_deadline"])
        ):
            continue
        debit = by_seq[int(debit_seq)]
        credit = by_seq[int(credit_seq)]
        expected_detail = json.dumps(
            {
                "hold_id": stored["hold_id"],
                "worker_keyid": stored["worker_keyid"],
                "sequence": sequence,
                "cumulative_cost": cost,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if (
            economic["worker_account"] == operator
            and economic["hold_id"] == hold["hold_id"]
            and economic["payer_account"] == hold["payer_account_at_authorize"]
            and int(economic["amount"]) == amount
            and int(economic["funded"]) == 1
            and int(economic["earned_at"]) == int(stored["accepted_at"])
            and economic["hold_terminal_at"] == hold["terminal_at"]
            and economic["matures_at"] is not None
            and int(economic["matures_at"]) == int(hold["terminal_at"]) + HOLD_S
            and economic["debit_journal_seq"] == debit_seq
            and economic["credit_journal_seq"] == credit_seq
            and debit["kind"] == "spend_settle_debit"
            and debit["receipt_id"] == receipt_id
            and debit["account"] == hold["escrow_account"]
            and debit["counterparty"] == worker["worker_account_at_authorize"]
            and int(debit["amount"]) == -amount
            and int(debit["ts"]) == int(stored["accepted_at"])
            and debit["detail"] == expected_detail
            and credit["kind"] == "spend_earn"
            and credit["receipt_id"] == receipt_id
            and credit["account"] == operator
            and credit["counterparty"] == hold["escrow_account"]
            and int(credit["amount"]) == amount
            and int(credit["ts"]) == int(stored["accepted_at"])
            and credit["detail"] == expected_detail
            and len(journals_by_receipt.get(receipt_id, [])) == 2
        ):
            v2_earnings += amount

    task_holds = {row["hold_id"]: row for row in ledger["task_holds"]}
    refunded_tasks: set[str] = set()
    for row in prior:
        if row["kind"] in {
            "task_refund_credit", "refund_after_submit",
            "task_dispute_refund_credit",
        }:
            hold_id = detail(row).get("hold_id")
            if isinstance(hold_id, str):
                refunded_tasks.add(hold_id)
    task_spending = 0
    for hold_id, hold in task_holds.items():
        auth_rows = journals_by_receipt.get(f"task-authorize:{hold_id}", [])
        if (
            hold["payer_account"] == operator
            and int(hold["funded"]) == 1
            and hold_id not in refunded_tasks
            and any(row["kind"] == "task_authorize_debit" for row in auth_rows)
        ):
            task_spending += int(hold["amount"])

    task_earnings = 0
    for earning in ledger["task_earnings"]:
        hold = task_holds.get(earning["hold_id"])
        debit = by_seq.get(int(earning["debit_journal_seq"]))
        credit = by_seq.get(int(earning["credit_journal_seq"]))
        if (
            hold is None or debit is None or credit is None
            or int(hold["funded"]) != 1
            or hold["worker_account"] != operator
            or authorized_at <= int(earning["matures_at"])
        ):
            continue
        event_id = f"task-pay:{hold['hold_id']}"
        valid_details = {
            json.dumps(
                {"hold_id": hold["hold_id"]}, sort_keys=True, separators=(",", ":")
            ),
            json.dumps(
                {"hold_id": hold["hold_id"], "paid_by_silence": True},
                sort_keys=True, separators=(",", ":"),
            ),
        }
        if hold["resolved_outcome"] == "pay":
            valid_details.add(json.dumps(
                {
                    "hold_id": hold["hold_id"], "resolved_by": "operator",
                    "dispute_reason": hold["dispute_reason"],
                    "resolution_reason": hold["resolution_reason"],
                },
                sort_keys=True, separators=(",", ":"),
            ))
        elif hold["disputed_at"] is not None:
            valid_details.add(json.dumps(
                {
                    "hold_id": hold["hold_id"], "dispute_backstop": True,
                    "dispute_reason": hold["dispute_reason"],
                },
                sort_keys=True, separators=(",", ":"),
            ))
        escrow_balance = sum(
            int(row["amount"])
            for row in prior if row["account"] == hold["escrow_account"]
        )
        if (
            hold["state"] == "paid"
            and hold["terminal_at"] == earning["earned_at"]
            and int(earning["matures_at"]) == int(earning["earned_at"]) + HOLD_S
            and escrow_balance == 0
            and debit["kind"] == "task_pay_debit"
            and debit["receipt_id"] == event_id
            and debit["account"] == hold["escrow_account"]
            and debit["counterparty"] == operator
            and int(debit["amount"]) == -int(hold["amount"])
            and int(debit["ts"]) == int(earning["earned_at"])
            and debit["detail"] in valid_details
            and credit["kind"] == "task_earn"
            and credit["receipt_id"] == event_id
            and credit["account"] == operator
            and credit["counterparty"] == hold["escrow_account"]
            and int(credit["amount"]) == int(hold["amount"])
            and int(credit["ts"]) == int(earning["earned_at"])
            and credit["detail"] == debit["detail"]
            and len(journals_by_receipt.get(event_id, [])) == 2
        ):
            task_earnings += int(hold["amount"])

    entitlement = max(
        0,
        deposited - withdrawn - held
        + legacy_earnings + v2_earnings + task_earnings
        - legacy_spending - spend_spending - task_spending,
    )
    return max(0, min(balance, entitlement))


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
                    "receipts": [
                        dict(row)
                        for row in db.execute("SELECT * FROM receipts ORDER BY receipt_id")
                    ],
                    "legacy_funding_projection": [
                        dict(row)
                        for row in db.execute(
                            "SELECT * FROM legacy_funding_projection ORDER BY receipt_id"
                        )
                    ],
                    "spend_holds": [
                        dict(row)
                        for row in db.execute("SELECT * FROM spend_holds ORDER BY hold_id")
                    ],
                    "spend_hold_workers": [
                        dict(row)
                        for row in db.execute(
                            "SELECT * FROM spend_hold_workers "
                            "ORDER BY hold_id, entry_index"
                        )
                    ],
                    "spend_usage_receipts": [
                        dict(row)
                        for row in db.execute(
                            "SELECT * FROM spend_usage_receipts "
                            "ORDER BY hold_id, worker_keyid, sequence"
                        )
                    ],
                    "spend_economic_receipts": [
                        dict(row)
                        for row in db.execute(
                            "SELECT * FROM spend_economic_receipts ORDER BY receipt_id"
                        )
                    ],
                    "task_holds": [
                        dict(row)
                        for row in db.execute(
                            "SELECT * FROM task_holds ORDER BY hold_id"
                        )
                    ],
                    "task_earnings": [
                        dict(row)
                        for row in db.execute(
                            "SELECT * FROM task_earnings ORDER BY hold_id"
                        )
                    ],
                    "economic_receipts": [
                        dict(row)
                        for row in db.execute(
                            "SELECT * FROM economic_receipts ORDER BY economic_id"
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
                    "chain_sweeps": [
                        dict(row)
                        for row in db.execute(
                            "SELECT * FROM chain_sweeps ORDER BY id"
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
            | {
                row["signature"]
                for row in ledger["chain_sweeps"]
                if row.get("state") in {"sent", "finalized"}
                and isinstance(row.get("signature"), str)
                and row["signature"]
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
                    "transaction statuses differ between primary and confirmation RPCs"
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

    def _sweep_transfer_proof(
        self, row: dict[str, Any], status: dict[str, Any] | None
    ) -> dict[str, Any]:
        proof: dict[str, Any] = {
            "sweep_id": row["id"],
            "operator": row["operator"],
            "token_account": row["token_account"],
            "signature": row["signature"],
            "amount_micro": int(row["amount_micro"]),
            "ledger_state": row["state"],
            "ok": False,
        }
        try:
            signature = row["signature"]
            if not isinstance(signature, str) or not signature:
                raise ReconcileError("sweep has no transaction signature")
            if not isinstance(status, dict):
                raise ReconcileError("sweep transaction has no chain status")
            proof["confirmation_status"] = status.get("confirmationStatus")
            if status.get("confirmationStatus") != "finalized" or status.get("err") is not None:
                raise ReconcileError("sweep transaction is not successfully finalized")
            transaction = self._transaction(signature)
            if not isinstance(transaction, dict):
                raise ReconcileError("finalized sweep transaction body is unavailable")
            meta = transaction.get("meta")
            if not isinstance(meta, dict) or meta.get("err") is not None:
                raise ReconcileError("sweep transaction metadata is absent or failed")
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
                    f"expected exactly one parsed sweep transfer, found {len(transfers)}"
                )
            transfer = transfers[0]
            token_amount = transfer.get("tokenAmount")
            if not isinstance(token_amount, dict):
                raise ReconcileError("sweep is not a TransferChecked instruction")
            if (
                transfer.get("source") != row["token_account"]
                or transfer.get("destination") != self.config.vault_account
                or transfer.get("mint") != self.config.mint
                or token_amount.get("decimals") != USDC_DECIMALS
                or str(token_amount.get("amount")) != str(row["amount_micro"])
            ):
                raise ReconcileError(
                    "sweep source, destination, mint, decimals, or amount differs"
                )
            proof["ok"] = True
        except (KeyError, OSError, RPCError, ReconcileError, TypeError, ValueError) as exc:
            proof["error"] = f"{type(exc).__name__}: {exc}"
        return proof

    def _sweep_provenance(
        self,
        ledger: dict[str, Any],
        statuses: dict[str, dict[str, Any] | None],
        current_block_height: int | None,
    ) -> tuple[list[str], list[dict[str, Any]], dict[str, int], int]:
        errors: list[str] = []
        proofs: list[dict[str, Any]] = []
        swept_by_account: dict[str, int] = {}
        total = 0
        for row in ledger["chain_sweeps"]:
            state = row["state"]
            if state == "failed":
                continue
            status = statuses.get(row["signature"])
            status_finalized = (
                isinstance(status, dict)
                and status.get("confirmationStatus") == "finalized"
            )
            chain_finalized = (
                status_finalized
                and status.get("err") is None
            )
            if state == "sent":
                stale = (
                    current_block_height is not None
                    and current_block_height
                    > int(row["last_valid_block_height"])
                    + self.config.sweep_stale_blocks
                )
                if status_finalized and status.get("err") is not None:
                    errors.append(f"sent sweep {row['id']} finalized with an error")
                    continue
                if stale:
                    errors.append(f"stale in-flight sweep {row['id']}")
                if not chain_finalized:
                    continue
            proof = self._sweep_transfer_proof(row, status)
            proofs.append(proof)
            if not proof["ok"]:
                errors.append(f"{row['id']}: finalized sweep proof is missing or mismatched")
                continue
            amount_credits = int(row["amount_micro"]) * RATE
            account = str(row["token_account"])
            swept_by_account[account] = swept_by_account.get(account, 0) + amount_credits
            total += amount_credits
        return errors, proofs, swept_by_account, total

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
        swept_by_account: dict[str, int],
        verified_swept_total: int,
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
        addresses = {
            row["token_account"] for row in ledger["deposit_accounts"]
        } | {self.config.vault_account}
        for address in sorted(addresses):
            on_chain = token_amounts.get(address, 0) * RATE
            if address == self.config.vault_account:
                expected = (
                    indexed.get(address, 0)
                    + verified_swept_total
                    - verified_vault_outflow
                )
            else:
                expected = indexed.get(address, 0) - swept_by_account.get(address, 0)
            if expected < 0:
                errors.append(
                    f"{address}: verified outflow exceeds indexed deposits and sweeps"
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
        # Excess alone can be deposits the indexer has not reached yet.  A
        # deficit is stable evidence of unexplained outflow, so another
        # account's excess must not downgrade the whole snapshot to lag.
        if errors and lag:
            errors.extend(lag)
            lag = []
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
                row.get("approval_ref") is None
                and row.get("approval_ts") is None
                and row.get("approval_expires_ts") is None
                and row.get("approved_withdrawal_id") is None
                and row.get("approved_amount") is None
                and row.get("approved_address") is None
            )
            approval_present = (
                isinstance(row.get("approval_ref"), str)
                and bool(row["approval_ref"])
                and isinstance(row.get("approval_ts"), int)
            )
            if approval_present and str(row["approval_ref"]).startswith("human:"):
                approval_present = (
                    isinstance(row.get("approval_expires_ts"), int)
                    and row.get("approved_withdrawal_id") == withdrawal_id
                    and row.get("approved_amount") == amount
                    and row.get("approved_address") == row["address"]
                )
            elif approval_present:
                approval_present = all(
                    row.get(field) is None
                    for field in (
                        "approval_expires_ts",
                        "approved_withdrawal_id",
                        "approved_amount",
                        "approved_address",
                    )
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

    @staticmethod
    def _spend_checks(
        ledger: dict[str, Any],
        grandfathered_holds: dict[str, GrandfatheredHold] | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Independently reconcile N2 receipts, pricing, escrow, and maturity."""
        grandfathered_holds = grandfathered_holds or {}
        errors: dict[str, list[str]] = {
            "spend_usage_linkage": [],
            "spend_pricing": [],
            "spend_caps": [],
            "spend_liabilities": [],
            "spend_release_lifecycle": [],
            "spend_closed_balances": [],
            "economic_namespaces": [],
            "economic_receipt_view": [],
        }
        balances = {row["id"]: int(row["balance"]) for row in ledger["accounts"]}
        journals = {int(row["seq"]): row for row in ledger["journal"]}
        journals_by_receipt: dict[str | None, list[dict[str, Any]]] = {}
        for row in ledger["journal"]:
            journals_by_receipt.setdefault(row["receipt_id"], []).append(row)
        settlement_journal_seqs = {
            int(row["seq"])
            for row in ledger["journal"]
            if row["kind"] in {"spend_settle_debit", "spend_earn"}
        }
        linked_journal_seqs: set[int] = set()
        dispute_journal_seqs = {
            int(row["seq"])
            for row in ledger["journal"]
            if row["kind"] in {"spend_dispute_clawback", "spend_dispute_refund"}
        }
        linked_dispute_journal_seqs: set[int] = set()
        holds = {row["hold_id"]: row for row in ledger["spend_holds"]}
        release_events_by_hold: dict[str, dict[str, list[dict[str, Any]]]] = {}
        release_kinds = {"spend_release_debit", "spend_release_credit"}
        for event_id, event_rows in journals_by_receipt.items():
            release_rows = [row for row in event_rows if row["kind"] in release_kinds]
            if not release_rows:
                continue
            try:
                detail = json.loads(release_rows[0]["detail"])
                release_hold_id = detail["hold_id"]
            except (KeyError, TypeError, json.JSONDecodeError):
                errors["spend_release_lifecycle"].append(
                    f"{event_id}: release journal has malformed hold detail"
                )
                continue
            if not isinstance(event_id, str) or release_hold_id not in holds:
                errors["spend_release_lifecycle"].append(
                    f"{event_id}: release journal has no spend hold"
                )
                continue
            release_events_by_hold.setdefault(release_hold_id, {})[event_id] = event_rows
        workers = {
            (row["hold_id"], row["worker_keyid"]): row
            for row in ledger["spend_hold_workers"]
        }
        workers_by_hold: dict[str, list[dict[str, Any]]] = {}
        for row in ledger["spend_hold_workers"]:
            workers_by_hold.setdefault(row["hold_id"], []).append(row)
        usage_by_entry: dict[tuple[str, str], list[dict[str, Any]]] = {}
        verified_entry_summaries: dict[tuple[str, str], dict[str, Any]] = {}
        verified_v2_economic_ids: set[str] = set()
        usage_cardinality: dict[str, int] = {}
        economic_cardinality: dict[str, int] = {}
        for row in ledger["spend_usage_receipts"]:
            receipt_id = row["receipt_id"]
            usage_cardinality[receipt_id] = usage_cardinality.get(receipt_id, 0) + 1
        for row in ledger["spend_economic_receipts"]:
            receipt_id = row["receipt_id"]
            economic_cardinality[receipt_id] = (
                economic_cardinality.get(receipt_id, 0) + 1
            )
        cardinality_mismatches = sorted(
            receipt_id
            for receipt_id in set(usage_cardinality) | set(economic_cardinality)
            if usage_cardinality.get(receipt_id, 0) != 1
            or economic_cardinality.get(receipt_id, 0) != 1
        )
        if cardinality_mismatches:
            receipt_id = cardinality_mismatches[0]
            errors["economic_receipt_view"].append(
                f"{receipt_id}: raw v2 cardinality requires exactly one usage row "
                f"and one economic row (usage={usage_cardinality.get(receipt_id, 0)}, "
                f"economic={economic_cardinality.get(receipt_id, 0)})"
            )
        legacy_ids = {row["receipt_id"] for row in ledger["receipts"]}
        usage_ids = {row["receipt_id"] for row in ledger["spend_usage_receipts"]}
        overlap = sorted(legacy_ids & usage_ids)
        if overlap:
            errors["economic_namespaces"].append(
                f"v1/v2 receipt id overlap: {overlap[0]}"
            )

        economic_rows = {
            row["economic_id"]: row for row in ledger["economic_receipts"]
        }
        spend_economic = {
            row["receipt_id"]: row for row in ledger["spend_economic_receipts"]
        }
        for receipt in ledger["spend_usage_receipts"]:
            key = (receipt["hold_id"], receipt["worker_keyid"])
            usage_by_entry.setdefault(key, []).append(receipt)

        for key, rows in usage_by_entry.items():
            entry = workers.get(key)
            hold = holds.get(key[0])
            if entry is None or hold is None:
                errors["spend_usage_linkage"].append(
                    f"{key[0]}/{key[1]}: receipt has no hold entry"
                )
                continue
            previous_cost = 0
            previous_prompt = 0
            previous_generated = 0
            entry_verified = True
            verified_last: dict[str, Any] | None = None
            for expected_sequence, stored in enumerate(rows, 1):
                receipt_error_count = sum(
                    len(errors[name])
                    for name in ("spend_usage_linkage", "spend_pricing", "spend_caps")
                )
                economic_error_count = len(errors["economic_receipt_view"])
                rid = stored["receipt_id"]
                if int(stored["sequence"]) != expected_sequence:
                    errors["spend_usage_linkage"].append(
                        f"{rid}: non-contiguous sequence"
                    )
                try:
                    receipt = json.loads(stored["receipt_json"])
                except (TypeError, json.JSONDecodeError):
                    receipt = None
                if not isinstance(receipt, dict) or set(receipt) != SPEND_USAGE_FIELDS:
                    errors["spend_usage_linkage"].append(f"{rid}: invalid receipt JSON")
                    entry_verified = False
                    continue
                canonical = json.dumps(
                    receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                )
                if stored["receipt_json"] != canonical:
                    errors["spend_usage_linkage"].append(
                        f"{rid}: stored receipt JSON is not canonical"
                    )
                unsigned = {k: v for k, v in receipt.items() if k != "receipt_id"}
                canonical_unsigned = json.dumps(
                    unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ).encode()
                expected_id = "sha256:" + hashlib.sha256(
                    SPEND_RECEIPT_DOMAIN + canonical_unsigned
                ).hexdigest()
                if expected_id != rid or receipt.get("receipt_id") != rid:
                    errors["spend_usage_linkage"].append(f"{rid}: domain hash mismatch")
                try:
                    pubkey = bytes.fromhex(key[1])
                    signature = bytes.fromhex(stored["signature"])
                    canonical_bytes = canonical.encode()
                    ed25519.Ed25519PublicKey.from_public_bytes(pubkey).verify(
                        signature, canonical_bytes
                    )
                except Exception:
                    errors["spend_usage_linkage"].append(f"{rid}: signature mismatch")

                immutable = {
                    "v": 2,
                    "kind": "nakshatra-worker-usage",
                    "hold_id": key[0],
                    "claim_response_sha256": entry["claim_response_sha256"],
                    "payer_keyid": hold["payer_keyid"],
                    "payer_account_at_authorize": hold["payer_account_at_authorize"],
                    "worker_keyid": key[1],
                    "worker_account_at_authorize": entry["worker_account_at_authorize"],
                    "billable": bool(entry["billable"]),
                    "session_id": hold["session_id"],
                    "model_id": hold["model_id"],
                    "billing_mode": hold["billing_mode"],
                    "layer_start": int(entry["layer_start"]),
                    "layer_end": int(entry["layer_end"]),
                }
                if any(receipt.get(field) != value for field, value in immutable.items()):
                    errors["spend_usage_linkage"].append(
                        f"{rid}: receipt differs from immutable hold snapshot"
                    )
                stored_fields = {
                    "hold_id": key[0],
                    "worker_keyid": key[1],
                    "sequence": receipt.get("sequence"),
                    "cumulative_prompt_tokens": receipt.get("cumulative_prompt_tokens"),
                    "cumulative_generated_tokens": receipt.get("cumulative_generated_tokens"),
                    "cumulative_token_layers": receipt.get("cumulative_token_layers"),
                    "cumulative_cost": receipt.get("cumulative_cost"),
                    "final": int(bool(receipt.get("final"))),
                }
                if any(stored[field] != value for field, value in stored_fields.items()):
                    errors["spend_usage_linkage"].append(
                        f"{rid}: stored receipt columns differ from signed receipt"
                    )
                if (
                    not isinstance(receipt.get("work_completed_at"), int)
                    or receipt["work_completed_at"] < int(entry["claimed_at"] or 0)
                    or receipt["work_completed_at"] > int(hold["execution_deadline"])
                ):
                    errors["spend_usage_linkage"].append(
                        f"{rid}: work completion is outside the claimed execution window"
                    )
                if bool(receipt.get("final")) and expected_sequence != len(rows):
                    errors["spend_usage_linkage"].append(
                        f"{rid}: only the final verified receipt may set final"
                    )

                prompt = int(receipt.get("cumulative_prompt_tokens", -1))
                generated_tokens = int(receipt.get("cumulative_generated_tokens", -1))
                layers = int(entry["layer_end"]) - int(entry["layer_start"])
                token_layers = (prompt + generated_tokens) * layers
                cost = token_layers * int(entry["price_multiplier"]) if entry["billable"] else 0
                if (
                    token_layers != receipt.get("cumulative_token_layers")
                    or cost != receipt.get("cumulative_cost")
                    or token_layers != int(stored["cumulative_token_layers"])
                    or cost != int(stored["cumulative_cost"])
                ):
                    errors["spend_pricing"].append(f"{rid}: recomputed pricing differs")
                if prompt < previous_prompt or generated_tokens < previous_generated:
                    errors["spend_pricing"].append(f"{rid}: cumulative usage regressed")
                if expected_sequence > 1 and prompt != previous_prompt:
                    errors["spend_pricing"].append(
                        f"{rid}: prompt usage changed after the first receipt"
                    )
                delta = cost - previous_cost
                if delta != int(stored["accepted_delta"]):
                    errors["spend_pricing"].append(f"{rid}: accepted delta differs")
                if cost > int(entry["max_cost"]) or token_layers > int(entry["max_token_layers"]):
                    errors["spend_caps"].append(f"{rid}: cumulative charge exceeds cap")

                debit_seq = stored["debit_journal_seq"]
                credit_seq = stored["credit_journal_seq"]
                receipt_journals = journals_by_receipt.get(rid, [])
                if delta == 0:
                    if debit_seq is not None or credit_seq is not None:
                        errors["spend_usage_linkage"].append(
                            f"{rid}: zero delta has journal links"
                        )
                    if receipt_journals:
                        errors["spend_usage_linkage"].append(
                            f"{rid}: zero delta has economic journal rows"
                        )
                else:
                    debit = journals.get(int(debit_seq)) if debit_seq is not None else None
                    credit = journals.get(int(credit_seq)) if credit_seq is not None else None
                    if debit_seq is not None:
                        linked_journal_seqs.add(int(debit_seq))
                    if credit_seq is not None:
                        linked_journal_seqs.add(int(credit_seq))
                    expected_debit = (
                        debit is not None
                        and debit["kind"] == "spend_settle_debit"
                        and debit["receipt_id"] == rid
                        and debit["account"] == hold["escrow_account"]
                        and debit["counterparty"] == entry["worker_account_at_authorize"]
                        and int(debit["amount"]) == -delta
                    )
                    expected_credit = (
                        credit is not None
                        and credit["kind"] == "spend_earn"
                        and credit["receipt_id"] == rid
                        and credit["account"] == entry["worker_account_at_authorize"]
                        and credit["counterparty"] == hold["escrow_account"]
                        and int(credit["amount"]) == delta
                    )
                    if not expected_debit or not expected_credit:
                        errors["spend_usage_linkage"].append(
                            f"{rid}: expected one matched hold debit and worker credit"
                        )
                    expected_detail = {
                        "hold_id": key[0],
                        "worker_keyid": key[1],
                        "sequence": expected_sequence,
                        "cumulative_cost": cost,
                    }
                    for journal_row in (debit, credit):
                        try:
                            detail = json.loads(journal_row["detail"]) if journal_row else None
                        except (TypeError, json.JSONDecodeError):
                            detail = None
                        if detail != expected_detail or (
                            journal_row is not None
                            and int(journal_row["ts"]) != int(stored["accepted_at"])
                        ):
                            errors["spend_usage_linkage"].append(
                                f"{rid}: settlement journal detail or time differs"
                            )
                            break
                    expected_seqs = {
                        int(value) for value in (debit_seq, credit_seq)
                        if value is not None
                    }
                    if {int(row["seq"]) for row in receipt_journals} != expected_seqs:
                        errors["spend_usage_linkage"].append(
                            f"{rid}: second direct debit/credit or unlinked journal row"
                        )
                economic = spend_economic.get(rid)
                view = economic_rows.get(f"v2:{rid}")
                if economic is None or view is None:
                    errors["economic_receipt_view"].append(
                        f"{rid}: missing shared economic row"
                    )
                else:
                    terminal = hold["terminal_at"]
                    maturity = None if terminal is None else int(terminal) + HOLD_S
                    expected = {
                        "hold_id": key[0],
                        "payer_account": hold["payer_account_at_authorize"],
                        "worker_account": entry["worker_account_at_authorize"],
                        "amount": delta,
                        "funded": int(hold["funded"]),
                        "hold_terminal_at": terminal,
                        "matures_at": maturity,
                        "earned_at": int(stored["accepted_at"]),
                        "debit_journal_seq": debit_seq,
                        "credit_journal_seq": credit_seq,
                    }
                    if any(economic[field] != value for field, value in expected.items()):
                        errors["economic_receipt_view"].append(
                            f"{rid}: economic metadata differs from receipt"
                        )
                    if any(view[field] != economic[field] for field in (
                        "hold_id", "payer_account", "worker_account", "amount",
                        "funded", "hold_terminal_at", "matures_at", "dispute_state",
                        "debit_journal_seq", "credit_journal_seq",
                    )):
                        errors["economic_receipt_view"].append(
                            f"{rid}: normalized view differs from source row"
                        )
                    if view["eligible_at"] != (
                        None if maturity is None else maturity + 1
                    ):
                        errors["economic_receipt_view"].append(
                            f"{rid}: v2 eligibility boundary differs from maturity policy"
                        )
                    dispute_rows = journals_by_receipt.get(f"spend-dispute:{rid}", [])
                    linked_dispute_journal_seqs.update(
                        int(row["seq"]) for row in dispute_rows
                        if row["kind"] in {"spend_dispute_clawback", "spend_dispute_refund"}
                    )
                    if economic["dispute_state"] == "clawed_back":
                        if hold["state"] != "disputed":
                            errors["economic_receipt_view"].append(
                                f"{rid}: clawed earning belongs to a nondisputed hold"
                            )
                        dispute_ok = delta == 0 and not dispute_rows
                        if delta > 0:
                            dispute_detail = json.dumps(
                                {"hold_id": key[0], "receipt_id": rid},
                                sort_keys=True,
                                separators=(",", ":"),
                            )
                            dispute_times = {int(row["ts"]) for row in dispute_rows}
                            dispute_ok = len(dispute_rows) == 2 and {
                                (
                                    row["kind"], row["account"], row["counterparty"],
                                    int(row["amount"]), row["detail"],
                                )
                                for row in dispute_rows
                            } == {
                                ("spend_dispute_clawback", entry["worker_account_at_authorize"],
                                 hold["payer_account_at_authorize"], -delta, dispute_detail),
                                ("spend_dispute_refund", hold["payer_account_at_authorize"],
                                 entry["worker_account_at_authorize"], delta, dispute_detail),
                            } and len(dispute_times) == 1 and hold["terminal_at"] is not None
                            if dispute_ok:
                                dispute_at = next(iter(dispute_times))
                                dispute_ok = (
                                    int(hold["terminal_at"]) <= dispute_at
                                    <= int(hold["terminal_at"]) + HOLD_S
                                )
                        if not dispute_ok:
                            errors["economic_receipt_view"].append(
                                f"{rid}: dispute state lacks equal-and-opposite journals"
                            )
                    elif dispute_rows or hold["state"] == "disputed":
                        errors["economic_receipt_view"].append(
                            f"{rid}: undisputed earning has dispute journals"
                        )
                previous_cost = cost
                previous_prompt = prompt
                previous_generated = generated_tokens
                if sum(
                    len(errors[name])
                    for name in ("spend_usage_linkage", "spend_pricing", "spend_caps")
                ) != receipt_error_count or (
                    len(errors["economic_receipt_view"]) != economic_error_count
                ):
                    entry_verified = False
                elif entry_verified:
                    verified_v2_economic_ids.add(f"v2:{rid}")
                    verified_last = {
                        "receipt_id": rid,
                        "sequence": expected_sequence,
                        "prompt": prompt,
                        "generated": generated_tokens,
                        "token_layers": token_layers,
                        "cost": cost,
                        "final": bool(receipt["final"]),
                        "accepted_at": int(stored["accepted_at"]),
                    }

            if entry_verified and verified_last is not None:
                verified_entry_summaries[key] = verified_last
                expected_summary = {
                    "receipt_sequence": verified_last["sequence"],
                    "last_receipt_id": verified_last["receipt_id"],
                    "cumulative_prompt_tokens": verified_last["prompt"],
                    "cumulative_generated_tokens": verified_last["generated"],
                    "cumulative_token_layers": verified_last["token_layers"],
                    "cumulative_cost": verified_last["cost"],
                    "final": int(verified_last["final"]),
                    "final_receipt_id": (
                        verified_last["receipt_id"] if verified_last["final"] else None
                    ),
                }
                if any(entry[field] != value for field, value in expected_summary.items()):
                    errors["spend_usage_linkage"].append(
                        f"{key[0]}/{key[1]}: entry summary differs from final verified receipt"
                    )

        derived_entry_states: dict[tuple[str, str], str] = {}
        for key, entry in workers.items():
            hold = holds.get(key[0])
            summary = verified_entry_summaries.get(key)
            if key not in usage_by_entry:
                empty_summary = {
                    "receipt_sequence": 0,
                    "last_receipt_id": None,
                    "cumulative_prompt_tokens": 0,
                    "cumulative_generated_tokens": 0,
                    "cumulative_token_layers": 0,
                    "cumulative_cost": 0,
                    "final": 0,
                    "final_receipt_id": None,
                }
                if any(entry[field] != value for field, value in empty_summary.items()):
                    errors["spend_usage_linkage"].append(
                        f"{key[0]}/{key[1]}: receipt-free entry has nonzero receipt summary"
                    )
            if summary is not None and summary["final"]:
                state = "final"
                if entry["finalized_at"] != summary["accepted_at"]:
                    errors["spend_usage_linkage"].append(
                        f"{key[0]}/{key[1]}: finalization time differs from final receipt"
                    )
            elif (
                hold is not None
                and (
                    hold["state"] == "expired"
                    or (
                        hold["state"] == "disputed"
                        and bool(journals_by_receipt.get(f"spend-release:{key[0]}:expired"))
                    )
                )
                and hold["terminal_at"] is not None
                and entry["finalized_at"] == hold["terminal_at"]
            ):
                state = "expired"
            elif entry["claimed_at"] is not None:
                state = "claimed"
            elif entry["finalized_at"] is not None:
                state = "abandoned"
            else:
                state = "planned"
            derived_entry_states[key] = state
            if entry["state"] != state:
                errors["spend_usage_linkage"].append(
                    f"{key[0]}/{key[1]}: entry state {entry['state']} != derived {state}"
                )

        orphan_settlement = sorted(settlement_journal_seqs - linked_journal_seqs)
        if orphan_settlement:
            errors["spend_usage_linkage"].append(
                f"orphan or duplicate spend settlement journal seq {orphan_settlement[0]}"
            )
        orphan_dispute = sorted(
            dispute_journal_seqs - linked_dispute_journal_seqs
        )
        if orphan_dispute:
            errors["economic_receipt_view"].append(
                f"orphan spend dispute journal seq {orphan_dispute[0]}"
            )

        for hold_id, hold in holds.items():
            own_workers = workers_by_hold.get(hold_id, [])
            recomputed_cap = sum(
                ((int(row["max_prompt_tokens"]) + int(row["max_output_tokens"]))
                 * int(row["layers"]) * int(row["price_multiplier"]))
                if row["billable"] else 0
                for row in own_workers
            )
            if recomputed_cap != int(hold["max_cost"]):
                errors["spend_pricing"].append(f"{hold_id}: hold cap pricing differs")
            auth_rows = journals_by_receipt.get(f"spend-authorize:{hold_id}", [])
            auth_ok = int(hold["max_cost"]) == 0 and not auth_rows
            if int(hold["max_cost"]) > 0:
                auth_ok = len(auth_rows) == 2 and {
                    (row["account"], row["counterparty"], int(row["amount"]))
                    for row in auth_rows
                } == {
                    (hold["payer_account_at_authorize"], hold["escrow_account"], -int(hold["max_cost"])),
                    (hold["escrow_account"], hold["payer_account_at_authorize"], int(hold["max_cost"])),
                }
            if not auth_ok:
                errors["spend_usage_linkage"].append(
                    f"{hold_id}: payer-funded authorization journal is inconsistent"
                )

            for event_id, event_rows in release_events_by_hold.get(hold_id, {}).items():
                prefix = f"spend-release:{hold_id}:"
                suffix = event_id[len(prefix):] if event_id.startswith(prefix) else ""
                event_ts = int(event_rows[0]["ts"])
                reason: str | None = None
                expected_amount: int | None = None
                lifecycle_ok = False
                if suffix == "settled":
                    reason = "settled"
                    expected_amount = sum(
                        int(row["max_cost"])
                        - int(verified_entry_summaries.get(
                            (hold_id, row["worker_keyid"]), {"cost": 0}
                        )["cost"])
                        for row in own_workers
                        if derived_entry_states.get((hold_id, row["worker_keyid"]))
                        == "final"
                    )
                    lifecycle_ok = (
                        hold["state"] in {"settled", "disputed"}
                        and hold["terminal_at"] == event_ts
                        and all(
                            derived_entry_states.get((hold_id, row["worker_keyid"]))
                            in {"final", "abandoned"}
                            for row in own_workers
                        )
                    )
                elif suffix == "expired":
                    reason = "settlement_deadline"
                    expected_amount = sum(
                        int(row["max_cost"])
                        - int(verified_entry_summaries.get(
                            (hold_id, row["worker_keyid"]), {"cost": 0}
                        )["cost"])
                        for row in own_workers
                        if derived_entry_states.get((hold_id, row["worker_keyid"]))
                        in {"expired", "final"}
                    )
                    lifecycle_ok = (
                        hold["state"] in {"expired", "disputed"}
                        and hold["terminal_at"] == event_ts
                        and event_ts >= int(hold["settlement_deadline"])
                    )
                elif suffix == "cancelled":
                    reason = "cancelled"
                    expected_amount = sum(int(row["max_cost"]) for row in own_workers)
                    lifecycle_ok = (
                        hold["state"] in {"cancelled", "disputed"}
                        and hold["terminal_at"] == event_ts
                        and all(row["claimed_at"] is None for row in own_workers)
                    )
                elif suffix == "execution-expiry":
                    reason = "execution_deadline"
                    expired_entries = [
                        row for row in own_workers
                        if derived_entry_states.get((hold_id, row["worker_keyid"]))
                        == "abandoned"
                        and row["claimed_at"] is None
                        and row["finalized_at"] == event_ts
                    ]
                    expected_amount = sum(int(row["max_cost"]) for row in expired_entries)
                    lifecycle_ok = bool(expired_entries) and event_ts >= int(
                        hold["execution_deadline"]
                    )
                elif suffix.endswith(":abandoned"):
                    worker_keyid = suffix[:-len(":abandoned")]
                    row = workers.get((hold_id, worker_keyid))
                    reason = "abandoned"
                    if row is not None:
                        expected_amount = int(row["max_cost"])
                        lifecycle_ok = (
                            derived_entry_states.get((hold_id, worker_keyid))
                            == "abandoned"
                            and row["claimed_at"] is None
                            and row["finalized_at"] == event_ts
                        )

                expected_detail = {"hold_id": hold_id, "reason": reason}
                if reason == "abandoned":
                    expected_detail["worker_keyid"] = suffix[:-len(":abandoned")]
                rows_ok = expected_amount is not None and expected_amount > 0
                if rows_ok:
                    rows_ok = len(event_rows) == 2 and {
                        (
                            row["kind"], row["account"], row["counterparty"],
                            int(row["amount"]), int(row["ts"]), row["detail"],
                        )
                        for row in event_rows
                    } == {
                        (
                            "spend_release_debit", hold["escrow_account"],
                            hold["payer_account_at_authorize"], -expected_amount,
                            event_ts,
                            json.dumps(expected_detail, sort_keys=True, separators=(",", ":")),
                        ),
                        (
                            "spend_release_credit", hold["payer_account_at_authorize"],
                            hold["escrow_account"], expected_amount, event_ts,
                            json.dumps(expected_detail, sort_keys=True, separators=(",", ":")),
                        ),
                    }
                if not lifecycle_ok or not rows_ok:
                    errors["spend_release_lifecycle"].append(
                        f"{event_id}: release does not match its exact lifecycle transition"
                    )
            verified_spend = sum(
                int(verified_entry_summaries.get(
                    (hold_id, row["worker_keyid"]), {"cost": 0}
                )["cost"])
                for row in own_workers
            )
            journal_releases = -sum(
                int(row["amount"])
                for event_rows in release_events_by_hold.get(hold_id, {}).values()
                for row in event_rows
                if row["kind"] == "spend_release_debit"
            )
            provenance_balance = int(hold["max_cost"]) - verified_spend - journal_releases
            if balances.get(hold["escrow_account"], 0) != provenance_balance:
                errors["spend_release_lifecycle"].append(
                    f"{hold_id}: escrow balance does not follow authorization, verified usage, and releases"
                )
            liability = sum(
                int(row["max_cost"])
                - int(verified_entry_summaries.get(
                    (hold_id, row["worker_keyid"]), {"cost": 0}
                )["cost"])
                for row in own_workers
                if derived_entry_states.get((hold_id, row["worker_keyid"]))
                in {"planned", "claimed", "final"}
            )
            expected_balance = 0 if hold["state"] in {
                "settled", "expired", "cancelled", "disputed"
            } else liability
            actual_balance = balances.get(hold["escrow_account"], 0)
            if actual_balance != expected_balance:
                errors["spend_liabilities"].append(
                    f"{hold_id}: escrow {actual_balance} != liability {expected_balance}"
                )
            if hold["state"] in {"settled", "expired", "cancelled", "disputed"} and actual_balance:
                errors["spend_closed_balances"].append(
                    f"{hold_id}: closed hold has orphan balance {actual_balance}"
                )
        hold_accounts = {row["escrow_account"] for row in holds.values()}
        for account, balance in balances.items():
            if account.startswith("__spend_hold__:") and account not in hold_accounts:
                errors["spend_liabilities"].append(
                    f"orphan spend hold account {account} has balance {balance}"
                )

        expected_v2_ids = {f"v2:{receipt_id}" for receipt_id in usage_ids}
        source_v2_ids = {
            f"v2:{row['receipt_id']}" for row in ledger["spend_economic_receipts"]
        }
        view_v2_ids = {
            economic_id for economic_id, row in economic_rows.items()
            if row["namespace"] == "v2"
        }
        if source_v2_ids != expected_v2_ids or view_v2_ids != expected_v2_ids:
            errors["economic_receipt_view"].append(
                "v2 economic rows do not exactly and bidirectionally match usage receipts"
            )
        for economic_id in sorted(source_v2_ids - verified_v2_economic_ids):
            errors["economic_receipt_view"].append(
                f"{economic_id}: v2 economic row is not backed by a verified "
                "signed usage receipt, accepted delta, and exact journal pair"
            )
        paid_task_holds = {
            row["hold_id"]: row for row in ledger["task_holds"]
            if row["state"] == "paid"
        }
        task_earnings = {
            row["hold_id"]: row for row in ledger["task_earnings"]
        }
        expected_task_ids = {
            f"task:{hold_id}" for hold_id in paid_task_holds
        }
        view_task_rows = [
            row for row in ledger["economic_receipts"]
            if row["namespace"] == "task"
        ]
        view_task_ids = {row["economic_id"] for row in view_task_rows}
        if (
            view_task_ids != expected_task_ids
            or len(view_task_rows) != len(expected_task_ids)
        ):
            errors["economic_receipt_view"].append(
                "task economic rows do not exactly and bidirectionally match paid holds"
            )
        if set(task_earnings) != set(paid_task_holds):
            errors["economic_receipt_view"].append(
                "task earning rows do not exactly and bidirectionally match paid holds"
            )

        accepted_grandfathers: dict[str, int] = {}
        for hold_id, hold in paid_task_holds.items():
            economic_id = f"task:{hold_id}"
            authorization_id = f"task-authorize:{hold_id}"
            event_id = f"task-pay:{hold_id}"
            view = economic_rows.get(economic_id)
            authorization_rows = journals_by_receipt.get(authorization_id, [])
            authorization_debits = [
                row for row in authorization_rows
                if row["kind"] == "task_authorize_debit"
            ]
            authorization_credits = [
                row for row in authorization_rows
                if row["kind"] == "task_authorize_credit"
            ]
            authorization_detail = json.dumps(
                {"hold_id": hold_id}, sort_keys=True, separators=(",", ":")
            )
            authorization_ok = (
                len(authorization_rows) == 2
                and len(authorization_debits) == 1
                and len(authorization_credits) == 1
                and authorization_debits[0]["account"] == hold["payer_account"]
                and authorization_debits[0]["counterparty"] == hold["escrow_account"]
                and int(authorization_debits[0]["amount"]) == -int(hold["amount"])
                and int(authorization_debits[0]["ts"]) == int(hold["authorized_at"])
                and authorization_debits[0]["detail"] == authorization_detail
                and authorization_credits[0]["account"] == hold["escrow_account"]
                and authorization_credits[0]["counterparty"] == hold["payer_account"]
                and int(authorization_credits[0]["amount"]) == int(hold["amount"])
                and int(authorization_credits[0]["ts"]) == int(hold["authorized_at"])
                and authorization_credits[0]["detail"] == authorization_detail
            )
            reconstructed_funded: bool | None = None
            if authorization_ok:
                backed_before = _replay_funding_backed_balance(
                    ledger,
                    str(hold["payer_account"]),
                    int(authorization_debits[0]["seq"]),
                    int(hold["authorized_at"]),
                )
                reconstructed_funded = backed_before >= int(hold["amount"])
            if reconstructed_funded is None:
                authorization_ok = False
                errors["economic_receipt_view"].append(
                    f"{economic_id}: task authorization journal provenance is inconsistent"
                )

            stored_funded = int(hold["funded"])
            listed_entry = grandfathered_holds.get(hold_id)
            listed = listed_entry is not None
            grandfather_eligible = (
                authorization_ok
                and stored_funded == 1
                and reconstructed_funded is False
            )
            if listed:
                entry_matches = (
                    listed_entry.amount == int(hold["amount"])
                    and listed_entry.payer_account == hold["payer_account"]
                    and listed_entry.worker_account == hold["worker_account"]
                )
                if grandfather_eligible and entry_matches:
                    accepted_grandfathers[hold_id] = int(hold["amount"])
                else:
                    errors["economic_receipt_view"].append(
                        f"{economic_id}: grandfather list entry is stale, mismatched, "
                        "or not eligible"
                    )
            elif authorization_ok and stored_funded != int(reconstructed_funded):
                errors["economic_receipt_view"].append(
                    f"{economic_id}: stored task funding differs from authorization provenance"
                )

            earning = task_earnings.get(hold_id)
            event_rows = journals_by_receipt.get(event_id, [])
            terminal = hold["terminal_at"]
            debit = (
                journals.get(int(earning["debit_journal_seq"]))
                if earning is not None and earning["debit_journal_seq"] is not None
                else None
            )
            credit = (
                journals.get(int(earning["credit_journal_seq"]))
                if earning is not None and earning["credit_journal_seq"] is not None
                else None
            )
            valid_details = {
                json.dumps(
                    {"hold_id": hold_id}, sort_keys=True, separators=(",", ":")
                ),
                json.dumps(
                    {"hold_id": hold_id, "paid_by_silence": True},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            }
            if hold["resolved_outcome"] == "pay":
                valid_details.add(
                    json.dumps(
                        {
                            "hold_id": hold_id,
                            "resolved_by": "operator",
                            "dispute_reason": hold["dispute_reason"],
                            "resolution_reason": hold["resolution_reason"],
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            elif hold["disputed_at"] is not None:
                valid_details.add(
                    json.dumps(
                        {
                            "hold_id": hold_id,
                            "dispute_backstop": True,
                            "dispute_reason": hold["dispute_reason"],
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            journal_pair_ok = (
                earning is not None
                and terminal is not None
                and len(event_rows) == 2
                and debit is not None
                and credit is not None
                and {int(row["seq"]) for row in event_rows}
                    == {int(debit["seq"]), int(credit["seq"])}
                and int(earning["earned_at"]) == int(terminal)
                and int(earning["matures_at"]) == int(terminal) + HOLD_S
                and balances.get(hold["escrow_account"], 0) == 0
                and debit["kind"] == "task_pay_debit"
                and debit["receipt_id"] == event_id
                and debit["account"] == hold["escrow_account"]
                and debit["counterparty"] == hold["worker_account"]
                and int(debit["amount"]) == -int(hold["amount"])
                and int(debit["ts"]) == int(terminal)
                and debit["detail"] in valid_details
                and credit["kind"] == "task_earn"
                and credit["receipt_id"] == event_id
                and credit["account"] == hold["worker_account"]
                and credit["counterparty"] == hold["escrow_account"]
                and int(credit["amount"]) == int(hold["amount"])
                and int(credit["ts"]) == int(terminal)
                and credit["detail"] == debit["detail"]
            )
            if not journal_pair_ok:
                errors["economic_receipt_view"].append(
                    f"{economic_id}: paid task hold is not cashable from exact payment provenance"
                )
            if view is None:
                errors["economic_receipt_view"].append(
                    f"{economic_id}: missing shared economic row"
                )
                continue
            maturity = None if terminal is None else int(terminal) + HOLD_S
            expected = {
                "namespace": "task",
                "receipt_id": event_id,
                "hold_id": hold_id,
                "payer_account": hold["payer_account"],
                "worker_account": hold["worker_account"],
                "amount": int(hold["amount"]),
                "funded": int(hold["funded"]),
                "earned_at": terminal,
                "hold_terminal_at": terminal,
                "matures_at": maturity,
                "eligible_at": None if maturity is None else maturity + 1,
                "dispute_state": "none",
                "debit_journal_seq": (
                    int(earning["debit_journal_seq"])
                    if earning is not None else None
                ),
                "credit_journal_seq": (
                    int(earning["credit_journal_seq"])
                    if earning is not None else None
                ),
            }
            if any(view[field] != value for field, value in expected.items()):
                errors["economic_receipt_view"].append(
                    f"{economic_id}: task economic projection differs from hold provenance"
                )
        for hold_id in sorted(set(grandfathered_holds) - set(paid_task_holds)):
            errors["economic_receipt_view"].append(
                f"task:{hold_id}: grandfather list entry has no paid task hold"
            )
        grandfathered_task_holds = {
            "ids": sorted(accepted_grandfathers),
            "amounts": [
                {"hold_id": hold_id, "credits": accepted_grandfathers[hold_id]}
                for hold_id in sorted(accepted_grandfathers)
            ],
            "total_credits": sum(accepted_grandfathers.values()),
        }
        expected_economic_ids = expected_v2_ids | {
            f"v1:{row['seq']}"
            for row in ledger["journal"]
            if row["kind"] == "earn" and int(row["amount"]) > 0
        } | {
            f"legacy_import:{row['seq']}" for row in ledger["journal"]
            if row["kind"] == "legacy_import" and int(row["amount"]) > 0
        } | expected_task_ids
        if set(economic_rows) != expected_economic_ids:
            errors["economic_receipt_view"].append(
                "shared economic view does not exactly cover receipt earnings"
            )
        receipts = {row["receipt_id"]: row for row in ledger["receipts"]}
        legacy_projection = {
            row["receipt_id"]: row for row in ledger["legacy_funding_projection"]
        }
        expected_projection_ids = {
            receipt_id for receipt_id, receipt in receipts.items()
            if receipt["state"] != "legacy_unsigned"
        }
        if set(legacy_projection) != expected_projection_ids:
            errors["economic_receipt_view"].append(
                "legacy funding projection does not exactly cover verified receipts"
            )

        first_legacy_seq: dict[int, list[dict[str, Any]]] = {}
        for receipt in ledger["receipts"]:
            settlement_rows = [
                row for row in journals_by_receipt.get(receipt["receipt_id"], [])
                if row["kind"] in {"earn", "spend"}
            ]
            if settlement_rows:
                first_legacy_seq.setdefault(
                    min(int(row["seq"]) for row in settlement_rows), []
                ).append(receipt)
        running_balances: dict[str, int] = {}
        starter_received: dict[str, int] = {}
        legacy_backed_before: dict[str, int] = {}
        for journal in ledger["journal"]:
            for receipt in first_legacy_seq.get(int(journal["seq"]), []):
                requester = receipt["requester"]
                legacy_backed_before[receipt["receipt_id"]] = (
                    running_balances.get(requester, 0)
                    - starter_received.get(requester, 0)
                )
            account = journal["account"]
            running_balances[account] = running_balances.get(account, 0) + int(
                journal["amount"]
            )
            if journal["kind"] == "starter_receive":
                starter_received[account] = (
                    starter_received.get(account, 0) + int(journal["amount"])
                )
        for account, balance in balances.items():
            if (
                account != TREASURY_ACCOUNT
                and not account.startswith("__withdrawal_hold__")
                and not account.startswith("__spend_hold__")
                and running_balances.get(account, 0) != balance
            ):
                errors["economic_receipt_view"].append(
                    f"{account}: balance differs from chronological journal provenance"
                )

        for receipt_id, receipt in receipts.items():
            if receipt["state"] == "legacy_unsigned":
                continue
            reconstructed_funded = (
                int(receipt["charged"]) == 0
                or legacy_backed_before.get(receipt_id, 0) >= int(receipt["charged"])
            )
            projection = legacy_projection.get(receipt_id)
            if projection is None or projection["funded"] != int(reconstructed_funded):
                errors["economic_receipt_view"].append(
                    f"{receipt_id}: legacy funding projection differs from journal provenance"
                )
            try:
                credited = json.loads(receipt["credited"])
            except (TypeError, json.JSONDecodeError):
                credited = None
            rows = journals_by_receipt.get(receipt_id, [])
            earn_rows = [row for row in rows if row["kind"] == "earn"]
            spend_rows = [row for row in rows if row["kind"] == "spend"]
            charged = int(receipt["charged"])
            exact_earns = isinstance(credited, dict) and len(earn_rows) == len(credited)
            if exact_earns:
                exact_earns = sorted(
                    (row["account"], row["counterparty"], int(row["amount"]), int(row["ts"]))
                    for row in earn_rows
                ) == sorted(
                    (account, receipt["requester"], int(amount), int(receipt["created_at"]))
                    for account, amount in credited.items()
                )
            exact_spend = (
                (charged == 0 and not spend_rows)
                or (
                    charged > 0
                    and len(spend_rows) == 1
                    and spend_rows[0]["account"] == receipt["requester"]
                    and spend_rows[0]["counterparty"] is None
                    and int(spend_rows[0]["amount"]) == -charged
                    and int(spend_rows[0]["ts"]) == int(receipt["created_at"])
                )
            )
            if (
                not exact_earns
                or not exact_spend
                or not isinstance(credited, dict)
                or sum(int(amount) for amount in credited.values()) != charged
            ):
                errors["economic_receipt_view"].append(
                    f"{receipt_id}: legacy receipt lacks its exact earn/spend journal pair"
                )
                continue
            marker_ok = True
            for earn in earn_rows:
                try:
                    marker = json.loads(earn["detail"])
                except (TypeError, json.JSONDecodeError):
                    marker = None
                projection_ok = (
                    projection is not None
                    and projection["funded"] == int(reconstructed_funded)
                )
                # Pre-marker v1 earns used the literal empty object. This is safe
                # only with the independently verified projection: cashability
                # reads legacy_funding_projection and never reads this marker.
                absent_legacy_marker = (
                    earn["detail"] == "{}"
                    and projection_ok
                    and int(projection["funded"]) == 0
                )
                if (
                    not absent_legacy_marker
                    and marker != {"funded": reconstructed_funded}
                ):
                    marker_ok = False
            if not marker_ok:
                errors["economic_receipt_view"].append(
                    f"{receipt_id}: legacy funded marker differs from journal provenance"
                )

            dispute_rows = [
                row for row in rows
                if row["kind"] in {"dispute_clawback", "dispute_refund"}
            ]
            expected_dispute: list[tuple[Any, ...]] = []
            if receipt["state"] == "disputed":
                expected_dispute.extend(
                    (
                        "dispute_clawback", account, receipt["requester"],
                        -int(amount), int(receipt["disputed_at"]),
                    )
                    for account, amount in credited.items()
                )
                if charged:
                    expected_dispute.append(
                        (
                            "dispute_refund", receipt["requester"], None,
                            charged, int(receipt["disputed_at"]),
                        )
                    )
            actual_dispute = [
                (
                    row["kind"], row["account"], row["counterparty"],
                    int(row["amount"]), int(row["ts"]),
                )
                for row in dispute_rows
            ]
            if sorted(actual_dispute, key=repr) != sorted(expected_dispute, key=repr):
                errors["economic_receipt_view"].append(
                    f"{receipt_id}: legacy dispute lacks exact clawback/refund journals"
                )

        for economic_id, row in economic_rows.items():
            if row["namespace"] == "v1":
                receipt = receipts.get(row["receipt_id"])
                credit = journals.get(int(row["credit_journal_seq"]))
                reconstructed_funded = (
                    receipt is not None
                    and legacy_backed_before.get(row["receipt_id"], 0)
                    >= int(receipt["charged"])
                )
                if (
                    receipt is None or credit is None
                    or row["amount"] != credit["amount"]
                    or row["worker_account"] != credit["account"]
                    or row["earned_at"] != credit["ts"]
                    or row["hold_terminal_at"] != credit["ts"]
                    or row["matures_at"] != int(credit["ts"]) + HOLD_S
                    or row["eligible_at"] != int(credit["ts"]) + HOLD_S
                    or row["funded"] != int(reconstructed_funded)
                    or row["dispute_state"]
                       != ("clawed_back" if receipt and receipt["state"] == "disputed" else "none")
                ):
                    errors["economic_receipt_view"].append(
                        f"{economic_id}: legacy economic projection differs"
                    )
            elif row["namespace"] == "legacy_import" and (
                row["funded"] != 0 or row["matures_at"] is not None
                or row["eligible_at"] is not None
            ):
                errors["economic_receipt_view"].append(
                    f"{economic_id}: imported earning became eligible"
                )

        deposits_by_account: dict[str, int] = {}
        for chain_ref in ledger["chain_refs"]:
            if chain_ref["kind"] == "deposit":
                deposits_by_account[chain_ref["account"]] = (
                    deposits_by_account.get(chain_ref["account"], 0)
                    + int(chain_ref["amount"])
                )
        for withdrawal in ledger["withdrawals"]:
            if withdrawal["state"] == "released":
                continue
            operator = withdrawal["operator"]
            at = int(withdrawal["created_ts"])
            matured = sum(
                int(row["amount"])
                for row in economic_rows.values()
                if row["worker_account"] == operator
                and row["funded"] == 1
                and row["dispute_state"] == "none"
                and row["eligible_at"] is not None
                and at >= int(row["eligible_at"])
            )
            committed = sum(
                int(other["amount"])
                for other in ledger["withdrawals"]
                if other["operator"] == operator
                and other["state"] != "released"
                and (int(other["created_ts"]), other["id"])
                    <= (at, withdrawal["id"])
            )
            if committed > deposits_by_account.get(operator, 0) + matured:
                errors["economic_receipt_view"].append(
                    f"{withdrawal['id']}: withdrawal exceeds shared-view entitlement"
                )

        return [
            {
                "id": check_id,
                "ok": not own_errors,
                "checked": len(ledger["spend_usage_receipts"]),
                "errors": own_errors,
            }
            for check_id, own_errors in errors.items()
        ], grandfathered_task_holds

    def _build_report(
        self,
        ledger: dict[str, Any],
        chain: dict[str, Any],
        statuses: dict[str, dict[str, Any] | None],
        grandfathered_holds: dict[str, GrandfatheredHold],
        *,
        generated: int,
        attempt: int,
        before_slot: int,
        current_block_height: int | None,
    ) -> tuple[dict[str, Any], list[str]]:
        stamp = dt.datetime.fromtimestamp(generated, tz=dt.timezone.utc)
        token_accounts, token_errors, token_amounts = self._format_token_accounts(
            ledger, chain
        )
        lifecycle_errors, sent_proofs, finalized_proofs, sent_adjustment = (
            self._withdrawal_lifecycle(ledger, statuses)
        )
        sweep_errors, sweep_proofs, swept_by_account, verified_swept_total = (
            self._sweep_provenance(ledger, statuses, current_block_height)
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
            ledger,
            token_amounts,
            verified_vault_outflow,
            swept_by_account,
            verified_swept_total,
        )
        # An unproved finalized sweep is a stable mismatch, not ordinary
        # indexer lag. Its missing adjustment can otherwise make the vault's
        # observed balance look merely ahead of the ledger.
        if sweep_errors and lag:
            deposit_errors.extend(lag)
            lag = []
        spend_checks, grandfathered_task_holds = self._spend_checks(
            ledger, grandfathered_holds
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
                "ok": not deposit_errors and not sweep_errors,
                "chain_ref_credits": chain_ref_deposits,
                "journal_credits": journal_deposits,
                "errors": [*deposit_errors, *sweep_errors],
            },
            {
                "id": "chain_sweeps",
                "ok": not sweep_errors,
                "checked": len(sweep_proofs),
                "verified_credits": verified_swept_total,
                "errors": sweep_errors,
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
            *spend_checks,
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
                "verified_swept_credits": verified_swept_total,
            },
            "token_accounts": token_accounts,
            "sent_withdrawals": sent_proofs,
            "finalized_withdrawals": finalized_proofs,
            "finalized_withdrawal_verification": "all",
            "chain_sweeps": sweep_proofs,
            "chain_sweep_summary": {
                "ledger_rows": len(ledger["chain_sweeps"]),
                "proofs_checked": len(sweep_proofs),
                "verified_credits": verified_swept_total,
                "verification": "all finalized ledger and chain-finalized sent sweeps",
            },
            "grandfathered_task_holds": grandfathered_task_holds,
            "alerts": [],
        }
        return report, lag

    def collect(self) -> dict[str, Any]:
        """Collect a stable proof without writing balances or operational files."""
        generated = int(self.now())
        grandfathered_holds = _load_grandfathered_holds(
            self.config.grandfathered_holds_file
        )
        baseline = self._ledger_snapshot()
        self._pin_rpcs()
        reasons: list[str] = []
        last_report: dict[str, Any] | None = None
        for attempt in range(1, self.config.snapshot_attempts + 1):
            addresses = self._addresses(baseline)
            signatures = self._signatures(baseline)
            before = self._token_accounts(addresses)
            statuses = self._statuses(signatures)
            current_block_height = (
                self.rpc.get_block_height()
                if any(row["state"] == "sent" for row in baseline["chain_sweeps"])
                else None
            )
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
                    grandfathered_holds,
                    generated=generated,
                    attempt=attempt,
                    before_slot=int(before["slot"]),
                    current_block_height=current_block_height,
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
            current_block_height = (
                self.rpc.get_block_height()
                if any(row["state"] == "sent" for row in baseline["chain_sweeps"])
                else None
            )
            after = self._token_accounts(addresses)
            last_report, lag = self._build_report(
                baseline,
                after,
                statuses,
                grandfathered_holds,
                generated=generated,
                attempt=self.config.snapshot_attempts,
                before_slot=int(before["slot"]),
                current_block_height=current_block_height,
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
    parser.add_argument(
        "--grandfathered-holds-file",
        help="operator-pinned list of grandfathered paid task hold ids",
    )
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
        if args.grandfathered_holds_file:
            overrides["grandfathered_holds_file"] = _expanded(
                args.grandfathered_holds_file
            )
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
