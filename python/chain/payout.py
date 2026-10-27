#!/usr/bin/env python3
"""nak-treasury: the sole Solana treasury keyholder and payout worker.

The process is fail-closed: only devnet or loopback localnet RPCs are accepted,
``NAK_FUNDS`` defaults to ``off``, and the payout kill file prevents new work.
Transactions are constructed, audited, and signed in-process.  The resulting
signature and wire bytes are committed to SQLite before JSON-RPC broadcast.
"""
from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import json
import logging
import os
import stat
import struct
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import CreateAccountParams, ID as SYSTEM_PROGRAM_ID, create_account
from solders.token import ID as TOKEN_PROGRAM_ID
from solders.token.associated import get_associated_token_address
from solders.transaction import Transaction

if __package__ in {None, ""}:  # Permit direct execution by the systemd unit.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from chain.indexer import (  # type: ignore
        DEVNET_GENESIS_HASH,
        MAINNET_GENESIS_HASH,
        DepositIndexer,
        IndexerConfig,
        USDC_DECIMALS,
    )
    from chain.solana_rpc import RPCError, SolanaRPC, decode_base58, validate_pubkey  # type: ignore
else:
    from .indexer import (
        DEVNET_GENESIS_HASH,
        MAINNET_GENESIS_HASH,
        DepositIndexer,
        IndexerConfig,
        USDC_DECIMALS,
    )
    from .solana_rpc import RPCError, SolanaRPC, decode_base58, validate_pubkey

from core.ledger_store import RATE, LedgerStore, WithdrawalStateError
from ledger_auth import is_suspended_tier, load_roster


LOG = logging.getLogger("nak-treasury")
VAULT_SCRIPT = Path("/home/prithvi/trisul/infra/vault/vault.py")
WRITE_GATE_DIR = Path("/home/prithvi/trisul/infra/pillar-agent")
DEFAULT_STORE = "~/.neuron/credits/ledger.sqlite"
DEFAULT_KILL_FILE = "~/.neuron/credits/payout.off"
DEFAULT_LOCK_FILE = "~/.neuron/credits/payout.lock"
DEFAULT_ROSTER = "~/.nakshatra/admission-peers.tsv"
DEFAULT_SWEEP_MIN_MICRO = 1_000_000
DEFAULT_SWEEP_STALE_BLOCKS = 300
MICRO_USDC = 10 ** USDC_DECIMALS
AUTO_CAP_USDC = Decimal("5")
DAY_CAP_USDC = Decimal("50")
MAX_EXPIRIES = 3
TOKEN_ACCOUNT_SIZE = 165
ASSOCIATED_TOKEN_PROGRAM_ID = Pubkey.from_string(
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
)
RENT_SYSVAR_ID = Pubkey.from_string(
    "SysvarRent111111111111111111111111111111111"
)


class PayoutError(RuntimeError):
    """A payout operation was refused or could not be built safely."""


class SafetyGateError(PayoutError):
    """A mutable global safety gate stopped all money movement in this pass."""


def _credits_for_usdc(value: str | Decimal, name: str) -> int:
    try:
        amount = Decimal(value)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a decimal USDC amount") from exc
    credits = amount * MICRO_USDC * RATE
    if amount <= 0 or credits != credits.to_integral_value():
        raise ValueError(f"{name} must be positive with at most 6 decimal places")
    return int(credits)


def _micro_usdc_string(amount: int) -> str:
    whole, fraction = divmod(amount, MICRO_USDC)
    if not fraction:
        return str(whole)
    return f"{whole}.{fraction:0{USDC_DECIMALS}d}".rstrip("0")


def vault_get(name: str) -> str:
    """Read one audited vault entry without placing its value in argv or env."""
    result = subprocess.run(
        [sys.executable, str(VAULT_SCRIPT), "get", name],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    if result.returncode != 0 or not result.stdout:
        detail = result.stderr.strip() or "vault returned no value"
        raise PayoutError(f"could not load {name}: {detail}")
    return result.stdout.strip()


def _secret_bytes(secret: str) -> bytes:
    """Accept the vault's base58 keypair or Solana JSON keypair representation."""
    try:
        if secret.lstrip().startswith("["):
            values = json.loads(secret)
            if (
                not isinstance(values, list)
                or len(values) != 64
                or any(isinstance(value, bool) or not isinstance(value, int)
                       or not 0 <= value <= 255 for value in values)
            ):
                raise ValueError("JSON keypair must contain exactly 64 bytes")
            raw = bytes(values)
        else:
            raw = decode_base58(secret)
    except (json.JSONDecodeError, ValueError) as exc:
        raise PayoutError("nak-treasury-secret is not a Solana keypair") from exc
    if len(raw) != 64:
        raise PayoutError("nak-treasury-secret must decode to 64 bytes")
    return raw


@dataclass(frozen=True)
class SignedTransaction:
    signature: str
    wire_b64: str
    blockhash: str
    last_valid_block_height: int


class PayoutProcessLock:
    """A non-blocking process-lifetime advisory lock for the keyholder."""

    def __init__(self, path: Path, fd: int):
        self.path = path
        self._fd = fd

    @classmethod
    def acquire(cls, path: Path) -> "PayoutProcessLock | None":
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise PayoutError(f"payout lock is not a regular file: {path}")
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    os.close(fd)
                    return None
                raise
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode("ascii"))
            return cls(path, fd)
        except BaseException:
            if fd >= 0:
                os.close(fd)
            raise

    def close(self) -> None:
        if self._fd >= 0:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> "PayoutProcessLock":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class SoldersTreasuryBackend:
    """Construct, audit, and sign Solana transactions entirely in memory."""

    def __init__(
        self,
        rpc: Any,
        mint: str,
        vault_account: str,
        *,
        secret_loader: Callable[[str], str] = vault_get,
    ):
        self.rpc = rpc
        self.mint = Pubkey.from_string(validate_pubkey(mint, "NAK_USDC_MINT"))
        self.vault_account = Pubkey.from_string(validate_pubkey(
            vault_account, "NAK_TREASURY_USDC_ACCOUNT"
        ))
        try:
            self._treasury = Keypair.from_bytes(
                _secret_bytes(secret_loader("nak-treasury-secret"))
            )
        except ValueError as exc:
            raise PayoutError("nak-treasury-secret is not a valid Solana keypair") from exc
        self.pubkey = str(self._treasury.pubkey())
        validate_pubkey(self.pubkey, "treasury public key")

    @staticmethod
    def _decode_message(message: Message) -> Message:
        """Round-trip through wire bytes before inspecting the compiled form."""
        try:
            decoded = Message.from_bytes(bytes(message))
        except ValueError as exc:
            raise PayoutError("compiled transaction message could not be decoded") from exc
        if decoded != message:
            raise PayoutError("compiled transaction message changed during decoding")
        return decoded

    @staticmethod
    def _resolved_accounts(message: Message, instruction: Any) -> list[Pubkey]:
        keys = message.account_keys
        try:
            return [keys[index] for index in instruction.accounts]
        except IndexError as exc:
            raise PayoutError("compiled instruction references an invalid account") from exc

    @staticmethod
    def _assert_message_keys(message: Message, expected: list[Pubkey]) -> None:
        keys = list(message.account_keys)
        unique_expected = list(dict.fromkeys(expected))
        if len(keys) != len(unique_expected) or set(keys) != set(unique_expected):
            raise PayoutError("compiled message contains unexpected accounts")

    def _assert_transfer_message(
        self,
        message: Message,
        recipient: str,
        destination: str,
        micro_usdc: int,
        blockhash: str,
    ) -> Message:
        decoded = self._decode_message(message)
        treasury = self._treasury.pubkey()
        destination_key = Pubkey.from_string(
            validate_pubkey(destination, "recipient ATA")
        )
        recipient_key = Pubkey.from_string(
            validate_pubkey(recipient, "withdrawal address")
        )
        expected_destination = get_associated_token_address(recipient_key, self.mint)
        if destination_key != expected_destination:
            raise PayoutError("recipient ATA does not match the bound withdrawal address")
        if decoded.recent_blockhash != Hash.from_string(blockhash):
            raise PayoutError("compiled transfer uses the wrong blockhash")
        if not decoded.account_keys or decoded.account_keys[0] != treasury:
            raise PayoutError("compiled transfer uses the wrong fee payer")
        if decoded.header.num_required_signatures != 1:
            raise PayoutError("compiled transfer requires an unexpected signer")
        if len(decoded.instructions) != 1:
            raise PayoutError("compiled transfer must contain exactly one instruction")
        instruction = decoded.instructions[0]
        try:
            program = decoded.account_keys[instruction.program_id_index]
        except IndexError as exc:
            raise PayoutError("compiled transfer references an invalid program") from exc
        if program != TOKEN_PROGRAM_ID:
            raise PayoutError("compiled transfer uses the wrong program")
        expected_accounts = [
            self.vault_account,
            self.mint,
            destination_key,
            treasury,
        ]
        if self._resolved_accounts(decoded, instruction) != expected_accounts:
            raise PayoutError("compiled transfer uses the wrong accounts")
        expected_data = b"\x0c" + struct.pack("<Q", micro_usdc) + bytes([USDC_DECIMALS])
        if instruction.data != expected_data:
            raise PayoutError("compiled transfer uses the wrong amount or decimals")
        self._assert_message_keys(
            decoded, [treasury, *expected_accounts, TOKEN_PROGRAM_ID]
        )
        expected_message = Message.new_with_blockhash(
            [
                Instruction(
                    TOKEN_PROGRAM_ID,
                    expected_data,
                    [
                        AccountMeta(self.vault_account, False, True),
                        AccountMeta(self.mint, False, False),
                        AccountMeta(destination_key, False, True),
                        AccountMeta(treasury, True, False),
                    ],
                )
            ],
            treasury,
            Hash.from_string(blockhash),
        )
        if bytes(decoded) != bytes(expected_message):
            raise PayoutError("compiled transfer metadata differs from the expected message")
        return decoded

    def _sign_message(self, message: Message, signers: list[Keypair]) -> Transaction:
        transaction = Transaction(signers, message, message.recent_blockhash)
        if transaction.verify_with_results() != [True] * len(signers):
            raise PayoutError("constructed transaction signature verification failed")
        for signer, signature in zip(signers, transaction.signatures, strict=True):
            if not signature.verify(signer.pubkey(), bytes(message)):
                raise PayoutError("constructed transaction has an invalid signature")
        return transaction

    def _send_transaction(
        self, transaction: Transaction, may_act: Callable[[], None]
    ) -> str:
        signature = str(transaction.signatures[0])
        wire_b64 = base64.b64encode(bytes(transaction)).decode("ascii")
        may_act()
        returned = self.rpc.send_transaction(wire_b64)
        if returned != signature:
            raise PayoutError("RPC returned a signature different from the signed transaction")
        return signature

    def create_deposit_account(self, may_act: Callable[[], None]) -> str:
        account = Keypair()
        rent = self.rpc.get_minimum_balance_for_rent_exemption(TOKEN_ACCOUNT_SIZE)
        latest = self.rpc.get_latest_blockhash()
        create = create_account(
            CreateAccountParams(
                from_pubkey=self._treasury.pubkey(),
                to_pubkey=account.pubkey(),
                lamports=rent,
                space=TOKEN_ACCOUNT_SIZE,
                owner=TOKEN_PROGRAM_ID,
            )
        )
        initialize = Instruction(
            TOKEN_PROGRAM_ID,
            b"\x01",  # InitializeAccount; owner is an account, not instruction data.
            [
                AccountMeta(account.pubkey(), False, True),
                AccountMeta(self.mint, False, False),
                AccountMeta(self._treasury.pubkey(), False, False),
                AccountMeta(RENT_SYSVAR_ID, False, False),
            ],
        )
        message = Message.new_with_blockhash(
            [create, initialize],
            self._treasury.pubkey(),
            Hash.from_string(latest["blockhash"]),
        )
        decoded = self._decode_message(message)
        if decoded.account_keys[0] != self._treasury.pubkey():
            raise PayoutError("deposit-account transaction uses the wrong fee payer")
        if [decoded.account_keys[ix.program_id_index] for ix in decoded.instructions] != [
            SYSTEM_PROGRAM_ID,
            TOKEN_PROGRAM_ID,
        ]:
            raise PayoutError("deposit-account transaction uses an unexpected program")
        self._send_transaction(
            self._sign_message(decoded, [self._treasury, account]), may_act
        )
        return str(account.pubkey())

    def recipient_ata(self, owner: str) -> str:
        owner_key = Pubkey.from_string(validate_pubkey(owner, "withdrawal address"))
        return str(get_associated_token_address(owner_key, self.mint))

    def create_recipient_ata(
        self, owner: str, may_act: Callable[[], None]
    ) -> str:
        owner_key = Pubkey.from_string(validate_pubkey(owner, "withdrawal address"))
        ata = get_associated_token_address(owner_key, self.mint)
        latest = self.rpc.get_latest_blockhash()
        instruction = Instruction(
            ASSOCIATED_TOKEN_PROGRAM_ID,
            b"\x01",  # CreateIdempotent
            [
                AccountMeta(self._treasury.pubkey(), True, True),
                AccountMeta(ata, False, True),
                AccountMeta(owner_key, False, False),
                AccountMeta(self.mint, False, False),
                AccountMeta(SYSTEM_PROGRAM_ID, False, False),
                AccountMeta(TOKEN_PROGRAM_ID, False, False),
            ],
        )
        message = Message.new_with_blockhash(
            [instruction],
            self._treasury.pubkey(),
            Hash.from_string(latest["blockhash"]),
        )
        decoded = self._decode_message(message)
        compiled = decoded.instructions[0]
        if decoded.account_keys[0] != self._treasury.pubkey():
            raise PayoutError("ATA transaction uses the wrong fee payer")
        if decoded.account_keys[compiled.program_id_index] != ASSOCIATED_TOKEN_PROGRAM_ID:
            raise PayoutError("ATA transaction uses the wrong program")
        expected_accounts = [
            self._treasury.pubkey(),
            ata,
            owner_key,
            self.mint,
            SYSTEM_PROGRAM_ID,
            TOKEN_PROGRAM_ID,
        ]
        if self._resolved_accounts(decoded, compiled) != expected_accounts:
            raise PayoutError("ATA transaction uses the wrong accounts")
        if compiled.data != b"\x01":
            raise PayoutError("ATA transaction is not idempotent")
        self._assert_message_keys(
            decoded, [*expected_accounts, ASSOCIATED_TOKEN_PROGRAM_ID]
        )
        self._send_transaction(self._sign_message(decoded, [self._treasury]), may_act)
        return str(ata)

    def build_transfer(
        self,
        recipient: str,
        destination: str,
        micro_usdc: int,
        blockhash: str,
        last_valid_block_height: int,
    ) -> SignedTransaction:
        destination = validate_pubkey(destination, "recipient ATA")
        blockhash = validate_pubkey(blockhash, "blockhash")
        if micro_usdc <= 0:
            raise PayoutError("transfer amount must be positive")
        destination_key = Pubkey.from_string(destination)
        instruction = Instruction(
            TOKEN_PROGRAM_ID,
            b"\x0c" + struct.pack("<Q", micro_usdc) + bytes([USDC_DECIMALS]),
            [
                AccountMeta(self.vault_account, False, True),
                AccountMeta(self.mint, False, False),
                AccountMeta(destination_key, False, True),
                AccountMeta(self._treasury.pubkey(), True, False),
            ],
        )
        message = Message.new_with_blockhash(
            [instruction], self._treasury.pubkey(), Hash.from_string(blockhash)
        )
        decoded = self._assert_transfer_message(
            message, recipient, destination, micro_usdc, blockhash
        )
        transaction = self._sign_message(decoded, [self._treasury])
        signature = str(transaction.signatures[0])
        return SignedTransaction(
            signature=signature,
            wire_b64=base64.b64encode(bytes(transaction)).decode("ascii"),
            blockhash=blockhash,
            last_valid_block_height=last_valid_block_height,
        )

    def build_sweep(
        self,
        source: str,
        micro_usdc: int,
        blockhash: str,
        last_valid_block_height: int,
    ) -> SignedTransaction:
        """Build and audit a treasury-authorized deposit-account sweep."""
        source_key = Pubkey.from_string(validate_pubkey(source, "deposit token account"))
        blockhash = validate_pubkey(blockhash, "blockhash")
        if micro_usdc <= 0:
            raise PayoutError("sweep amount must be positive")
        treasury = self._treasury.pubkey()
        data = b"\x0c" + struct.pack("<Q", micro_usdc) + bytes([USDC_DECIMALS])
        expected_accounts = [source_key, self.mint, self.vault_account, treasury]
        instruction = Instruction(
            TOKEN_PROGRAM_ID,
            data,
            [
                AccountMeta(source_key, False, True),
                AccountMeta(self.mint, False, False),
                AccountMeta(self.vault_account, False, True),
                AccountMeta(treasury, True, False),
            ],
        )
        message = self._decode_message(
            Message.new_with_blockhash(
                [instruction], treasury, Hash.from_string(blockhash)
            )
        )
        if message.recent_blockhash != Hash.from_string(blockhash):
            raise PayoutError("compiled sweep uses the wrong blockhash")
        if not message.account_keys or message.account_keys[0] != treasury:
            raise PayoutError("compiled sweep uses the wrong fee payer")
        if message.header.num_required_signatures != 1 or len(message.instructions) != 1:
            raise PayoutError("compiled sweep has unexpected signatures or instructions")
        compiled = message.instructions[0]
        if message.account_keys[compiled.program_id_index] != TOKEN_PROGRAM_ID:
            raise PayoutError("compiled sweep uses the wrong program")
        if self._resolved_accounts(message, compiled) != expected_accounts:
            raise PayoutError("compiled sweep uses the wrong accounts")
        if compiled.data != data:
            raise PayoutError("compiled sweep uses the wrong amount or decimals")
        self._assert_message_keys(message, [treasury, *expected_accounts, TOKEN_PROGRAM_ID])
        expected = Message.new_with_blockhash(
            [instruction], treasury, Hash.from_string(blockhash)
        )
        if bytes(message) != bytes(expected):
            raise PayoutError("compiled sweep metadata differs from the expected message")
        transaction = self._sign_message(message, [self._treasury])
        return SignedTransaction(
            signature=str(transaction.signatures[0]),
            wire_b64=base64.b64encode(bytes(transaction)).decode("ascii"),
            blockhash=blockhash,
            last_valid_block_height=last_valid_block_height,
        )


@dataclass(frozen=True)
class PayoutConfig:
    cluster: str
    mint: str
    rpc_url: str
    vault_account: str
    enabled: bool = False
    kill_file: Path = Path(DEFAULT_KILL_FILE).expanduser()
    auto_cap: int = _credits_for_usdc(AUTO_CAP_USDC, "AUTO_CAP")
    day_cap: int = _credits_for_usdc(DAY_CAP_USDC, "DAY_CAP")
    devnet_genesis: str = DEVNET_GENESIS_HASH
    presence_wait_s: int = 120
    require_live_funds_env: bool = False
    roster_path: Path = Path(DEFAULT_ROSTER).expanduser()
    sweep_min_micro: int = DEFAULT_SWEEP_MIN_MICRO
    sweep_stale_blocks: int = DEFAULT_SWEEP_STALE_BLOCKS

    def __post_init__(self) -> None:
        # Reuse S3's complete cluster/RPC/pubkey validation.
        IndexerConfig(
            cluster=self.cluster,
            mint=self.mint,
            rpc_url=self.rpc_url,
            devnet_genesis=self.devnet_genesis,
        )
        validate_pubkey(self.vault_account, "NAK_TREASURY_USDC_ACCOUNT")
        if self.auto_cap <= 0 or self.day_cap <= 0:
            raise ValueError("payout caps must be positive")
        if self.presence_wait_s <= 0:
            raise ValueError("presence wait must be positive")
        if (
            isinstance(self.sweep_min_micro, bool)
            or not isinstance(self.sweep_min_micro, int)
            or self.sweep_min_micro <= 0
        ):
            raise ValueError("sweep minimum must be a positive integer")
        if (
            isinstance(self.sweep_stale_blocks, bool)
            or not isinstance(self.sweep_stale_blocks, int)
            or self.sweep_stale_blocks < 0
        ):
            raise ValueError("sweep stale block allowance must be a non-negative integer")

    @classmethod
    def from_env(cls) -> "PayoutConfig":
        required = (
            "NAK_SOLANA_CLUSTER",
            "NAK_USDC_MINT",
            "NAK_SOLANA_RPC",
            "NAK_TREASURY_USDC_ACCOUNT",
        )
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise ValueError(f"missing required environment: {', '.join(missing)}")
        return cls(
            cluster=os.environ["NAK_SOLANA_CLUSTER"],
            mint=os.environ["NAK_USDC_MINT"],
            rpc_url=os.environ["NAK_SOLANA_RPC"],
            vault_account=os.environ["NAK_TREASURY_USDC_ACCOUNT"],
            enabled=os.environ.get("NAK_FUNDS", "off") == "on",
            kill_file=Path(
                os.path.expanduser(os.environ.get("NAK_PAYOUT_KILL_FILE", DEFAULT_KILL_FILE))
            ),
            auto_cap=_credits_for_usdc(
                os.environ.get("NAK_PAYOUT_AUTO_CAP", str(AUTO_CAP_USDC)),
                "NAK_PAYOUT_AUTO_CAP",
            ),
            day_cap=_credits_for_usdc(
                os.environ.get("NAK_PAYOUT_DAY_CAP", str(DAY_CAP_USDC)),
                "NAK_PAYOUT_DAY_CAP",
            ),
            devnet_genesis=os.environ.get(
                "NAK_SOLANA_DEVNET_GENESIS", DEVNET_GENESIS_HASH
            ),
            presence_wait_s=int(os.environ.get("NAK_PAYOUT_PRESENCE_WAIT", "120")),
            require_live_funds_env=True,
            roster_path=Path(
                os.path.expanduser(
                    os.environ.get("NAK_ADMISSION_ROSTER", DEFAULT_ROSTER)
                )
            ),
            sweep_min_micro=int(
                os.environ.get("NAK_SWEEP_MIN_MICRO", str(DEFAULT_SWEEP_MIN_MICRO))
            ),
            sweep_stale_blocks=int(
                os.environ.get(
                    "NAK_SWEEP_STALE_BLOCKS", str(DEFAULT_SWEEP_STALE_BLOCKS)
                )
            ),
        )


def _write_gate():
    """Load the one approved human-presence doorway without importing at startup."""
    if str(WRITE_GATE_DIR) not in sys.path:
        sys.path.insert(0, str(WRITE_GATE_DIR))
    import write_gate  # type: ignore

    return write_gate


class WriteGatePresence:
    """Non-blocking adapter over write_gate's existing challenge/broker/verifier."""

    @staticmethod
    def prepare(row: dict[str, Any], description: str, wait_s: int) -> dict[str, Any]:
        write_gate = _write_gate()
        keyid = write_gate.owner_keyid()
        challenge = write_gate.eg.issue_challenge(
            keyid,
            "nak.payout",
            f"withdrawal:{row['id']}",
            300,
            description=description,
        )
        if not challenge.get("ok"):
            raise PayoutError(
                f"presence challenge refused: {challenge.get('error', challenge)}"
            )
        # The legacy broker clamps requests to [30, 180] seconds.  Record that
        # deadline before enqueue so an ambiguous POST can be recovered without
        # ever creating a second live challenge.
        ttl = max(30, min(int(wait_s), 180))
        return {
            "withdrawal_id": str(row["id"]),
            "amount": int(row["amount"]),
            "address": str(row["address"]),
            "keyid": keyid,
            "nonce": challenge["nonce"],
            "challenge": challenge["challenge"],
            "description": description,
            "expires_ts": int(time.time()) + ttl,
        }

    @staticmethod
    def enqueue(request: dict[str, Any], wait_s: int) -> dict[str, Any]:
        """Recover an ambiguous enqueue by challenge, otherwise enqueue once."""
        write_gate = _write_gate()
        if request.get("request_id"):
            return request
        from urllib.parse import urlencode

        pending = write_gate._broker_call(
            "GET", f"/pending?{urlencode({'keyid': request['keyid']})}"
        )
        for candidate in pending.get("requests", []):
            if (
                candidate.get("challenge") == request["challenge"]
                and candidate.get("description") == request["description"][:200]
            ):
                return {
                    **request,
                    "request_id": candidate["request_id"],
                    "expires_ts": min(
                        int(request["expires_ts"]), int(candidate["expires"])
                    ),
                }
        if not request.get("_allow_new_enqueue"):
            return request
        if int(time.time()) > int(request["expires_ts"]):
            return request
        enqueued = write_gate._broker_call(
            "POST",
            "/enqueue",
            {
                "keyid": request["keyid"],
                "challenge": request["challenge"],
                "description": request["description"],
                "body": None,
                "ttl": min(int(wait_s), 180),
            },
        )
        request_id = enqueued.get("request_id")
        if not request_id:
            raise PayoutError(
                f"signer broker refused the request: {enqueued.get('error', enqueued)}"
            )
        return {
            **request,
            "request_id": request_id,
            "expires_ts": min(
                int(request["expires_ts"]),
                int(enqueued.get("expires", request["expires_ts"])),
            ),
        }

    @staticmethod
    def recover(request: dict[str, Any], wait_s: int) -> dict[str, Any]:
        """Recover an elected caller's ambiguous POST without issuing another."""
        return WriteGatePresence.enqueue(
            {**request, "_allow_new_enqueue": False}, wait_s
        )

    @staticmethod
    def fetch(request: dict[str, Any]) -> dict[str, Any]:
        """Read the broker result once; the caller persists it before verification."""
        if int(time.time()) > int(request["expires_ts"]):
            return {"status": "expired", "error": "presence request expired"}
        request_id = request.get("request_id")
        if not request_id:
            return {"status": "pending"}
        write_gate = _write_gate()
        return write_gate._broker_call(
            "GET", f"/result?request_id={request_id}"
        )

    @staticmethod
    def verify(
        request: dict[str, Any], result: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        """Re-verify a raw persisted result without trusting broker state."""
        status = result.get("status")
        if status == "pending":
            return "pending", result
        if status == "expired":
            return "expired", result
        if status == "declined":
            return "denied", result
        if status != "signed" or not result.get("signature"):
            # unknown/consumed is ambiguous until the locally recorded request
            # expires.  Ambiguity can never approve or trigger a second request.
            return "pending", result
        if int(time.time()) > int(request["expires_ts"]):
            return "expired", {"error": "approval arrived after expiry"}
        write_gate = _write_gate()
        verified = write_gate.eg.verify_signature_only(
            request["keyid"],
            request["challenge"],
            result["signature"],
            signer_keyid=result.get("signer"),
        )
        if not verified.get("ok"):
            return "denied", {
                "error": f"presence not certified: {verified.get('error')}"
            }
        return "approved", {
            **verified.get("granted", {}),
            "challenge": request["challenge"],
            "signature": result["signature"],
            "signer": verified.get("signer") or request["keyid"],
            "withdrawal_id": request["withdrawal_id"],
            "amount": int(request["amount"]),
            "address": request["address"],
        }


class _ImmediatePresence:
    """Compatibility adapter for deterministic injected unit-test callbacks."""

    immediate = True

    def __init__(self, callback: Callable[[dict[str, Any], str, int], tuple[bool, Any]]):
        self.callback = callback
        self.results: dict[str, tuple[bool, Any]] = {}

    def prepare(self, row: dict[str, Any], description: str, wait_s: int) -> dict[str, Any]:
        self.results[str(row["id"])] = self.callback(row, description, wait_s)
        return {
            "withdrawal_id": str(row["id"]),
            "amount": int(row["amount"]),
            "address": str(row["address"]),
            "keyid": "injected",
            "nonce": f"injected:{row['id']}",
            "challenge": f"injected:{row['id']}",
            "description": description,
            "expires_ts": int(time.time()) + max(1, int(wait_s)),
        }

    @staticmethod
    def enqueue(request: dict[str, Any], _wait_s: int) -> dict[str, Any]:
        return {**request, "request_id": f"injected:{request['withdrawal_id']}"}

    def fetch(self, request: dict[str, Any]) -> dict[str, Any]:
        ok, detail = self.results.pop(str(request["withdrawal_id"]))
        if not ok:
            return {
                "status": "declined",
                **(detail if isinstance(detail, dict) else {}),
            }
        granted = dict(detail) if isinstance(detail, dict) else {}
        granted.setdefault("withdrawal_id", request["withdrawal_id"])
        granted.setdefault("amount", int(request["amount"]))
        granted.setdefault("address", request["address"])
        return {"status": "signed", "granted": granted}

    @staticmethod
    def verify(
        _request: dict[str, Any], result: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        if result.get("status") == "signed":
            return "approved", dict(result.get("granted") or {})
        return "denied", result


class PayoutEngine:
    def __init__(
        self,
        store: LedgerStore,
        rpc: Any,
        config: PayoutConfig,
        *,
        backend: Any | None = None,
        backend_factory: Callable[[], Any] | None = None,
        presence: Any | None = None,
        now: Callable[[], float] = time.time,
    ):
        self.store = store
        self.rpc = rpc
        self.config = config
        self._backend_value = backend
        self._backend_factory = backend_factory
        if presence is None:
            self.presence = WriteGatePresence()
        elif callable(presence) and not hasattr(presence, "prepare"):
            self.presence = _ImmediatePresence(presence)
        else:
            self.presence = presence
        self.now = now
        expected = config.devnet_genesis if config.cluster == "devnet" else None
        genesis = DepositIndexer._pin_rpc(rpc, expected, "payout")
        if genesis == MAINNET_GENESIS_HASH:
            raise ValueError("mainnet-beta genesis is explicitly refused")
        self.genesis_hash = genesis

    def _backend(self):
        if self._backend_value is None:
            if self._backend_factory is None:
                raise PayoutError("no treasury signer backend configured")
            self._backend_value = self._backend_factory()
        return self._backend_value

    def _may_act(self) -> None:
        """Recheck every mutable safety gate immediately before an RPC write."""
        if not self.config.enabled:
            raise SafetyGateError("NAK_FUNDS is disabled")
        if (
            self.config.require_live_funds_env
            and os.environ.get("NAK_FUNDS", "off") != "on"
        ):
            raise SafetyGateError("NAK_FUNDS is no longer on")
        if self.config.kill_file.exists():
            raise SafetyGateError(
                f"payout kill file present: {self.config.kill_file}"
            )
        expected = (
            self.config.devnet_genesis if self.config.cluster == "devnet" else None
        )
        genesis = DepositIndexer._pin_rpc(self.rpc, expected, "payout action")
        if genesis == MAINNET_GENESIS_HASH or genesis != self.genesis_hash:
            raise SafetyGateError("payout RPC genesis changed or is mainnet-beta")

    @staticmethod
    def _description(row: dict[str, Any]) -> str:
        micro = int(row["amount"]) // RATE
        return (
            f"Nakshatra devnet payout {_micro_usdc_string(micro)} USDC; "
            f"operator={row['operator']}; address={row['address']}; "
            f"withdrawal={row['id']}"
        )

    def _midnight_utc(self) -> int:
        now = int(self.now())
        return now - (now % 86_400)

    def _ensure_recipient_ata(self, address: str) -> str:
        backend = self._backend()
        ata = backend.recipient_ata(address)
        if not self.rpc.account_exists(ata):
            created = backend.create_recipient_ata(address, self._may_act)
            if created != ata:
                raise PayoutError("recipient ATA changed during idempotent creation")
            self._wait_for_account(ata)
        return ata

    def _wait_for_account(self, address: str, timeout_s: float = 20.0) -> None:
        """Wait until a newly-created account is visible at finalized commitment."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.rpc.account_exists(address):
                return
            time.sleep(0.2)
        raise PayoutError(f"created account {address} did not finalize")

    def _frozen_operators(self) -> set[str]:
        roster = load_roster(self.config.roster_path)
        return {
            str(row["operator"])
            for row in roster.values()
            if isinstance(row, dict)
            and isinstance(row.get("operator"), str)
            and is_suspended_tier(row.get("tier"))
        }

    def _approve_pending(self, frozen_operators: set[str]) -> int:
        changed = 0
        for row in self.store.withdrawals(
            "pending", "expired", exclude_operators=frozen_operators
        ):
            if row["state"] == "expired" and row.get("approval_ref"):
                continue
            try:
                changed += self._approve_one(row)
            except Exception:
                LOG.exception(
                    "withdrawal approval step failed withdrawal=%s", row["id"]
                )
        return changed

    def _refresh_approval_lifetimes(self) -> int:
        """Return stale human approvals to the ordinary approval path."""
        changed = 0
        for row in self.store.withdrawals("approved", "expired"):
            try:
                if self.store.withdraw_require_fresh_approval(
                    row["id"], int(getattr(self, "now", time.time)())
                ):
                    LOG.info(
                        "withdrawal %s requires a fresh human approval", row["id"]
                    )
                    changed += 1
            except Exception:
                LOG.exception(
                    "withdrawal approval lifetime check failed withdrawal=%s",
                    row["id"],
                )
        return changed

    def _approve_one(self, row: dict[str, Any]) -> int:
        changed = 0
        if int(row["presence_attempts"]) >= 2:
            self.store.withdraw_release(row["id"])
            return 1
        if self.store.withdraw_auto_approve(
            row["id"],
            "auto:devnet-caps-v1",
            approved_since=self._midnight_utc(),
            auto_cap=self.config.auto_cap,
            day_cap=self.config.day_cap,
        ):
            return 1
        if not self.config.enabled:
            LOG.info("DRY-RUN human approval required for %s", row["id"])
            return 0
        request = self.store.withdrawal_presence(row["id"])
        freshly_prepared = request is None
        if request is None:
            prepared = self.presence.prepare(
                row, self._description(row), self.config.presence_wait_s
            )
            request = self.store.withdraw_begin_presence(
                row["id"],
                int(row["amount"]),
                str(row["address"]),
                prepared["keyid"],
                prepared["nonce"],
                prepared["challenge"],
                prepared["description"],
                int(prepared["expires_ts"]),
            )
            changed += 1
        if (
            request["withdrawal_id"] != row["id"]
            or int(request["amount"]) != int(row["amount"])
            or request["address"] != row["address"]
            or request["description"] != self._description(row)
        ):
            LOG.error("presence binding mismatch withdrawal=%s", row["id"])
            attempts = self.store.withdraw_presence_attempt(row["id"])
            if attempts >= 2:
                self.store.withdraw_release(row["id"])
            return changed + 1
        if int(self.now()) > int(request["expires_ts"]):
            attempts = self.store.withdraw_presence_attempt(row["id"])
            if attempts >= 2:
                self.store.withdraw_release(row["id"])
            return changed + 1
        allow_new_enqueue = False
        if not bool(request["enqueue_attempted"]):
            request, allow_new_enqueue = (
                self.store.withdraw_presence_mark_enqueue_attempted(row["id"])
            )
        if request.get("request_id"):
            enqueued = request
        elif allow_new_enqueue:
            enqueued = self.presence.enqueue(
                {**request, "_allow_new_enqueue": True},
                self.config.presence_wait_s,
            )
        elif hasattr(self.presence, "recover"):
            enqueued = self.presence.recover(
                request, self.config.presence_wait_s
            )
        else:
            enqueued = request
        if enqueued.get("request_id") and not request.get("request_id"):
            request = self.store.withdraw_presence_enqueued(
                row["id"],
                str(enqueued["request_id"]),
                int(enqueued["expires_ts"]),
            )
        else:
            request = enqueued
        if freshly_prepared and not getattr(self.presence, "immediate", False):
            return changed

        stored_result = request.get("broker_result_json")
        if stored_result is not None:
            result = json.loads(stored_result)
        elif hasattr(self.presence, "fetch"):
            result = self.presence.fetch(request)
            if result.get("status") == "signed":
                # /result is one-shot. This durable write must precede every
                # signature check and approval state transition.
                result = self.store.withdraw_presence_store_result(
                    row["id"], result
                )
        else:
            # Compatibility for deterministic adapters from before the split
            # fetch/verify interface. Production WriteGatePresence never uses it.
            status, granted = self.presence.check(request)
            result = {"status": status, "granted": granted}

        if hasattr(self.presence, "verify"):
            status, granted = self.presence.verify(request, result)
        else:
            status = str(result.get("status"))
            granted = dict(result.get("granted") or {})
        if status == "pending":
            return changed
        matching = (
            isinstance(granted, dict)
            and granted.get("withdrawal_id") == row["id"]
            and granted.get("amount") == int(row["amount"])
            and granted.get("address") == row["address"]
        )
        if status == "approved" and matching:
            reference = (
                granted.get("challenge")
                or granted.get("signature")
                or granted.get("signer")
                or "presence"
            )
            self.store.withdraw_approve(
                row["id"],
                f"human:{reference}",
                expires_ts=int(request["expires_ts"]),
                approved_withdrawal_id=str(request["withdrawal_id"]),
                approved_amount=int(request["amount"]),
                approved_address=str(request["address"]),
            )
            return changed + 1
        if status == "approved":
            LOG.error(
                "presence approval binding mismatch withdrawal=%s", row["id"]
            )
        attempts = self.store.withdraw_presence_attempt(row["id"])
        if attempts >= 2:
            self.store.withdraw_release(row["id"])
        return changed + 1

    def _create_deposit_accounts(self) -> int:
        changed = 0
        for row in self.store.pending_deposit_accounts():
            try:
                token_account = self._backend().create_deposit_account(self._may_act)
                self._wait_for_account(token_account)
                self.store.register_deposit_account(row["operator"], token_account)
                changed += 1
            except (OSError, RPCError, PayoutError, ValueError) as exc:
                self.store.record_deposit_account_error(
                    row["operator"], f"{type(exc).__name__}: {exc}"
                )
                LOG.error("deposit account creation failed for %s: %s", row["operator"], exc)
        return changed

    def _advance_sweep(self, row: dict[str, Any]) -> int:
        """Resolve one durable sweep without ever constructing a competing tx."""
        status = self.rpc.get_signature_status(row["signature"])
        if isinstance(status, dict):
            if status.get("err") is not None:
                if status.get("confirmationStatus") == "finalized":
                    self.store.fail_sweep(row["id"])
                    LOG.error(
                        "sweep failed operator=%s account=%s signature=%s",
                        row["operator"], row["token_account"], row["signature"],
                    )
                    return 1
                # A processed/confirmed error can disappear with its fork. The
                # immutable signed transaction may still land, so do not let a
                # competing sweep be constructed.
                self._log_stale_sweep(row, self.rpc.get_block_height())
                return 0
            if status.get("confirmationStatus") == "finalized":
                self.store.finalize_sweep(row["id"])
                LOG.info(
                    "sweep finalized operator=%s account=%s amount_micro=%s signature=%s",
                    row["operator"], row["token_account"], row["amount_micro"],
                    row["signature"],
                )
                return 1
            self._log_stale_sweep(row, self.rpc.get_block_height())
            return 0
        height = self.rpc.get_block_height()
        if height > int(row["last_valid_block_height"]):
            # Search history once more after observing expiry, matching payout fencing.
            status = self.rpc.get_signature_status(row["signature"])
            if status is None:
                self.store.fail_sweep(row["id"])
                LOG.warning(
                    "sweep expired operator=%s account=%s signature=%s",
                    row["operator"], row["token_account"], row["signature"],
                )
                return 1
            if status.get("err") is not None:
                if status.get("confirmationStatus") == "finalized":
                    self.store.fail_sweep(row["id"])
                    return 1
                self._log_stale_sweep(row, height)
                return 0
            if status.get("confirmationStatus") == "finalized":
                self.store.finalize_sweep(row["id"])
                return 1
            self._log_stale_sweep(row, height)
        return 0

    def _log_stale_sweep(self, row: dict[str, Any], height: int) -> None:
        stale_after = (
            int(row["last_valid_block_height"]) + self.config.sweep_stale_blocks
        )
        if height > stale_after:
            LOG.error(
                "stale in-flight sweep %s operator=%s account=%s signature=%s "
                "block_height=%s stale_after=%s",
                row["id"], row["operator"], row["token_account"],
                row["signature"], height, stale_after,
            )

    @staticmethod
    def _sweep_alert(row: dict[str, Any], kind: str, detail: str) -> None:
        LOG.error(
            "%s",
            json.dumps(
                {
                    "event": "chain_sweep_alert",
                    "kind": kind,
                    "operator": row["operator"],
                    "token_account": row["token_account"],
                    "detail": detail,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        )

    def _validate_sweep_source(
        self, row: dict[str, Any], snapshot: dict[str, Any]
    ) -> None:
        treasury = str(self._backend().pubkey)
        owner = snapshot.get("owner")
        if owner != treasury:
            detail = f"source owner {owner!r} != treasury {treasury}"
            self._sweep_alert(row, "source_authority", detail)
            raise PayoutError(detail)
        if snapshot.get("delegate") is not None:
            detail = f"source account has delegate {snapshot.get('delegate')!r}"
            self._sweep_alert(row, "source_authority", detail)
            raise PayoutError(detail)
        close_authority = snapshot.get(
            "closeAuthority", snapshot.get("close_authority")
        )
        if close_authority not in {None, treasury}:
            detail = (
                f"source close authority {close_authority!r} != treasury {treasury}"
            )
            self._sweep_alert(row, "source_authority", detail)
            raise PayoutError(detail)

    def _start_sweep(self, row: dict[str, Any], amount_micro: int) -> int:
        latest = self.rpc.get_latest_blockhash()
        signed = self._backend().build_sweep(
            row["token_account"],
            amount_micro,
            latest["blockhash"],
            latest["last_valid_block_height"],
        )
        sweep_id = uuid.uuid4().hex
        # The immutable signature and validity window are durable before broadcast.
        self.store.begin_sweep(
            sweep_id,
            row["operator"],
            row["token_account"],
            amount_micro,
            signed.signature,
            signed.blockhash,
            signed.last_valid_block_height,
        )
        try:
            self._may_act()
            returned = self.rpc.send_transaction(signed.wire_b64)
            if returned != signed.signature:
                raise PayoutError(
                    "RPC returned a signature different from the signed sweep"
                )
        except RPCError as exc:
            LOG.warning("sweep broadcast ambiguous for %s: %s", sweep_id, exc)
        LOG.info(
            "sweep sent operator=%s account=%s amount_micro=%s signature=%s",
            row["operator"], row["token_account"], amount_micro, signed.signature,
        )
        return 1

    def _resolve_sweeps(self) -> int:
        changed = 0
        for sweep in self.store.sweeps_in_flight():
            try:
                changed += self._advance_sweep(sweep)
            except Exception:
                LOG.exception(
                    "sweep resolution failed operator=%s account=%s",
                    sweep["operator"], sweep["token_account"],
                )
        return changed

    def _start_sweeps(self) -> int:
        changed = 0
        in_flight = {
            row["token_account"] for row in self.store.sweeps_in_flight()
        }
        for row in self.store.sweep_accounts():
            account = str(row["token_account"])
            if (
                not int(row["indexer_ready"])
                or int(row["paused"])
                or account in in_flight
            ):
                continue
            try:
                snapshot = self.rpc.get_token_account(account)
                if (
                    snapshot.get("mint") != self.config.mint
                    or int(snapshot.get("decimals")) != USDC_DECIMALS
                ):
                    raise PayoutError("deposit account mint or decimals differ")
                self._validate_sweep_source(row, snapshot)
                balance = int(snapshot["amount"])
                if balance < self.config.sweep_min_micro:
                    continue
                indexed = int(row["indexed_credits"])
                swept = int(row["swept_micro"])
                if balance * RATE != indexed - swept * RATE:
                    LOG.info(
                        "sweep deferred for indexer lag operator=%s account=%s",
                        row["operator"], account,
                    )
                    continue
                context_slot = snapshot.get("slot")
                if (
                    isinstance(context_slot, bool)
                    or not isinstance(context_slot, int)
                    or context_slot < 0
                ):
                    raise PayoutError("deposit account balance has no valid context slot")
                signatures = self.rpc.get_signatures_for_address(
                    account, limit=1, min_context_slot=context_slot
                )
                newest = None
                if signatures:
                    first = signatures[0]
                    if not isinstance(first, dict) or not isinstance(
                        first.get("signature"), str
                    ):
                        raise PayoutError(
                            "newest deposit-account signature is malformed"
                        )
                    newest = first["signature"]
                confirmed_snapshot = self.rpc.get_token_account(account)
                if (
                    confirmed_snapshot.get("mint") != self.config.mint
                    or int(confirmed_snapshot.get("decimals")) != USDC_DECIMALS
                ):
                    raise PayoutError("deposit account mint or decimals differ")
                self._validate_sweep_source(row, confirmed_snapshot)
                confirmed_slot = confirmed_snapshot.get("slot")
                if (
                    isinstance(confirmed_slot, bool)
                    or not isinstance(confirmed_slot, int)
                    or confirmed_slot < context_slot
                ):
                    raise PayoutError("deposit account balance context regressed")
                if int(confirmed_snapshot["amount"]) != balance:
                    LOG.info(
                        "sweep deferred because balance changed during eligibility "
                        "operator=%s account=%s",
                        row["operator"], account,
                    )
                    continue
                if newest != row["cursor"]:
                    LOG.info(
                        "sweep deferred until indexer cursor catches up "
                        "operator=%s account=%s",
                        row["operator"], account,
                    )
                    continue
                changed += self._start_sweep(row, balance)
                in_flight.add(account)
            except Exception:
                LOG.exception(
                    "sweep failed operator=%s account=%s",
                    row["operator"], account,
                )
        return changed

    def _sweep_pass(self) -> int:
        return (
            PayoutEngine._resolve_sweeps(self)
            + PayoutEngine._start_sweeps(self)
        )

    def _build_and_send(self, row: dict[str, Any]) -> int:
        now = int(self.now())
        if self.store.withdraw_require_fresh_approval(row["id"], now):
            LOG.info("withdrawal %s requires a fresh human approval", row["id"])
            return 1
        if not self.store.withdrawal_approval_valid(row["id"], now):
            LOG.error("withdrawal %s has no valid bound approval", row["id"])
            return 0
        ata = self._ensure_recipient_ata(row["address"])
        latest = self.rpc.get_latest_blockhash()
        micro_usdc, remainder = divmod(int(row["amount"]), RATE)
        if remainder:
            raise PayoutError("withdrawal credits are not an exact micro-USDC amount")
        # Check both the mutable process gates and the durable human approval
        # immediately before the treasury key is asked to sign.
        self._may_act()
        now = int(self.now())
        if self.store.withdraw_require_fresh_approval(row["id"], now):
            LOG.info("withdrawal %s approval expired before signing", row["id"])
            return 1
        if not self.store.withdrawal_approval_valid(row["id"], now):
            return 0
        signed = self._backend().build_transfer(
            row["address"],
            ata,
            micro_usdc,
            latest["blockhash"],
            latest["last_valid_block_height"],
        )
        # This commit is deliberately before the first possible broadcast.
        self.store.withdraw_mark_sent(
            row["id"],
            signed.signature,
            signed.blockhash,
            signed.last_valid_block_height,
            signed.wire_b64,
        )
        try:
            # Signing can straddle the approval deadline. Never send a newly
            # signed transaction after its exact authorization has expired.
            self._may_act()
            if not self.store.withdrawal_approval_valid(
                row["id"], int(getattr(self, "now", time.time)())
            ):
                LOG.warning(
                    "withdrawal %s approval expired after signing; not broadcast",
                    row["id"],
                )
                return 1
            returned = self.rpc.send_transaction(signed.wire_b64)
            if returned != signed.signature:
                raise PayoutError("RPC returned a signature different from the signed transaction")
        except RPCError as exc:
            # Durable sent state makes this retryable after an ambiguous transport failure.
            LOG.warning("broadcast ambiguous for %s: %s", row["id"], exc)
        return 1

    def _advance_sent(self, row: dict[str, Any], frozen: bool = False) -> int:
        status = self.rpc.get_signature_status(row["tx_sig"])
        if status is not None:
            if status.get("err") is not None:
                if status.get("confirmationStatus") == "finalized":
                    # Only a finalized failure is permanently unable to land.
                    self.store.withdraw_mark_expired(row["id"])
                    return 1
                # A processed/confirmed failure may disappear with its fork;
                # its original transaction remains valid. Do not compete.
                return 0
            if status.get("confirmationStatus") == "finalized":
                self.store.withdraw_finalize(row["id"])
                return 1
            # Processed/confirmed means the old signature has landed and may
            # still finalize even after its blockhash window. Never build a
            # competing transfer while any successful status is visible.
            return 0
        height = self.rpc.get_block_height()
        if height > int(row["last_valid_block_height"]):
            # Status must be absent in a fresh history search made only after
            # observing a finalized height beyond the validity window.
            status = self.rpc.get_signature_status(row["tx_sig"])
            if status is None:
                self.store.withdraw_mark_expired(row["id"])
                self.store.withdraw_require_fresh_approval(
                    row["id"], int(getattr(self, "now", time.time)())
                )
                return 1
            if status.get("err") is not None:
                if status.get("confirmationStatus") == "finalized":
                    self.store.withdraw_mark_expired(row["id"])
                    return 1
                return 0
            if status.get("confirmationStatus") == "finalized":
                self.store.withdraw_finalize(row["id"])
                return 1
            return 0
        if frozen:
            # Status tracking above still runs; only a (re)broadcast moves value out.
            LOG.info(
                "withdrawal %s rebroadcast skipped because its roster key is suspended",
                row["id"],
            )
            return 0
        if not self.store.withdrawal_approval_valid(
            row["id"], int(getattr(self, "now", time.time)())
        ):
            LOG.info(
                "withdrawal %s rebroadcast withheld until its signed transaction "
                "expires; human approval is no longer valid",
                row["id"],
            )
            return 0
        # A crash may have happened after the durable mark and before broadcast.
        try:
            self._may_act()
            if not self.store.withdrawal_approval_valid(
                row["id"], int(getattr(self, "now", time.time)())
            ):
                LOG.info(
                    "withdrawal %s rebroadcast withheld because its approval "
                    "expired or changed during the safety check",
                    row["id"],
                )
                return 0
            returned = self.rpc.send_transaction(row["tx_wire"])
            if returned != row["tx_sig"]:
                raise PayoutError("RPC returned a signature different from the stored transaction")
        except RPCError as exc:
            LOG.warning("rebroadcast ambiguous for %s: %s", row["id"], exc)
        return 0

    def poll_once(self) -> int:
        # Resolution is bookkeeping only: it never signs or broadcasts.  It
        # must keep converging after an operator disables new money movement.
        changed = PayoutEngine._resolve_sweeps(self)
        if self.config.kill_file.exists():
            LOG.warning("payout kill file present: %s", self.config.kill_file)
            return changed

        frozen_operators = self._frozen_operators()
        frozen_withdrawals = {
            str(row["id"])
            for row in self.store.withdrawals("pending", "approved", "expired")
            if str(row["operator"]) in frozen_operators
        }
        for withdrawal_id in sorted(frozen_withdrawals):
            LOG.info(
                "withdrawal %s is frozen because its roster key is suspended",
                withdrawal_id,
            )

        changed += PayoutEngine._refresh_approval_lifetimes(self)
        if not self.config.enabled:
            changed += self._approve_pending(frozen_operators)
            for row in self.store.withdrawals(
                "approved", "expired", exclude_operators=frozen_operators
            ):
                LOG.info("DRY-RUN would send withdrawal %s", row["id"])
            for row in self.store.pending_deposit_accounts():
                LOG.info("DRY-RUN would create deposit account for %s", row["operator"])
            return changed

        # Internal consolidation is guarded like payouts, but has no cap or presence gate.
        changed += PayoutEngine._start_sweeps(self)
        changed += self._create_deposit_accounts()
        for row in self.store.withdrawals(
            "sent", exclude_operators=frozen_operators
        ):
            try:
                changed += self._advance_sent(
                    row, frozen=str(row["operator"]) in frozen_operators
                )
            except SafetyGateError:
                raise
            except Exception:
                LOG.exception(
                    "withdrawal sent step failed withdrawal=%s", row["id"]
                )
        # Sent attempts are resolved first so a transaction that aged out while
        # the daemon was down can re-enter the normal approval path this pass.
        changed += self._approve_pending(frozen_operators)
        for row in self.store.withdrawals(
            "expired", exclude_operators=frozen_operators
        ):
            try:
                if int(row["expiry_count"]) >= MAX_EXPIRIES:
                    self.store.withdraw_release(row["id"])
                    changed += 1
                else:
                    changed += self._build_and_send(row)
            except SafetyGateError:
                raise
            except Exception:
                LOG.exception(
                    "withdrawal retry step failed withdrawal=%s", row["id"]
                )
        for row in self.store.withdrawals(
            "approved", exclude_operators=frozen_operators
        ):
            try:
                changed += self._build_and_send(row)
            except SafetyGateError:
                raise
            except Exception:
                LOG.exception(
                    "withdrawal send step failed withdrawal=%s", row["id"]
                )
        return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", default=DEFAULT_STORE)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument(
        "--lock-file",
        default=os.environ.get("NAK_PAYOUT_LOCK_FILE", DEFAULT_LOCK_FILE),
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    lock_path = Path(os.path.expanduser(args.lock_file))
    process_lock = PayoutProcessLock.acquire(lock_path)
    if process_lock is None:
        LOG.info("payout worker already running; lock busy: %s", lock_path)
        return 0
    with process_lock:
        config = PayoutConfig.from_env()
        rpc = SolanaRPC(config.rpc_url)
        with LedgerStore(Path(os.path.expanduser(args.store))) as store:
            engine = PayoutEngine(
                store,
                rpc,
                config,
                backend_factory=lambda: SoldersTreasuryBackend(
                    rpc, config.mint, config.vault_account
                ),
            )
            while True:
                try:
                    engine.poll_once()
                except (OSError, RPCError, PayoutError, WithdrawalStateError) as exc:
                    LOG.error("payout pass failed closed: %s: %s", type(exc).__name__, exc)
                if args.once:
                    return 0
                time.sleep(max(args.interval, 0.2))


if __name__ == "__main__":
    raise SystemExit(main())
