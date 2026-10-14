#!/usr/bin/env python3
"""nak-treasury: the sole Solana treasury keyholder and payout worker.

The process is fail-closed: only devnet or loopback localnet RPCs are accepted,
``NAK_FUNDS`` defaults to ``off``, and the payout kill file prevents all work.
Transactions are signed offline by ``spl-token --sign-only``.  The resulting
signature and wire bytes are committed to SQLite before JSON-RPC broadcast.
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable

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


LOG = logging.getLogger("nak-treasury")
VAULT_SCRIPT = Path("/home/prithvi/trisul/infra/vault/vault.py")
WRITE_GATE_DIR = Path("/home/prithvi/trisul/infra/pillar-agent")
DEFAULT_STORE = "~/.neuron/credits/ledger.sqlite"
DEFAULT_KILL_FILE = "~/.neuron/credits/payout.off"
MICRO_USDC = 10 ** USDC_DECIMALS
AUTO_CAP_USDC = Decimal("5")
DAY_CAP_USDC = Decimal("50")
MAX_EXPIRIES = 3


class PayoutError(RuntimeError):
    """A payout operation was refused or could not be built safely."""


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


class CLITreasuryBackend:
    """Offline signer using installed Solana/SPL CLIs and private temp files.

    ``spl-token --sign-only`` produces a signed message without network I/O.
    This class assembles the one-signature wire transaction itself so the
    keyholder can durably mark it sent before calling ``sendTransaction``.
    """

    def __init__(
        self,
        rpc_url: str,
        mint: str,
        vault_account: str,
        *,
        secret_loader: Callable[[str], str] = vault_get,
        run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ):
        self.rpc_url = rpc_url
        self.mint = validate_pubkey(mint, "NAK_USDC_MINT")
        self.vault_account = validate_pubkey(
            vault_account, "NAK_TREASURY_USDC_ACCOUNT"
        )
        self._secret = _secret_bytes(secret_loader("nak-treasury-secret"))
        self._run_impl = run
        self.solana_keygen = self._tool("solana-keygen")
        self.spl_token = self._tool("spl-token")
        with self._private_keys() as (_directory, treasury, _account):
            self.pubkey = self._run(
                [self.solana_keygen, "pubkey", str(treasury)]
            ).stdout.strip()
        validate_pubkey(self.pubkey, "treasury public key")

    @staticmethod
    def _tool(name: str) -> str:
        path = shutil.which(name)
        if path is None:
            raise PayoutError(f"required executable is missing: {name}")
        return path

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        result = self._run_impl(
            argv,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=45,
            check=False,
        )
        if result.returncode != 0:
            raise PayoutError(
                f"{Path(argv[0]).name} failed: {result.stderr.strip()[:500]}"
            )
        return result

    def _private_keys(self):
        backend = self

        class Keys:
            def __enter__(self):
                self.temp = tempfile.TemporaryDirectory(prefix="nak-treasury-")
                directory = Path(self.temp.name)
                os.chmod(directory, 0o700)
                treasury = directory / "treasury.json"
                fd = os.open(treasury, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.write(fd, json.dumps(list(backend._secret)).encode("ascii"))
                finally:
                    os.close(fd)
                return directory, treasury, directory / "account.json"

            def __exit__(self, exc_type, exc, tb):
                self.temp.cleanup()

        return Keys()

    def create_deposit_account(self) -> str:
        with self._private_keys() as (_directory, treasury, account):
            self._run(
                [
                    self.solana_keygen,
                    "new",
                    "--no-bip39-passphrase",
                    "--silent",
                    "--force",
                    "-o",
                    str(account),
                ]
            )
            os.chmod(account, 0o600)
            address = self._run(
                [self.solana_keygen, "pubkey", str(account)]
            ).stdout.strip()
            self._run(
                [
                    self.spl_token,
                    "--url",
                    self.rpc_url,
                    "--fee-payer",
                    str(treasury),
                    "--output",
                    "json",
                    "create-account",
                    self.mint,
                    str(account),
                    "--owner",
                    self.pubkey,
                ]
            )
            return validate_pubkey(address, "deposit token account")

    def recipient_ata(self, owner: str) -> str:
        owner = validate_pubkey(owner, "withdrawal address")
        result = self._run(
            [
                self.spl_token,
                "--url",
                self.rpc_url,
                "--output",
                "json",
                "address",
                "--verbose",
                "--token",
                self.mint,
                "--owner",
                owner,
            ]
        )
        try:
            payload = json.loads(result.stdout)
            address = payload["associatedTokenAddress"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise PayoutError("spl-token returned malformed address output") from exc
        return validate_pubkey(address, "recipient ATA")

    def create_recipient_ata(self, owner: str) -> str:
        owner = validate_pubkey(owner, "withdrawal address")
        with self._private_keys() as (_directory, treasury, _account):
            self._run(
                [
                    self.spl_token,
                    "--url",
                    self.rpc_url,
                    "--fee-payer",
                    str(treasury),
                    "--output",
                    "json",
                    "create-account",
                    self.mint,
                    "--owner",
                    owner,
                ]
            )
        return self.recipient_ata(owner)

    def build_transfer(
        self,
        destination: str,
        micro_usdc: int,
        blockhash: str,
        last_valid_block_height: int,
    ) -> SignedTransaction:
        destination = validate_pubkey(destination, "recipient ATA")
        blockhash = validate_pubkey(blockhash, "blockhash")
        if micro_usdc <= 0:
            raise PayoutError("transfer amount must be positive")
        with self._private_keys() as (_directory, treasury, _account):
            result = self._run(
                [
                    self.spl_token,
                    "--url",
                    self.rpc_url,
                    "--output",
                    "json",
                    "transfer",
                    self.mint,
                    _micro_usdc_string(micro_usdc),
                    destination,
                    "--from",
                    self.vault_account,
                    "--owner",
                    str(treasury),
                    "--fee-payer",
                    str(treasury),
                    "--allow-non-system-account-recipient",
                    "--sign-only",
                    "--blockhash",
                    blockhash,
                    "--mint-decimals",
                    str(USDC_DECIMALS),
                    "--dump-transaction-message",
                ]
            )
        try:
            payload = json.loads(result.stdout)
            message = base64.b64decode(payload["message"], validate=True)
            signers = payload["signers"]
            pair = next(item for item in signers if item.startswith(self.pubkey + "="))
            signature = pair.split("=", 1)[1]
            signature_bytes = decode_base58(signature)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError, StopIteration) as exc:
            raise PayoutError("spl-token returned malformed sign-only output") from exc
        if len(signature_bytes) != 64:
            raise PayoutError("spl-token returned a malformed signature")
        # Legacy Solana wire format: compact-u16 signature count, signatures,
        # then the exact message signed by the CLI. Treasury is the only signer.
        wire = b"\x01" + signature_bytes + message
        return SignedTransaction(
            signature=signature,
            wire_b64=base64.b64encode(wire).decode("ascii"),
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
        )


def _default_presence(row: dict[str, Any], description: str, wait_s: int):
    """Lazy adapter to the one approved human-presence doorway."""
    if str(WRITE_GATE_DIR) not in sys.path:
        sys.path.insert(0, str(WRITE_GATE_DIR))
    import write_gate  # type: ignore

    return write_gate._fingerprint_presence(
        write_gate.owner_keyid(),
        "nak.payout",
        f"withdrawal:{row['id']}",
        description,
        wait_s,
    )


class PayoutEngine:
    def __init__(
        self,
        store: LedgerStore,
        rpc: Any,
        config: PayoutConfig,
        *,
        backend: Any | None = None,
        backend_factory: Callable[[], Any] | None = None,
        presence: Callable[[dict[str, Any], str, int], tuple[bool, Any]] = _default_presence,
        now: Callable[[], float] = time.time,
    ):
        self.store = store
        self.rpc = rpc
        self.config = config
        self._backend_value = backend
        self._backend_factory = backend_factory
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
            created = backend.create_recipient_ata(address)
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

    def _approve_pending(self) -> int:
        changed = 0
        for row in self.store.withdrawals("pending"):
            today = self.store.approved_withdrawal_total_since(self._midnight_utc())
            automatic = (
                int(row["amount"]) <= self.config.auto_cap
                and today + int(row["amount"]) <= self.config.day_cap
            )
            if automatic:
                self.store.withdraw_approve(row["id"], "auto:devnet-caps-v1")
                changed += 1
                continue
            if not self.config.enabled:
                LOG.info("DRY-RUN human approval required for %s", row["id"])
                continue
            ok, granted = self.presence(
                row, self._description(row), self.config.presence_wait_s
            )
            if ok:
                if isinstance(granted, dict):
                    reference = (
                        granted.get("challenge")
                        or granted.get("signature")
                        or granted.get("signer")
                        or "presence"
                    )
                else:
                    reference = "presence"
                self.store.withdraw_approve(row["id"], f"human:{reference}")
                changed += 1
            else:
                attempts = self.store.withdraw_presence_attempt(row["id"])
                if attempts >= 2:
                    self.store.withdraw_release(row["id"])
                changed += 1
        return changed

    def _create_deposit_accounts(self) -> int:
        changed = 0
        for row in self.store.pending_deposit_accounts():
            try:
                token_account = self._backend().create_deposit_account()
                self._wait_for_account(token_account)
                self.store.register_deposit_account(row["operator"], token_account)
                changed += 1
            except (OSError, RPCError, PayoutError, ValueError) as exc:
                self.store.record_deposit_account_error(
                    row["operator"], f"{type(exc).__name__}: {exc}"
                )
                LOG.error("deposit account creation failed for %s: %s", row["operator"], exc)
        return changed

    def _build_and_send(self, row: dict[str, Any]) -> int:
        ata = self._ensure_recipient_ata(row["address"])
        latest = self.rpc.get_latest_blockhash()
        micro_usdc, remainder = divmod(int(row["amount"]), RATE)
        if remainder:
            raise PayoutError("withdrawal credits are not an exact micro-USDC amount")
        signed = self._backend().build_transfer(
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
            returned = self.rpc.send_transaction(signed.wire_b64)
            if returned != signed.signature:
                raise PayoutError("RPC returned a signature different from the signed transaction")
        except RPCError as exc:
            # Durable sent state makes this retryable after an ambiguous transport failure.
            LOG.warning("broadcast ambiguous for %s: %s", row["id"], exc)
        return 1

    def _advance_sent(self, row: dict[str, Any]) -> int:
        status = self.rpc.get_signature_status(row["tx_sig"])
        if status is not None:
            if status.get("err") is not None:
                # A landed failed transaction cannot later transfer funds.
                self.store.withdraw_mark_expired(row["id"])
                return 1
            if status.get("confirmationStatus") == "finalized":
                self.store.withdraw_finalize(row["id"])
                return 1
            # Processed/confirmed means the old signature has landed and may
            # still finalize even after its blockhash window. Never build a
            # competing transfer while any successful status is visible.
            return 0
        height = self.rpc.get_block_height()
        if height > int(row["last_valid_block_height"]):
            self.store.withdraw_mark_expired(row["id"])
            return 1
        # A crash may have happened after the durable mark and before broadcast.
        try:
            returned = self.rpc.send_transaction(row["tx_wire"])
            if returned != row["tx_sig"]:
                raise PayoutError("RPC returned a signature different from the stored transaction")
        except RPCError as exc:
            LOG.warning("rebroadcast ambiguous for %s: %s", row["id"], exc)
        return 0

    def poll_once(self) -> int:
        if self.config.kill_file.exists():
            LOG.warning("payout kill file present: %s", self.config.kill_file)
            return 0

        changed = self._approve_pending()
        if not self.config.enabled:
            for row in self.store.withdrawals("approved", "expired"):
                LOG.info("DRY-RUN would send withdrawal %s", row["id"])
            for row in self.store.pending_deposit_accounts():
                LOG.info("DRY-RUN would create deposit account for %s", row["operator"])
            return changed

        changed += self._create_deposit_accounts()
        for row in self.store.withdrawals("sent"):
            changed += self._advance_sent(row)
        for row in self.store.withdrawals("expired"):
            if int(row["expiry_count"]) >= MAX_EXPIRIES:
                self.store.withdraw_release(row["id"])
                changed += 1
            else:
                changed += self._build_and_send(row)
        for row in self.store.withdrawals("approved"):
            changed += self._build_and_send(row)
        return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", default=DEFAULT_STORE)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = PayoutConfig.from_env()
    rpc = SolanaRPC(config.rpc_url)
    with LedgerStore(Path(os.path.expanduser(args.store))) as store:
        engine = PayoutEngine(
            store,
            rpc,
            config,
            backend_factory=lambda: CLITreasuryBackend(
                config.rpc_url, config.mint, config.vault_account
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
