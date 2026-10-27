"""Client primitives for the ``nakshatra_pay`` Solana program.

This module is deliberately a library: it derives addresses, builds instructions,
decodes accounts, verifies vouchers locally, and performs finalized RPC reads.  It
does not load wallet files, broadcast transactions, or run a background process.

The committed Anchor IDL is checked at import time.  Explicit builders below use
that checked account metadata for their account order and signer/write flags, while
their argument codecs are independently described by :data:`_ARG_LAYOUTS`.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import struct
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
try:
    from solders.instruction import AccountMeta, Instruction
    from solders.pubkey import Pubkey
except ModuleNotFoundError:  # Voucher verification intentionally has no solders dependency.
    AccountMeta = Instruction = Pubkey = None  # type: ignore[assignment,misc]

try:
    from .solana_rpc import RPCError, decode_base58
except ImportError:  # pragma: no cover - permits direct import from python/chain
    from solana_rpc import RPCError, decode_base58  # type: ignore


IDL_PATH = (
    Path(__file__).resolve().parents[2]
    / "programs"
    / "nakshatra_pay"
    / "idl"
    / "nakshatra_pay.json"
)
ANCHOR_TOML_PATH = IDL_PATH.parents[1] / "Anchor.toml"
with IDL_PATH.open("r", encoding="utf-8") as _idl_file:
    IDL: dict[str, Any] = json.load(_idl_file)
with ANCHOR_TOML_PATH.open("rb") as _anchor_file:
    _anchor = tomllib.load(_anchor_file)
try:
    _anchor_program_id = _anchor["programs"]["localnet"]["nakshatra_pay"]
except (KeyError, TypeError) as exc:
    raise RuntimeError(f"nakshatra_pay is missing from {ANCHOR_TOML_PATH}") from exc
if _anchor_program_id != IDL.get("address"):
    raise RuntimeError(
        f"program id mismatch: IDL has {IDL.get('address')!r}, "
        f"Anchor.toml has {_anchor_program_id!r}"
    )

def _constant_pubkey(value: str) -> Any:
    return value if Pubkey is None else Pubkey.from_string(value)


PROGRAM_ID = _constant_pubkey(IDL["address"])
SYSTEM_PROGRAM_ID = _constant_pubkey("11111111111111111111111111111111")
TOKEN_PROGRAM_ID = _constant_pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
ED25519_PROGRAM_ID = _constant_pubkey("Ed25519SigVerify111111111111111111111111111")
INSTRUCTIONS_SYSVAR_ID = _constant_pubkey(
    "Sysvar1nstructions1111111111111111111111111"
)
UPGRADEABLE_LOADER_ID = _constant_pubkey(
    "BPFLoaderUpgradeab1e11111111111111111111111"
)

VOUCHER_DOMAIN = b"NAK_PAY_VOUCHER1"
VERDICT_DOMAIN = b"NAK_PAY_VERDICT1"
VOUCHER_MESSAGE_LEN = 88
VERDICT_MESSAGE_LEN = 153
DELEGATE_OPEN_CHANNEL = 1
DELEGATE_OPEN_TASK = 2
DELEGATE_FLAGS_ALL = DELEGATE_OPEN_CHANNEL | DELEGATE_OPEN_TASK

PubkeyLike = Any


def _require_solders() -> None:
    if Pubkey is None:
        raise RuntimeError(
            "solders is required for PDA, instruction, and account-decoding operations"
        )


def _pubkey(value: PubkeyLike, name: str = "public key") -> Pubkey:
    _require_solders()
    if isinstance(value, Pubkey):
        return value
    try:
        if isinstance(value, str):
            return Pubkey.from_string(value)
        raw = bytes(value)
        if len(raw) != 32:
            raise ValueError(f"{name} must contain 32 bytes")
        return Pubkey.from_bytes(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {name}: {exc}") from exc


def _pubkey_bytes(value: Any, name: str = "public key") -> bytes:
    if Pubkey is not None and isinstance(value, Pubkey):
        return bytes(value)
    try:
        raw = decode_base58(value) if isinstance(value, str) else bytes(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {name}: {exc}") from exc
    if len(raw) != 32:
        raise ValueError(f"{name} must contain 32 bytes")
    return raw


def _encode_base58(raw: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    zeroes = len(raw) - len(raw.lstrip(b"\0"))
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    return "1" * zeroes + encoded


def _pubkey_text(value: Any, name: str = "public key") -> str:
    return _encode_base58(_pubkey_bytes(value, name))


def _u64(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**64:
        raise ValueError(f"{name} must be a u64")
    return value


def _pda(seeds: Sequence[bytes], program_id: PubkeyLike) -> tuple[Pubkey, int]:
    return Pubkey.find_program_address(list(seeds), _pubkey(program_id, "program id"))


def config_pda(program_id: PubkeyLike = PROGRAM_ID) -> tuple[Pubkey, int]:
    return _pda([b"config"], program_id)


def fee_vault_pda(
    config: PubkeyLike | None = None, program_id: PubkeyLike = PROGRAM_ID
) -> tuple[Pubkey, int]:
    config_key = config_pda(program_id)[0] if config is None else _pubkey(config, "config")
    return _pda([b"fee_vault", bytes(config_key)], program_id)


def owner_state_pda(
    owner: PubkeyLike,
    config: PubkeyLike | None = None,
    program_id: PubkeyLike = PROGRAM_ID,
) -> tuple[Pubkey, int]:
    config_key = config_pda(program_id)[0] if config is None else _pubkey(config, "config")
    return _pda([b"owner_state", bytes(config_key), bytes(_pubkey(owner, "owner"))], program_id)


def escrow_pda(
    owner: PubkeyLike,
    config: PubkeyLike | None = None,
    program_id: PubkeyLike = PROGRAM_ID,
) -> tuple[Pubkey, int]:
    config_key = config_pda(program_id)[0] if config is None else _pubkey(config, "config")
    return _pda([b"escrow", bytes(config_key), bytes(_pubkey(owner, "owner"))], program_id)


def vault_pda(escrow: PubkeyLike, program_id: PubkeyLike = PROGRAM_ID) -> tuple[Pubkey, int]:
    return _pda([b"vault", bytes(_pubkey(escrow, "escrow"))], program_id)


def delegate_pda(
    escrow: PubkeyLike, key: PubkeyLike, program_id: PubkeyLike = PROGRAM_ID
) -> tuple[Pubkey, int]:
    return _pda(
        [b"delegate", bytes(_pubkey(escrow, "escrow")), bytes(_pubkey(key, "delegate key"))],
        program_id,
    )


def channel_pda(
    escrow: PubkeyLike,
    generation: int,
    seq: int,
    program_id: PubkeyLike = PROGRAM_ID,
) -> tuple[Pubkey, int]:
    return _pda(
        [
            b"channel",
            bytes(_pubkey(escrow, "escrow")),
            struct.pack("<Q", _u64(generation, "generation")),
            struct.pack("<Q", _u64(seq, "seq")),
        ],
        program_id,
    )


def task_pda(
    escrow: PubkeyLike,
    generation: int,
    task_seq: int,
    program_id: PubkeyLike = PROGRAM_ID,
) -> tuple[Pubkey, int]:
    return _pda(
        [
            b"task",
            bytes(_pubkey(escrow, "escrow")),
            struct.pack("<Q", _u64(generation, "generation")),
            struct.pack("<Q", _u64(task_seq, "task_seq")),
        ],
        program_id,
    )


def event_authority_pda(program_id: PubkeyLike = PROGRAM_ID) -> tuple[Pubkey, int]:
    return _pda([b"__event_authority"], program_id)


def program_data_pda(program_id: PubkeyLike = PROGRAM_ID) -> tuple[Pubkey, int]:
    return _pda([bytes(_pubkey(program_id, "program id"))], UPGRADEABLE_LOADER_ID)


_ARG_LAYOUTS: dict[str, tuple[tuple[str, str], ...]] = {
    "channel_close_finalize": (),
    "channel_close_request": (),
    "channel_fund": (("add", "u64"),),
    "channel_open": (("worker", "pubkey"), ("cap", "u64")),
    "channel_redeem": (("cumulative_total", "u64"),),
    "config_accept_authority": (),
    "config_apply": (),
    "config_cancel": (),
    "config_init": (("fee_bps", "u16"),),
    "config_propose": (("fee_bps", "u16"),),
    "config_propose_authority": (("new_authority", "pubkey"),),
    "delegate_close": (),
    "delegate_revoke": (("key", "pubkey"),),
    "delegate_set": (
        ("key", "pubkey"),
        ("cap_total", "u64"),
        ("expires_at", "i64"),
        ("flags", "u8"),
    ),
    "escrow_close": (),
    "escrow_deposit": (("amount", "u64"),),
    "escrow_init": (),
    "escrow_withdraw_cancel": (),
    "escrow_withdraw_execute": (),
    "escrow_withdraw_request": (("amount", "u64"),),
    "fee_withdraw": (("amount", "u64"),),
    "task_open": (
        ("worker", "pubkey"),
        ("verifier", "pubkey"),
        ("amount", "u64"),
        ("deadline", "i64"),
        ("task_hash", "bytes32"),
    ),
    "task_submit": (("result_hash", "bytes32"),),
    "task_timeout": (),
    "task_verify": (("verdict", "verdict"),),
}

# SHA-256 of the normalized instruction names, discriminators, account
# order/signer/write/optional flags, and IDL argument declarations.  Updating the
# IDL therefore requires an intentional client review, rather than silently
# changing transaction privileges at import time.
_EXPECTED_INSTRUCTION_FINGERPRINT = (
    "162545c34ac7bf4435392840e8a0f59d9ef7f90b0afac8cc484961a5777ebccd"
)


def _idl_arg_kind(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value == {"array": ["u8", 32]}:
        return "bytes32"
    if value == {"defined": {"name": "Verdict"}}:
        return "verdict"
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _verify_idl() -> dict[str, dict[str, Any]]:
    instructions = IDL.get("instructions")
    if not isinstance(instructions, list):
        raise RuntimeError(f"invalid nakshatra_pay IDL at {IDL_PATH}: no instructions")
    normalized = [
        {
            "name": item.get("name"),
            "discriminator": item.get("discriminator"),
            "accounts": [
                [
                    account.get("name"),
                    bool(account.get("signer", False)),
                    bool(account.get("writable", False)),
                    bool(account.get("optional", False)),
                ]
                for account in item.get("accounts", [])
            ],
            "args": item.get("args"),
        }
        for item in instructions
    ]
    fingerprint = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if fingerprint != _EXPECTED_INSTRUCTION_FINGERPRINT:
        raise RuntimeError(
            "nakshatra_pay IDL instruction interface changed: "
            f"expected {_EXPECTED_INSTRUCTION_FINGERPRINT}, got {fingerprint}"
        )
    by_name = {item.get("name"): item for item in instructions}
    if set(by_name) != set(_ARG_LAYOUTS):
        missing = sorted(set(_ARG_LAYOUTS) - set(by_name))
        extra = sorted(set(by_name) - set(_ARG_LAYOUTS))
        raise RuntimeError(f"nakshatra_pay IDL/builder mismatch: missing={missing}, extra={extra}")
    for name, layout in _ARG_LAYOUTS.items():
        item = by_name[name]
        actual = tuple((arg["name"], _idl_arg_kind(arg["type"])) for arg in item["args"])
        if actual != layout:
            raise RuntimeError(
                f"nakshatra_pay IDL/builder argument mismatch for {name}: "
                f"IDL={actual!r}, builder={layout!r}"
            )
        discriminator = item.get("discriminator")
        if not isinstance(discriminator, list) or len(discriminator) != 8:
            raise RuntimeError(f"invalid instruction discriminator for {name}")
        for account in item.get("accounts", []):
            if not isinstance(account.get("name"), str):
                raise RuntimeError(f"invalid account metadata for {name}")
    return by_name


_IDL_INSTRUCTIONS = _verify_idl()

_DEFAULT_ACCOUNTS = {
    "system_program": SYSTEM_PROGRAM_ID,
    "token_program": TOKEN_PROGRAM_ID,
    "instructions_sysvar": INSTRUCTIONS_SYSVAR_ID,
}


def _encode_arg(kind: str, value: Any, name: str) -> bytes:
    if kind == "pubkey":
        return bytes(_pubkey(value, name))
    if kind == "bytes32":
        raw = bytes(value)
        if len(raw) != 32:
            raise ValueError(f"{name} must contain exactly 32 bytes")
        return raw
    if kind == "verdict":
        if isinstance(value, str):
            normalized = value.lower()
            if normalized not in {"pass", "fail"}:
                raise ValueError("verdict must be 'pass' or 'fail'")
            return bytes([0 if normalized == "pass" else 1])
        if isinstance(value, bool) or value not in {0, 1}:
            raise ValueError("verdict must be Pass/Fail or 0/1")
        return bytes([value])
    formats = {"u8": ("<B", 0, 2**8), "u16": ("<H", 0, 2**16), "u64": ("<Q", 0, 2**64), "i64": ("<q", -(2**63), 2**63)}
    try:
        fmt, low, high = formats[kind]
    except KeyError as exc:  # protected by the import-time IDL check
        raise RuntimeError(f"unsupported builder argument type {kind}") from exc
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value < high:
        raise ValueError(f"{name} must be a {kind}")
    return struct.pack(fmt, value)


def build_instruction(
    name: str,
    accounts: Mapping[str, PubkeyLike | None],
    *args: Any,
    program_id: PubkeyLike = PROGRAM_ID,
) -> Instruction:
    """Build one checked IDL instruction.

    Optional Anchor accounts use the program id sentinel when their value is
    ``None``.  Common program/sysvar accounts and Anchor's event accounts are
    filled automatically when omitted.
    """
    try:
        spec = _IDL_INSTRUCTIONS[name]
        arg_layout = _ARG_LAYOUTS[name]
    except KeyError as exc:
        raise ValueError(f"unknown nakshatra_pay instruction {name!r}") from exc
    if len(args) != len(arg_layout):
        raise TypeError(f"{name} expects {len(arg_layout)} arguments, got {len(args)}")
    program_key = _pubkey(program_id, "program id")
    metas: list[AccountMeta] = []
    used: set[str] = set()
    for account in spec["accounts"]:
        account_name = account["name"]
        used.add(account_name)
        value = accounts.get(account_name)
        if value is None and account_name == "program":
            value = program_key
        elif value is None and account_name == "event_authority":
            value = event_authority_pda(program_key)[0]
        elif value is None and account_name in _DEFAULT_ACCOUNTS:
            value = _DEFAULT_ACCOUNTS[account_name]
        elif value is None and account.get("optional", False):
            value = program_key
        elif value is None:
            raise ValueError(f"missing {name} account: {account_name}")
        metas.append(
            AccountMeta(
                _pubkey(value, f"{name}.{account_name}"),
                bool(account.get("signer", False)),
                bool(account.get("writable", False)),
            )
        )
    unexpected = set(accounts) - used
    if unexpected:
        raise ValueError(f"unexpected {name} accounts: {sorted(unexpected)}")
    data = bytes(spec["discriminator"]) + b"".join(
        _encode_arg(kind, value, arg_name)
        for (arg_name, kind), value in zip(arg_layout, args, strict=True)
    )
    return Instruction(program_key, data, metas)


# Explicit public builders.  Keeping these small makes call sites discoverable,
# while build_instruction remains the single implementation of IDL ordering.
def config_init(accounts: Mapping[str, PubkeyLike | None], fee_bps: int, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("config_init", accounts, fee_bps, program_id=program_id)


def config_propose(accounts: Mapping[str, PubkeyLike | None], fee_bps: int, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("config_propose", accounts, fee_bps, program_id=program_id)


def config_apply(accounts: Mapping[str, PubkeyLike | None], *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("config_apply", accounts, program_id=program_id)


def config_cancel(accounts: Mapping[str, PubkeyLike | None], *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("config_cancel", accounts, program_id=program_id)


def config_propose_authority(accounts: Mapping[str, PubkeyLike | None], new_authority: PubkeyLike, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("config_propose_authority", accounts, new_authority, program_id=program_id)


def config_accept_authority(accounts: Mapping[str, PubkeyLike | None], *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("config_accept_authority", accounts, program_id=program_id)


def fee_withdraw(accounts: Mapping[str, PubkeyLike | None], amount: int, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("fee_withdraw", accounts, amount, program_id=program_id)


def escrow_init(accounts: Mapping[str, PubkeyLike | None], *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("escrow_init", accounts, program_id=program_id)


def escrow_deposit(accounts: Mapping[str, PubkeyLike | None], amount: int, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("escrow_deposit", accounts, amount, program_id=program_id)


def escrow_withdraw_request(accounts: Mapping[str, PubkeyLike | None], amount: int, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("escrow_withdraw_request", accounts, amount, program_id=program_id)


def escrow_withdraw_cancel(accounts: Mapping[str, PubkeyLike | None], *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("escrow_withdraw_cancel", accounts, program_id=program_id)


def escrow_withdraw_execute(accounts: Mapping[str, PubkeyLike | None], *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("escrow_withdraw_execute", accounts, program_id=program_id)


def escrow_close(accounts: Mapping[str, PubkeyLike | None], *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("escrow_close", accounts, program_id=program_id)


def delegate_set(accounts: Mapping[str, PubkeyLike | None], key: PubkeyLike, cap_total: int, expires_at: int, flags: int, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("delegate_set", accounts, key, cap_total, expires_at, flags, program_id=program_id)


def delegate_revoke(accounts: Mapping[str, PubkeyLike | None], key: PubkeyLike, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("delegate_revoke", accounts, key, program_id=program_id)


def delegate_close(accounts: Mapping[str, PubkeyLike | None], *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("delegate_close", accounts, program_id=program_id)


def channel_open(accounts: Mapping[str, PubkeyLike | None], worker: PubkeyLike, cap: int, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("channel_open", accounts, worker, cap, program_id=program_id)


def channel_fund(accounts: Mapping[str, PubkeyLike | None], add: int, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("channel_fund", accounts, add, program_id=program_id)


def channel_redeem(accounts: Mapping[str, PubkeyLike | None], cumulative_total: int, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("channel_redeem", accounts, cumulative_total, program_id=program_id)


def channel_close_request(accounts: Mapping[str, PubkeyLike | None], *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("channel_close_request", accounts, program_id=program_id)


def channel_close_finalize(accounts: Mapping[str, PubkeyLike | None], *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("channel_close_finalize", accounts, program_id=program_id)


def task_open(accounts: Mapping[str, PubkeyLike | None], worker: PubkeyLike, verifier: PubkeyLike, amount: int, deadline: int, task_hash: bytes, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("task_open", accounts, worker, verifier, amount, deadline, task_hash, program_id=program_id)


def task_submit(accounts: Mapping[str, PubkeyLike | None], result_hash: bytes, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("task_submit", accounts, result_hash, program_id=program_id)


def task_verify(accounts: Mapping[str, PubkeyLike | None], verdict: str | int, *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("task_verify", accounts, verdict, program_id=program_id)


def task_timeout(accounts: Mapping[str, PubkeyLike | None], *, program_id: PubkeyLike = PROGRAM_ID) -> Instruction:
    return build_instruction("task_timeout", accounts, program_id=program_id)


def voucher_message(program: PubkeyLike, channel: PubkeyLike, total: int) -> bytes:
    message = (
        VOUCHER_DOMAIN
        + _pubkey_bytes(program, "program id")
        + _pubkey_bytes(channel, "channel")
        + struct.pack("<Q", _u64(total, "total"))
    )
    assert len(message) == VOUCHER_MESSAGE_LEN
    return message


def verdict_message(program: PubkeyLike, task: PubkeyLike, worker: PubkeyLike, amount: int, result_hash: bytes, verdict: str | int) -> bytes:
    result = bytes(result_hash)
    if len(result) != 32:
        raise ValueError("result_hash must contain exactly 32 bytes")
    verdict_byte = _encode_arg("verdict", verdict, "verdict")
    message = VERDICT_DOMAIN + _pubkey_bytes(program, "program id") + _pubkey_bytes(task, "task") + _pubkey_bytes(worker, "worker") + struct.pack("<Q", _u64(amount, "amount")) + result + verdict_byte
    assert len(message) == VERDICT_MESSAGE_LEN
    return message


def _private_key(key: Any) -> Ed25519PrivateKey:
    if isinstance(key, Ed25519PrivateKey):
        return key
    if hasattr(key, "secret"):
        key = key.secret()
    raw = bytes(key)
    if len(raw) == 64:  # Solana JSON/base58 keypair: seed || public key
        raw = raw[:32]
    if len(raw) != 32:
        raise ValueError("Ed25519 private key must be a 32-byte seed or 64-byte keypair")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _public_key(key: Any) -> Ed25519PublicKey:
    if isinstance(key, Ed25519PublicKey):
        return key
    return Ed25519PublicKey.from_public_bytes(_pubkey_bytes(key, "Ed25519 public key"))


def sign_voucher(key: Any, program: PubkeyLike, channel: PubkeyLike, total: int) -> bytes:
    return _private_key(key).sign(voucher_message(program, channel, total))


def verify_voucher(pubkey: Any, signature: bytes, program: PubkeyLike, channel: PubkeyLike, total: int) -> bool:
    try:
        _public_key(pubkey).verify(bytes(signature), voucher_message(program, channel, total))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sign_verdict(key: Any, program: PubkeyLike, task: PubkeyLike, worker: PubkeyLike, amount: int, result_hash: bytes, verdict: str | int) -> bytes:
    return _private_key(key).sign(verdict_message(program, task, worker, amount, result_hash, verdict))


def ed25519_instruction(pubkey: Any, signature: bytes, message: bytes) -> Instruction:
    _require_solders()
    public = pubkey.public_bytes_raw() if isinstance(pubkey, Ed25519PublicKey) else _pubkey_bytes(pubkey, "Ed25519 public key")
    signature_bytes = bytes(signature)
    message_bytes = bytes(message)
    if len(signature_bytes) != 64:
        raise ValueError("Ed25519 signature must contain exactly 64 bytes")
    if len(message_bytes) >= 2**16:
        raise ValueError("Ed25519 message is too long")
    header = bytes([1, 0]) + struct.pack(
        "<7H", 48, 0xFFFF, 16, 0xFFFF, 112, len(message_bytes), 0xFFFF
    )
    return Instruction(ED25519_PROGRAM_ID, header + public + signature_bytes + message_bytes, [])


def voucher_ed25519_instruction(pubkey: Any, signature: bytes, program: PubkeyLike, channel: PubkeyLike, total: int) -> Instruction:
    return ed25519_instruction(pubkey, signature, voucher_message(program, channel, total))


def verdict_ed25519_instruction(pubkey: Any, signature: bytes, program: PubkeyLike, task: PubkeyLike, worker: PubkeyLike, amount: int, result_hash: bytes, verdict: str | int) -> Instruction:
    return ed25519_instruction(pubkey, signature, verdict_message(program, task, worker, amount, result_hash, verdict))


@dataclass(frozen=True)
class VoucherRecord:
    channel: str
    total: int
    signature: bytes


class VoucherBook:
    """SQLite-backed monotonic voucher storage, safe for either side of a channel."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS vouchers (channel TEXT PRIMARY KEY, total TEXT NOT NULL, signature BLOB NOT NULL)"
        )

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "VoucherBook":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def latest(self, channel: PubkeyLike) -> VoucherRecord | None:
        channel_text = _pubkey_text(channel, "channel")
        row = self._db.execute(
            "SELECT total, signature FROM vouchers WHERE channel = ?", (channel_text,)
        ).fetchone()
        if row is None:
            return None
        return VoucherRecord(channel_text, int(row[0]), bytes(row[1]))

    def store(self, channel: PubkeyLike, total: int, signature: bytes) -> VoucherRecord:
        channel_text = _pubkey_text(channel, "channel")
        amount = _u64(total, "total")
        signature_bytes = bytes(signature)
        if len(signature_bytes) != 64:
            raise ValueError("voucher signature must contain exactly 64 bytes")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            row = self._db.execute(
                "SELECT total FROM vouchers WHERE channel = ?", (channel_text,)
            ).fetchone()
            if row is not None and amount < int(row[0]):
                raise ValueError(
                    f"voucher total {amount} is below stored total {int(row[0])}"
                )
            self._db.execute(
                "INSERT INTO vouchers(channel, total, signature) VALUES (?, ?, ?) "
                "ON CONFLICT(channel) DO UPDATE SET total=excluded.total, signature=excluded.signature",
                (channel_text, str(amount), signature_bytes),
            )
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        return VoucherRecord(channel_text, amount, signature_bytes)


@dataclass(frozen=True)
class PendingConfig:
    fee_bps: int
    fee_wallet: Pubkey
    effective_at: int


@dataclass(frozen=True)
class PendingWithdrawal:
    amount: int
    withdraw_at: int


@dataclass(frozen=True)
class Config:
    authority: Pubkey
    mint: Pubkey
    fee_wallet: Pubkey
    fee_bps: int
    withdraw_delay_s: int
    close_grace_s: int
    config_delay_s: int
    pending: PendingConfig | None
    pending_authority: Pubkey | None
    bump: int
    fee_vault_bump: int


@dataclass(frozen=True)
class OwnerState:
    next_generation: int
    bump: int


@dataclass(frozen=True)
class Escrow:
    owner: Pubkey
    vault: Pubkey
    committed: int
    open_channels: int
    open_tasks: int
    channel_seq: int
    task_seq: int
    generation: int
    pending_withdraw: PendingWithdrawal | None
    rent_payer: Pubkey
    bump: int
    vault_bump: int


@dataclass(frozen=True)
class Delegate:
    escrow: Pubkey
    key: Pubkey
    generation: int
    cap_total: int
    spent: int
    expires_at: int
    flags: int
    open_channels: int
    open_tasks: int
    disabled: bool
    bump: int


@dataclass(frozen=True)
class Channel:
    escrow: Pubkey
    generation: int
    seq: int
    worker: Pubkey
    voucher_signer: Pubkey
    delegate: Pubkey | None
    cap: int
    redeemed: int
    fee_bps_snapshot: int
    status: str
    close_at: int
    rent_payer: Pubkey
    bump: int


@dataclass(frozen=True)
class Task:
    escrow: Pubkey
    generation: int
    task_seq: int
    worker: Pubkey
    verifier: Pubkey
    amount: int
    deadline: int
    task_hash: bytes
    result_hash: bytes
    status: str
    submitted_at: int
    delegate: Pubkey | None
    fee_bps_snapshot: int
    rent_payer: Pubkey
    bump: int


class _Reader:
    def __init__(self, data: bytes):
        self.data = memoryview(data)
        self.offset = 0

    def take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise ValueError("account data is truncated")
        result = bytes(self.data[self.offset:end])
        self.offset = end
        return result

    def number(self, fmt: str) -> int:
        size = struct.calcsize(fmt)
        return int(struct.unpack(fmt, self.take(size))[0])

    def pubkey(self) -> Pubkey:
        _require_solders()
        return Pubkey.from_bytes(self.take(32))

    def boolean(self) -> bool:
        value = self.number("<B")
        if value not in {0, 1}:
            raise ValueError(f"invalid Borsh bool {value}")
        return bool(value)

    def option(self, read: Any) -> Any | None:
        tag = self.number("<B")
        if tag == 0:
            return None
        if tag != 1:
            raise ValueError(f"invalid Borsh option tag {tag}")
        return read()

    def finish(self) -> None:
        # Anchor allocates maximum space for optional fields, leaving zero padding.
        if any(self.data[self.offset:]):
            raise ValueError("account data contains unexpected trailing bytes")


_ACCOUNT_DISCRIMINATORS = {
    item["name"]: bytes(item["discriminator"]) for item in IDL["accounts"]
}

_ACCOUNT_LAYOUTS: dict[str, tuple[tuple[str, Any], ...]] = {
    "Config": (
        ("authority", "pubkey"), ("mint", "pubkey"), ("fee_wallet", "pubkey"),
        ("fee_bps", "u16"), ("withdraw_delay_s", "i64"), ("close_grace_s", "i64"),
        ("config_delay_s", "i64"), ("pending", {"option": {"defined": {"name": "PendingConfig"}}}),
        ("pending_authority", {"option": "pubkey"}), ("bump", "u8"),
        ("fee_vault_bump", "u8"),
    ),
    "Escrow": (
        ("owner", "pubkey"), ("vault", "pubkey"), ("committed", "u64"),
        ("open_channels", "u32"), ("open_tasks", "u32"), ("channel_seq", "u64"),
        ("task_seq", "u64"), ("generation", "u64"),
        ("pending_withdraw", {"option": {"defined": {"name": "PendingWithdrawal"}}}),
        ("rent_payer", "pubkey"), ("bump", "u8"), ("vault_bump", "u8"),
    ),
    "Delegate": (
        ("escrow", "pubkey"), ("key", "pubkey"), ("generation", "u64"),
        ("cap_total", "u64"), ("spent", "u64"), ("expires_at", "i64"),
        ("flags", "u8"), ("open_channels", "u32"), ("open_tasks", "u32"),
        ("disabled", "bool"), ("bump", "u8"),
    ),
    "Channel": (
        ("escrow", "pubkey"), ("generation", "u64"), ("seq", "u64"),
        ("worker", "pubkey"), ("voucher_signer", "pubkey"),
        ("delegate", {"option": "pubkey"}), ("cap", "u64"), ("redeemed", "u64"),
        ("fee_bps_snapshot", "u16"),
        ("status", {"defined": {"name": "ChannelStatus"}}), ("close_at", "i64"),
        ("rent_payer", "pubkey"), ("bump", "u8"),
    ),
    "Task": (
        ("escrow", "pubkey"), ("generation", "u64"), ("task_seq", "u64"),
        ("worker", "pubkey"), ("verifier", "pubkey"), ("amount", "u64"),
        ("deadline", "i64"), ("task_hash", {"array": ["u8", 32]}),
        ("result_hash", {"array": ["u8", 32]}),
        ("status", {"defined": {"name": "TaskStatus"}}), ("submitted_at", "i64"),
        ("delegate", {"option": "pubkey"}), ("fee_bps_snapshot", "u16"),
        ("rent_payer", "pubkey"), ("bump", "u8"),
    ),
    "OwnerState": (("next_generation", "u64"), ("bump", "u8")),
}


def _verify_account_layouts() -> None:
    by_name = {item["name"]: item for item in IDL.get("types", [])}
    for name, expected in _ACCOUNT_LAYOUTS.items():
        try:
            fields = by_name[name]["type"]["fields"]
        except (KeyError, TypeError) as exc:
            raise RuntimeError(f"nakshatra_pay IDL has no struct layout for {name}") from exc
        actual = tuple((field["name"], field["type"]) for field in fields)
        if actual != expected:
            raise RuntimeError(
                f"nakshatra_pay IDL/account-decoder mismatch for {name}: "
                f"IDL={actual!r}, decoder={expected!r}"
            )


_verify_account_layouts()


def _account_reader(name: str, data: bytes) -> _Reader:
    raw = bytes(data)
    expected = _ACCOUNT_DISCRIMINATORS[name]
    if len(raw) < 8 or raw[:8] != expected:
        raise ValueError(f"data is not a {name} account")
    return _Reader(raw[8:])


def decode_config(data: bytes) -> Config:
    r = _account_reader("Config", data)
    authority, mint, fee_wallet = r.pubkey(), r.pubkey(), r.pubkey()
    fee_bps = r.number("<H")
    withdraw_delay_s, close_grace_s, config_delay_s = r.number("<q"), r.number("<q"), r.number("<q")
    pending = r.option(lambda: PendingConfig(r.number("<H"), r.pubkey(), r.number("<q")))
    pending_authority = r.option(r.pubkey)
    result = Config(authority, mint, fee_wallet, fee_bps, withdraw_delay_s, close_grace_s, config_delay_s, pending, pending_authority, r.number("<B"), r.number("<B"))
    r.finish()
    return result


def decode_owner_state(data: bytes) -> OwnerState:
    r = _account_reader("OwnerState", data)
    result = OwnerState(r.number("<Q"), r.number("<B"))
    r.finish()
    return result


def decode_escrow(data: bytes) -> Escrow:
    r = _account_reader("Escrow", data)
    owner, vault = r.pubkey(), r.pubkey()
    committed = r.number("<Q")
    open_channels, open_tasks = r.number("<I"), r.number("<I")
    channel_seq, task_seq, generation = r.number("<Q"), r.number("<Q"), r.number("<Q")
    pending = r.option(lambda: PendingWithdrawal(r.number("<Q"), r.number("<q")))
    result = Escrow(owner, vault, committed, open_channels, open_tasks, channel_seq, task_seq, generation, pending, r.pubkey(), r.number("<B"), r.number("<B"))
    r.finish()
    return result


def decode_delegate(data: bytes) -> Delegate:
    r = _account_reader("Delegate", data)
    result = Delegate(r.pubkey(), r.pubkey(), r.number("<Q"), r.number("<Q"), r.number("<Q"), r.number("<q"), r.number("<B"), r.number("<I"), r.number("<I"), r.boolean(), r.number("<B"))
    r.finish()
    return result


def decode_channel(data: bytes) -> Channel:
    r = _account_reader("Channel", data)
    escrow, generation, seq = r.pubkey(), r.number("<Q"), r.number("<Q")
    worker, voucher_signer = r.pubkey(), r.pubkey()
    delegate = r.option(r.pubkey)
    cap, redeemed, fee_bps = r.number("<Q"), r.number("<Q"), r.number("<H")
    status_index = r.number("<B")
    if status_index not in {0, 1}:
        raise ValueError(f"invalid ChannelStatus variant {status_index}")
    result = Channel(escrow, generation, seq, worker, voucher_signer, delegate, cap, redeemed, fee_bps, ("Open", "Closing")[status_index], r.number("<q"), r.pubkey(), r.number("<B"))
    r.finish()
    return result


def decode_task(data: bytes) -> Task:
    r = _account_reader("Task", data)
    escrow, generation, task_seq = r.pubkey(), r.number("<Q"), r.number("<Q")
    worker, verifier = r.pubkey(), r.pubkey()
    amount, deadline = r.number("<Q"), r.number("<q")
    task_hash, result_hash = r.take(32), r.take(32)
    status_index = r.number("<B")
    if status_index not in {0, 1}:
        raise ValueError(f"invalid TaskStatus variant {status_index}")
    submitted_at = r.number("<q")
    delegate = r.option(r.pubkey)
    result = Task(escrow, generation, task_seq, worker, verifier, amount, deadline, task_hash, result_hash, ("Open", "Submitted")[status_index], submitted_at, delegate, r.number("<H"), r.pubkey(), r.number("<B"))
    r.finish()
    return result


_DECODERS = {
    "Config": decode_config,
    "Escrow": decode_escrow,
    "Delegate": decode_delegate,
    "Channel": decode_channel,
    "Task": decode_task,
    "OwnerState": decode_owner_state,
}
if set(_DECODERS) != set(_ACCOUNT_DISCRIMINATORS):
    raise RuntimeError("nakshatra_pay IDL/account-decoder mismatch")


def _read_account(
    rpc: Any,
    address: PubkeyLike,
    program_id: PubkeyLike = PROGRAM_ID,
) -> bytes:
    key = str(_pubkey(address, "account address"))
    result = rpc.call("getAccountInfo", [key, {"commitment": "finalized", "encoding": "base64"}])
    try:
        value = result["value"]
        if value is None:
            raise RPCError(f"account does not exist: {key}")
        if value["owner"] != _pubkey_text(program_id, "program id"):
            raise RPCError(
                f"account {key} is owned by {value['owner']}, not {_pubkey_text(program_id)}"
            )
        encoded = value["data"][0]
        return base64.b64decode(encoded, validate=True)
    except RPCError:
        raise
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise RPCError(f"getAccountInfo returned malformed data for {key}") from exc


@dataclass(frozen=True)
class EscrowStatus:
    address: Pubkey
    escrow: Escrow
    vault_balance: int
    committed: int
    available: int
    pending_withdraw: PendingWithdrawal | None


def get_escrow_status(
    rpc: Any,
    escrow: PubkeyLike,
    *,
    program_id: PubkeyLike = PROGRAM_ID,
) -> EscrowStatus:
    address = _pubkey(escrow, "escrow")
    state = decode_escrow(_read_account(rpc, address, program_id))
    token = rpc.get_token_account(str(state.vault))
    if token.get("owner") != str(address):
        raise RPCError(f"vault {state.vault} is not controlled by escrow {address}")
    balance = int(token["amount"])
    available = balance - state.committed
    if available < 0:
        raise RPCError(f"escrow {address} is undercollateralized")
    return EscrowStatus(address, state, balance, state.committed, available, state.pending_withdraw)


def get_channel_state(
    rpc: Any,
    channel: PubkeyLike,
    *,
    program_id: PubkeyLike = PROGRAM_ID,
) -> Channel:
    return decode_channel(_read_account(rpc, channel, program_id))


def get_task_state(
    rpc: Any,
    task: PubkeyLike,
    *,
    program_id: PubkeyLike = PROGRAM_ID,
) -> Task:
    return decode_task(_read_account(rpc, task, program_id))


__all__ = [name for name in globals() if not name.startswith("_")]
