#!/usr/bin/env python3
"""Devnet-only deployment and Squads v4 authority handover for nakshatra_pay.

This intentionally uses only the Python standard library and the installed Solana
CLI.  Squads v4 instructions and Solana legacy transactions are encoded here so
the operator does not have to trust an additional SDK dependency.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


PROGRAM_ID = "GLWqQsSqUsDkPvkc8rxcoQUyro7ZQd5denht21NtdTTo"
SQUADS_PROGRAM_ID = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
UPGRADEABLE_LOADER_ID = "BPFLoaderUpgradeab1e11111111111111111111111"
TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
ASSOCIATED_TOKEN_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"
DEVNET_USDC_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
DEVNET_GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
DEVNET_RPC = "https://api.devnet.solana.com"
MAX_RPC_BODY = 8 * 1024 * 1024

SOLANA_BIN = Path("/home/prithvi/.local/share/solana/install/active_release/bin")
SOLANA = SOLANA_BIN / "solana"
SOLANA_KEYGEN = SOLANA_BIN / "solana-keygen"
SPL_TOKEN = SOLANA_BIN / "spl-token"

ROOT = Path(__file__).resolve().parents[1]
IDL_PATH = ROOT / "idl" / "nakshatra_pay.json"

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {c: i for i, c in enumerate(B58_ALPHABET)}

# Ed25519 constants.  The small implementation below is used only to sign a
# transaction message already assembled in memory; key material is never logged.
Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, Q - 2, Q)) % Q
I = pow(2, (Q - 1) // 4, Q)


class DeployError(RuntimeError):
    pass


class RefuseRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Make every JSON-RPC redirect a hard failure."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"redirect refused to {newurl}",
            headers,
            fp,
        )


def validate_rpc_url(url: str, rehearsal: bool) -> None:
    """Accept only the one production endpoint or a literal rehearsal loopback."""
    if not rehearsal:
        if url != DEVNET_RPC:
            raise DeployError(f"production --url must be exactly {DEVNET_RPC}")
        return
    match = re.fullmatch(r"http://127\.0\.0\.1:([0-9]+)", url)
    if match is None:
        raise DeployError("rehearsal --url must be exactly http://127.0.0.1:<port>")
    port = int(match.group(1))
    if port < 1 or port > 65535:
        raise DeployError("rehearsal --url port must be between 1 and 65535")


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    chars: list[str] = []
    while n:
        n, r = divmod(n, 58)
        chars.append(B58_ALPHABET[r])
    zeroes = len(raw) - len(raw.lstrip(b"\0"))
    return "1" * zeroes + ("".join(reversed(chars)) if chars else "")


def b58decode(value: str) -> bytes:
    n = 0
    try:
        for char in value:
            n = n * 58 + B58_INDEX[char]
    except KeyError as exc:
        raise DeployError("invalid base58 value") from exc
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(value) - len(value.lstrip("1"))) + raw


def pubkey(value: str) -> bytes:
    raw = b58decode(value)
    if len(raw) != 32:
        raise DeployError(f"invalid public key: {value}")
    return raw


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(D * y * y + 1, Q - 2, Q) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q:
        x = x * I % Q
    if x & 1:
        x = Q - x
    return x


BY = 4 * pow(5, Q - 2, Q) % Q
BX = _xrecover(BY)
BASE = (BX, BY, 1, BX * BY % Q)
IDENTITY = (0, 1, 1, 0)


def _point_add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % Q
    b = (y1 + x1) * (y2 + x2) % Q
    c = 2 * D * t1 * t2 % Q
    d2 = 2 * z1 * z2 % Q
    e = b - a
    f = d2 - c
    g = d2 + c
    h = b + a
    return e * f % Q, g * h % Q, f * g % Q, e * h % Q


def _scalar_mult(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _point_encode(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    zi = pow(z, Q - 2, Q)
    x = x * zi % Q
    y = y * zi % Q
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _public_from_seed(seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(bytes([h[0] & 248]) + h[1:31] + bytes([(h[31] & 63) | 64]), "little")
    return _point_encode(_scalar_mult(BASE, scalar))


def _sign(seed: bytes, public: bytes, message: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    scalar_bytes = bytes([h[0] & 248]) + h[1:31] + bytes([(h[31] & 63) | 64])
    scalar = int.from_bytes(scalar_bytes, "little")
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % L
    encoded_r = _point_encode(_scalar_mult(BASE, r))
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % L
    return encoded_r + ((r + challenge * scalar) % L).to_bytes(32, "little")


def _is_curve_point(encoded: bytes) -> bool:
    if len(encoded) != 32:
        return False
    value = int.from_bytes(encoded, "little")
    y = value & ((1 << 255) - 1)
    if y >= Q:
        return False
    x = _xrecover(y)
    if ((x * x - (y * y - 1) * pow(D * y * y + 1, Q - 2, Q)) % Q) != 0:
        return False
    if (x & 1) != (value >> 255):
        x = Q - x
    return (y * y - x * x - 1 - D * x * x * y * y) % Q == 0


def find_pda(seeds: Sequence[bytes], program: str | bytes) -> tuple[bytes, int]:
    program_raw = pubkey(program) if isinstance(program, str) else program
    if any(len(seed) > 32 for seed in seeds):
        raise DeployError("PDA seed exceeds 32 bytes")
    for bump in range(255, -1, -1):
        digest = hashlib.sha256(b"".join([*seeds, bytes([bump]), program_raw, b"ProgramDerivedAddress"])).digest()
        if not _is_curve_point(digest):
            return digest, bump
    raise DeployError("unable to derive PDA")


def shortvec(value: int) -> bytes:
    if value < 0:
        raise DeployError("negative shortvec")
    out = bytearray()
    while True:
        elem = value & 0x7F
        value >>= 7
        if value:
            elem |= 0x80
        out.append(elem)
        if not value:
            return bytes(out)


def u8(value: int) -> bytes:
    return struct.pack("<B", value)


def u16(value: int) -> bytes:
    return struct.pack("<H", value)


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def option(value: bytes | None) -> bytes:
    return b"\0" if value is None else b"\1" + value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_print(value: dict[str, Any]) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def run_cli(args: Sequence[str | os.PathLike[str]]) -> str:
    command = [str(arg) for arg in args]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode:
        message = result.stderr.strip() or result.stdout.strip() or "command failed"
        # `solana program deploy` prints a randomly generated buffer recovery
        # phrase on some failures.  Defense in depth: never propagate that
        # secret even though normal deploys always use our explicit buffer.
        message = re.sub(
            r"(?s)(Recover the intermediate account's ephemeral keypair file with.*?seed phrase:).*?(To resume a deploy)",
            r"\1\n[REDACTED]\n\2",
            message,
        )
        raise DeployError(message)
    return result.stdout.strip()


class Rpc:
    def __init__(self, url: str, timeout: float = 30.0):
        self.url = url
        self.timeout = timeout
        self._request_id = 0
        self._opener = urllib.request.build_opener(RefuseRedirectHandler())

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        self._request_id += 1
        body = json.dumps(
            {"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": params or []},
            separators=(",", ":"),
        ).encode()
        request = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                payload = json.loads(response.read(8 * 1024 * 1024))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise DeployError(f"RPC {method} failed: {exc}") from exc
        if payload.get("error") is not None:
            error = payload["error"]
            message = error.get("message", str(error)) if isinstance(error, dict) else str(error)
            data = error.get("data") if isinstance(error, dict) else None
            if isinstance(data, dict) and data.get("logs"):
                message += ": " + " | ".join(str(line) for line in data["logs"])
            raise DeployError(f"RPC {method}: {message}")
        if "result" not in payload:
            raise DeployError(f"RPC {method} returned no result")
        return payload["result"]

    def account(self, address: str) -> dict[str, Any] | None:
        result = self.call("getAccountInfo", [address, {"encoding": "base64", "commitment": "confirmed"}])
        value = result.get("value")
        if value is None:
            return None
        data = value.get("data")
        if not isinstance(data, list) or len(data) < 1:
            raise DeployError(f"account {address} has an unsupported encoding")
        value = dict(value)
        value["data_raw"] = base64.b64decode(data[0], validate=True)
        return value


class CliRpcProxy:
    """Loopback-only, no-redirect JSON-RPC forwarder for untrusted CLI clients."""

    def __init__(self, rpc: Rpc, rehearsal: bool):
        self.rpc = rpc
        self.rehearsal = rehearsal
        self.server: http.server.ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> str:
        # Intentionally repeat the guard immediately before each external CLI.
        # A stateful endpoint cannot pass the command guard and then pivot the
        # CLI to another cluster.
        cluster_guard(self.rpc, self.rehearsal)
        forwarder = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *_args: Any) -> None:
                pass

            def _failure(self, message: str) -> None:
                body = json.dumps(
                    {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": message}},
                    separators=(",", ":"),
                ).encode()
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                length_text = self.headers.get("Content-Length")
                if length_text is None or not length_text.isdigit():
                    self._failure("RPC request requires Content-Length")
                    return
                length = int(length_text)
                if length > MAX_RPC_BODY:
                    self._failure("RPC request body is too large")
                    return
                body = self.rfile.read(length)
                request = urllib.request.Request(
                    forwarder.rpc.url,
                    data=body,
                    headers={"Content-Type": self.headers.get("Content-Type", "application/json")},
                    method="POST",
                )
                try:
                    with forwarder.rpc._opener.open(request, timeout=forwarder.rpc.timeout) as response:
                        if 300 <= response.status < 400:
                            raise DeployError(f"RPC redirect refused (HTTP {response.status})")
                        response_body = response.read(MAX_RPC_BODY + 1)
                        if len(response_body) > MAX_RPC_BODY:
                            raise DeployError("RPC response body is too large")
                        content_type = response.headers.get("Content-Type", "application/json")
                        status = response.status
                except urllib.error.HTTPError as exc:
                    if 300 <= exc.code < 400:
                        self._failure(f"RPC redirect refused (HTTP {exc.code})")
                    else:
                        self._failure(f"upstream RPC HTTP error {exc.code}")
                    return
                except (OSError, urllib.error.URLError, DeployError) as exc:
                    self._failure(str(exc))
                    return
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(response_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(response_body)

            def do_GET(self) -> None:
                # Websocket upgrades and all non-JSON-RPC traffic fail closed.
                self._failure("only JSON-RPC POST requests are allowed")

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_port}"

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join()


def cluster_guard(rpc: Rpc, rehearsal: bool) -> str:
    genesis = rpc.call("getGenesisHash")
    host = urllib.parse.urlparse(rpc.url).hostname
    if genesis == DEVNET_GENESIS:
        if rehearsal:
            raise DeployError("--rehearsal is only valid with a validator on 127.0.0.1")
        return genesis
    if rehearsal and host == "127.0.0.1":
        return genesis
    raise DeployError(f"refusing write: RPC genesis {genesis} is not devnet")


def load_keypair(path: Path) -> tuple[bytes, bytes]:
    try:
        values = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise DeployError(f"cannot read keypair at {path}") from exc
    if not isinstance(values, list) or len(values) != 64 or any(not isinstance(x, int) or x < 0 or x > 255 for x in values):
        raise DeployError(f"invalid keypair at {path}")
    raw = bytes(values)
    public = _public_from_seed(raw[:32])
    if public != raw[32:]:
        raise DeployError(f"keypair public key mismatch at {path}")
    return raw[:32], public


def create_keypair(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    seed = secrets.token_bytes(32)
    public = _public_from_seed(seed)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(list(seed + public), handle, separators=(",", ":"))
            handle.write("\n")
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return public


@dataclass(frozen=True)
class Meta:
    key: bytes
    signer: bool = False
    writable: bool = False


@dataclass(frozen=True)
class Instruction:
    program_id: bytes
    accounts: tuple[Meta, ...]
    data: bytes


def compile_message(payer: bytes, instructions: Sequence[Instruction], recent_blockhash: bytes) -> tuple[bytes, list[bytes]]:
    flags: dict[bytes, list[bool]] = {payer: [True, True]}
    encountered: list[bytes] = [payer]
    for ix in instructions:
        for meta in ix.accounts:
            if meta.key not in flags:
                flags[meta.key] = [meta.signer, meta.writable]
                encountered.append(meta.key)
            else:
                flags[meta.key][0] |= meta.signer
                flags[meta.key][1] |= meta.writable
        if ix.program_id not in flags:
            flags[ix.program_id] = [False, False]
            encountered.append(ix.program_id)
    flags[payer] = [True, True]
    categories = (
        lambda k: k != payer and flags[k] == [True, True],
        lambda k: k != payer and flags[k] == [True, False],
        lambda k: not flags[k][0] and flags[k][1],
        lambda k: not flags[k][0] and not flags[k][1],
    )
    keys = [payer]
    for predicate in categories:
        keys.extend(key for key in encountered if key not in keys and predicate(key))
    signers = [key for key in keys if flags[key][0]]
    readonly_signed = sum(1 for key in signers if not flags[key][1])
    readonly_unsigned = sum(1 for key in keys[len(signers):] if not flags[key][1])
    index = {key: i for i, key in enumerate(keys)}
    body = bytearray([len(signers), readonly_signed, readonly_unsigned])
    body += shortvec(len(keys)) + b"".join(keys) + recent_blockhash
    body += shortvec(len(instructions))
    for ix in instructions:
        account_indexes = bytes(index[meta.key] for meta in ix.accounts)
        body += bytes([index[ix.program_id]])
        body += shortvec(len(account_indexes)) + account_indexes
        body += shortvec(len(ix.data)) + ix.data
    return bytes(body), signers


def send_instructions(rpc: Rpc, payer_path: Path, instructions: Sequence[Instruction], extra_signers: Sequence[Path] = ()) -> str:
    seed, payer = load_keypair(payer_path)
    keypairs: dict[bytes, bytes] = {payer: seed}
    for path in extra_signers:
        extra_seed, extra_public = load_keypair(path)
        keypairs[extra_public] = extra_seed
    latest = rpc.call("getLatestBlockhash", [{"commitment": "confirmed"}])
    blockhash = b58decode(latest["value"]["blockhash"])
    message, signer_keys = compile_message(payer, instructions, blockhash)
    missing = [b58encode(key) for key in signer_keys if key not in keypairs]
    if missing:
        raise DeployError("missing transaction signer(s): " + ",".join(missing))
    signatures = [_sign(keypairs[key], key, message) for key in signer_keys]
    transaction = shortvec(len(signatures)) + b"".join(signatures) + message
    signature = rpc.call(
        "sendTransaction",
        [base64.b64encode(transaction).decode(), {"encoding": "base64", "preflightCommitment": "confirmed"}],
    )
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status = rpc.call("getSignatureStatuses", [[signature], {"searchTransactionHistory": True}])["value"][0]
        if status is not None:
            if status.get("err") is not None:
                raise DeployError(f"transaction {signature} failed: {status['err']}")
            if status.get("confirmationStatus") in ("confirmed", "finalized"):
                return signature
        time.sleep(0.25)
    raise DeployError(f"transaction confirmation timed out: {signature}")


class State:
    def __init__(self, directory: Path):
        self.directory = directory
        self.path = directory / "state.json"
        self.data: dict[str, Any] = {}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                raise DeployError(f"invalid state file: {self.path}") from exc
            if not isinstance(self.data, dict):
                raise DeployError(f"invalid state file (expected a JSON object): {self.path}")

    def save(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(self.data, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.replace(temporary, self.path)


def require_state(state: State, *fields: str) -> None:
    missing = [field for field in fields if state.data.get(field) is None]
    if missing:
        raise DeployError("missing deployment state; run prerequisite command(s): " + ",".join(missing))


def pay_idl() -> dict[str, Any]:
    try:
        return json.loads(IDL_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise DeployError(f"cannot read IDL at {IDL_PATH}") from exc


def pay_ix(name: str, accounts: Sequence[Meta], args: bytes = b"") -> Instruction:
    idl = pay_idl()
    entry = next((item for item in idl.get("instructions", []) if item.get("name") == name), None)
    if entry is None:
        raise DeployError(f"IDL instruction missing: {name}")
    expected = entry.get("accounts", [])
    if len(expected) != len(accounts):
        raise DeployError(f"IDL account count changed for {name}")
    for spec, meta in zip(expected, accounts):
        if bool(spec.get("signer")) != meta.signer or bool(spec.get("writable")) != meta.writable:
            raise DeployError(f"IDL account flags changed for {name}:{spec.get('name')}")
    return Instruction(pubkey(PROGRAM_ID), tuple(accounts), bytes(entry["discriminator"]) + args)


def event_authority() -> bytes:
    return find_pda([b"__event_authority"], PROGRAM_ID)[0]


def config_pda() -> bytes:
    return find_pda([b"config"], PROGRAM_ID)[0]


def fee_vault_pda(config: bytes) -> bytes:
    return find_pda([b"fee_vault", config], PROGRAM_ID)[0]


def program_data_pda() -> bytes:
    return find_pda([pubkey(PROGRAM_ID)], UPGRADEABLE_LOADER_ID)[0]


def squads_program_config_pda() -> bytes:
    return find_pda([b"multisig", b"program_config"], SQUADS_PROGRAM_ID)[0]


def squads_multisig_pda(create_key: bytes) -> bytes:
    return find_pda([b"multisig", b"multisig", create_key], SQUADS_PROGRAM_ID)[0]


def squads_vault_pda(multisig: bytes, index: int = 0) -> bytes:
    return find_pda([b"multisig", multisig, b"vault", u8(index)], SQUADS_PROGRAM_ID)[0]


def squads_transaction_pda(multisig: bytes, index: int) -> bytes:
    return find_pda([b"multisig", multisig, b"transaction", u64(index)], SQUADS_PROGRAM_ID)[0]


def squads_proposal_pda(multisig: bytes, index: int) -> bytes:
    return find_pda([b"multisig", multisig, b"transaction", u64(index), b"proposal"], SQUADS_PROGRAM_ID)[0]


def decode_program_data(account: dict[str, Any]) -> dict[str, Any]:
    data: bytes = account["data_raw"]
    if account.get("owner") != UPGRADEABLE_LOADER_ID or len(data) < 45 or struct.unpack_from("<I", data, 0)[0] != 3:
        raise DeployError("invalid upgradeable ProgramData account")
    tag = data[12]
    authority = None if tag == 0 else b58encode(data[13:45]) if tag == 1 else None
    if tag not in (0, 1):
        raise DeployError("invalid ProgramData authority option")
    return {"slot": struct.unpack_from("<Q", data, 4)[0], "upgrade_authority": authority, "bytes": data[45:]}


def inspect_program(rpc: Rpc, so_size: int | None = None) -> dict[str, Any] | None:
    program = rpc.account(PROGRAM_ID)
    if program is None:
        return None
    data: bytes = program["data_raw"]
    if not program.get("executable") or program.get("owner") != UPGRADEABLE_LOADER_ID:
        raise DeployError("program account is not executable under the upgradeable loader")
    if len(data) != 36 or struct.unpack_from("<I", data, 0)[0] != 2:
        raise DeployError("invalid upgradeable program account")
    encoded_program_data = b58encode(data[4:36])
    derived = b58encode(program_data_pda())
    if encoded_program_data != derived:
        raise DeployError("ProgramData address does not match loader derivation")
    program_data_account = rpc.account(encoded_program_data)
    if program_data_account is None:
        raise DeployError("ProgramData account is missing")
    decoded = decode_program_data(program_data_account)
    deployed_bytes = decoded.pop("bytes")
    if so_size is not None:
        if len(deployed_bytes) != so_size:
            raise DeployError(
                f"ProgramData code length mismatch: expected {so_size}, got {len(deployed_bytes)}"
            )
    decoded.update(
        {
            "program": PROGRAM_ID,
            "program_data": encoded_program_data,
            "executable": True,
            "code_sha256": hashlib.sha256(deployed_bytes).hexdigest(),
            "code_length": len(deployed_bytes),
        }
    )
    return decoded


def decode_config(data: bytes) -> dict[str, Any]:
    expected = hashlib.sha256(b"account:Config").digest()[:8]
    if len(data) < 124 or data[:8] != expected:
        raise DeployError("invalid Config account")
    offset = 8
    authority = b58encode(data[offset : offset + 32]); offset += 32
    mint = b58encode(data[offset : offset + 32]); offset += 32
    fee_wallet = b58encode(data[offset : offset + 32]); offset += 32
    fee_bps = struct.unpack_from("<H", data, offset)[0]; offset += 2
    withdraw_delay_s, close_grace_s, config_delay_s = struct.unpack_from("<qqq", data, offset); offset += 24
    pending_tag = data[offset]; offset += 1
    pending: dict[str, Any] | None = None
    if pending_tag == 1:
        pending = {
            "fee_bps": struct.unpack_from("<H", data, offset)[0],
            "fee_wallet": b58encode(data[offset + 2 : offset + 34]),
            "effective_at": struct.unpack_from("<q", data, offset + 34)[0],
        }
        offset += 42
    elif pending_tag != 0:
        raise DeployError("invalid Config pending option")
    authority_tag = data[offset]; offset += 1
    pending_authority = None
    if authority_tag == 1:
        pending_authority = b58encode(data[offset : offset + 32]); offset += 32
    elif authority_tag != 0:
        raise DeployError("invalid Config pending authority option")
    if len(data) < offset + 2:
        raise DeployError("truncated Config account")
    return {
        "authority": authority,
        "mint": mint,
        "fee_wallet": fee_wallet,
        "fee_bps": fee_bps,
        "withdraw_delay_s": withdraw_delay_s,
        "close_grace_s": close_grace_s,
        "config_delay_s": config_delay_s,
        "pending": pending,
        "pending_authority": pending_authority,
        "bump": data[offset],
        "fee_vault_bump": data[offset + 1],
    }


def read_config(rpc: Rpc) -> dict[str, Any] | None:
    account = rpc.account(b58encode(config_pda()))
    return None if account is None else decode_config(account["data_raw"])


def decode_multisig(data: bytes) -> dict[str, Any]:
    discriminator = bytes([224, 116, 121, 186, 68, 161, 79, 236])
    if len(data) < 104 or data[:8] != discriminator:
        raise DeployError("invalid Squads multisig account")
    offset = 8
    create_key = b58encode(data[offset : offset + 32]); offset += 32
    config_authority_raw = data[offset : offset + 32]; offset += 32
    threshold = struct.unpack_from("<H", data, offset)[0]; offset += 2
    time_lock = struct.unpack_from("<I", data, offset)[0]; offset += 4
    transaction_index, stale_transaction_index = struct.unpack_from("<QQ", data, offset); offset += 16
    rent_tag = data[offset]; offset += 1
    rent_collector = None
    if rent_tag == 1:
        rent_collector = b58encode(data[offset : offset + 32]); offset += 32
    elif rent_tag != 0:
        raise DeployError("invalid Squads rent collector option")
    bump = data[offset]; offset += 1
    count = struct.unpack_from("<I", data, offset)[0]; offset += 4
    members = []
    for _ in range(count):
        if len(data) < offset + 33:
            raise DeployError("truncated Squads member list")
        members.append({"key": b58encode(data[offset : offset + 32]), "permissions": data[offset + 32]})
        offset += 33
    return {
        "create_key": create_key,
        "config_authority": None if config_authority_raw == b"\0" * 32 else b58encode(config_authority_raw),
        "threshold": threshold,
        "time_lock": time_lock,
        "transaction_index": transaction_index,
        "stale_transaction_index": stale_transaction_index,
        "rent_collector": rent_collector,
        "bump": bump,
        "members": members,
    }


def read_multisig(rpc: Rpc, address: str) -> dict[str, Any] | None:
    account = rpc.account(address)
    return None if account is None else decode_multisig(account["data_raw"])


PROPOSAL_STATUS = {0: "draft", 1: "active", 2: "rejected", 3: "approved", 4: "executing", 5: "executed", 6: "cancelled"}


def decode_proposal(data: bytes) -> dict[str, Any]:
    discriminator = bytes([26, 94, 189, 187, 116, 136, 53, 33])
    if len(data) < 58 or data[:8] != discriminator:
        raise DeployError("invalid Squads proposal account")
    offset = 8
    multisig = b58encode(data[offset : offset + 32]); offset += 32
    index = struct.unpack_from("<Q", data, offset)[0]; offset += 8
    variant = data[offset]; offset += 1
    if variant not in PROPOSAL_STATUS:
        raise DeployError("unknown Squads proposal status")
    timestamp = None
    if variant != 4:
        timestamp = struct.unpack_from("<q", data, offset)[0]; offset += 8
    bump = data[offset]; offset += 1
    votes: dict[str, list[str]] = {}
    for name in ("approved", "rejected", "cancelled"):
        count = struct.unpack_from("<I", data, offset)[0]; offset += 4
        votes[name] = [b58encode(data[offset + i * 32 : offset + (i + 1) * 32]) for i in range(count)]
        offset += count * 32
    return {"multisig": multisig, "transaction_index": index, "status": PROPOSAL_STATUS[variant], "timestamp": timestamp, "bump": bump, **votes}


def read_proposal(rpc: Rpc, multisig: bytes, index: int) -> dict[str, Any] | None:
    account = rpc.account(b58encode(squads_proposal_pda(multisig, index)))
    return None if account is None else decode_proposal(account["data_raw"])


def squads_ix(discriminator: Sequence[int], accounts: Sequence[Meta], data: bytes = b"") -> Instruction:
    return Instruction(pubkey(SQUADS_PROGRAM_ID), tuple(accounts), bytes(discriminator) + data)


def build_config_accept_message(vault: bytes) -> tuple[bytes, list[Meta]]:
    config = config_pda()
    event = event_authority()
    program = pubkey(PROGRAM_ID)
    inner_accounts = [Meta(vault, True, False), Meta(config, False, True), Meta(event), Meta(program)]
    inner = pay_ix("config_accept_authority", inner_accounts)
    # Squads' compact TransactionMessage: vault is the sole signer/payer, config
    # is the sole writable non-signer, and there are no address table lookups.
    keys = [vault, config, event, program]
    compiled = u8(3) + u8(4) + bytes([0, 1, 2, 3]) + u16(len(inner.data)) + inner.data
    message = bytes([1, 1, 1, len(keys)]) + b"".join(keys) + u8(1) + compiled + u8(0)
    execute_accounts = [Meta(vault, False, True), Meta(config, False, True), Meta(event), Meta(program)]
    return message, execute_accounts


def program_config(rpc: Rpc) -> tuple[str, int]:
    address = b58encode(squads_program_config_pda())
    account = rpc.account(address)
    if account is None:
        raise DeployError("Squads program config account is missing")
    data: bytes = account["data_raw"]
    if len(data) < 80 or data[:8] != bytes([196, 210, 90, 231, 144, 149, 140, 63]):
        raise DeployError("invalid Squads program config account")
    return b58encode(data[48:80]), struct.unpack_from("<Q", data, 40)[0]


def assert_token_account(rpc: Rpc, address: str, mint: str, owner: str) -> None:
    account = rpc.account(address)
    if account is None:
        raise DeployError("fee wallet is missing")
    if account.get("owner") != TOKEN_PROGRAM_ID:
        raise DeployError("fee wallet account owner is not the classic SPL Token program")
    data: bytes = account["data_raw"]
    if len(data) != 165 or b58encode(data[:32]) != mint or b58encode(data[32:64]) != owner:
        raise DeployError("fee wallet does not match the requested mint and owner")


def ensure_fee_wallet(
    rpc: Rpc, rehearsal: bool, payer_path: Path, mint: str, explicit: str | None
) -> tuple[str, str | None]:
    payer = load_keypair(payer_path)[1]
    payer_text = b58encode(payer)
    if explicit:
        pubkey(explicit)
        assert_token_account(rpc, explicit, mint, payer_text)
        return explicit, None
    ata = b58encode(find_pda([payer, pubkey(TOKEN_PROGRAM_ID), pubkey(mint)], ASSOCIATED_TOKEN_PROGRAM_ID)[0])
    if rpc.account(ata) is not None:
        assert_token_account(rpc, ata, mint, payer_text)
        return ata, None
    with CliRpcProxy(rpc, rehearsal) as cli_url:
        output = run_cli(
            [SPL_TOKEN, "--url", cli_url, "--output", "json", "--fee-payer", payer_path,
             "create-account", mint, "--owner", payer_text]
        )
    signature = None
    try:
        result = json.loads(output)
        signature = result.get("transactionSignature") or result.get("signature")
    except json.JSONDecodeError:
        pass
    # The CLI exit code is not authoritative. Re-read the account through the
    # fenced Python client and validate its owner, mint and wallet authority.
    assert_token_account(rpc, ata, mint, payer_text)
    return ata, signature


def cmd_build_check(args: argparse.Namespace, state: State, rpc: Rpc | None = None) -> dict[str, Any]:
    so = args.so.resolve()
    if not so.is_file():
        raise DeployError(f"binary does not exist: {so}")
    actual = sha256_file(so)
    expected = args.expect_sha256.lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise DeployError("--expect-sha256 must be 64 lowercase or uppercase hexadecimal characters")
    if actual != expected:
        raise DeployError(f"binary sha256 mismatch: expected {expected}, got {actual}")
    genesis = cluster_guard(rpc, args.rehearsal) if rpc is not None else None
    state.data.update({"schema": 1, "program": PROGRAM_ID, "expected_sha256": expected, "so_size": so.stat().st_size})
    if genesis is not None:
        state.data["genesis"] = genesis
    state.save()
    return {
        "ok": True, "command": "build-check", "program": PROGRAM_ID, "genesis": genesis,
        "sha256": actual, "size": so.stat().st_size,
    }


def cmd_deploy(args: argparse.Namespace, state: State, rpc: Rpc) -> dict[str, Any]:
    genesis = cluster_guard(rpc, args.rehearsal)
    require_state(state, "expected_sha256", "so_size")
    so = args.so.resolve()
    if not so.is_file() or so.stat().st_size != state.data["so_size"] or sha256_file(so) != state.data["expected_sha256"]:
        raise DeployError("deploy binary does not match the successful build-check")
    _, program_key = load_keypair(args.program_keypair)
    _, payer = load_keypair(args.payer)
    if b58encode(program_key) != PROGRAM_ID:
        raise DeployError("program keypair does not match nakshatra_pay program id")
    existing = inspect_program(rpc, so.stat().st_size)
    signature = None
    action = "unchanged"
    if existing is None:
        buffer_path = state.directory / "deploy-buffer-keypair.json"
        if not buffer_path.exists():
            create_keypair(buffer_path)
        with CliRpcProxy(rpc, args.rehearsal) as cli_url:
            output = run_cli(
                [
                    SOLANA, "--url", cli_url, "--ws", cli_url.replace("http://", "ws://", 1),
                    "--keypair", args.payer, "--output", "json", "program", "deploy", so,
                    "--program-id", args.program_keypair, "--upgrade-authority", args.payer,
                    "--fee-payer", args.payer, "--buffer", buffer_path,
                    "--max-len", str(so.stat().st_size), "--use-rpc",
                ]
            )
        try:
            parsed = json.loads(output)
            signature = parsed.get("signature")
        except json.JSONDecodeError:
            pass
        existing = inspect_program(rpc, so.stat().st_size)
        if existing is None or existing["upgrade_authority"] != b58encode(payer):
            raise DeployError("deployed ProgramData authority does not match the deployer")
        if existing["code_sha256"] != state.data["expected_sha256"]:
            raise DeployError("deployed ProgramData bytes do not match the reviewed binary")
        action = "deployed"
    if existing is None or existing["code_sha256"] != state.data["expected_sha256"]:
        raise DeployError("on-chain program bytes do not match the reviewed binary")
    if existing["upgrade_authority"] not in (b58encode(payer), state.data.get("vault")):
        raise DeployError("unexpected existing program upgrade authority")
    state.data.update(
        {
            "genesis": genesis,
            "deployer": b58encode(payer),
            "program_data": existing["program_data"],
            "deploy_slot": existing["slot"],
        }
    )
    state.save()
    return {"ok": True, "command": "deploy", "action": action, "signature": signature, **existing}


def cmd_config_init(args: argparse.Namespace, state: State, rpc: Rpc) -> dict[str, Any]:
    genesis = cluster_guard(rpc, args.rehearsal)
    require_state(state, "expected_sha256", "so_size", "deployer")
    _, payer = load_keypair(args.payer)
    if b58encode(payer) != state.data["deployer"]:
        raise DeployError("config-init payer is not the recorded deployer")
    if args.fee_bps != 300:
        raise DeployError("fee_bps must be exactly 300")
    mint = args.mint or DEVNET_USDC_MINT
    if not args.rehearsal and mint != DEVNET_USDC_MINT:
        raise DeployError("non-rehearsal config-init requires the devnet USDC mint")
    pubkey(mint)
    existing = read_config(rpc)
    signature = None
    wallet_signature = None
    if existing is None:
        if rpc.account(mint) is None:
            raise DeployError("mint account does not exist")
        fee_wallet, wallet_signature = ensure_fee_wallet(rpc, args.rehearsal, args.payer, mint, args.fee_wallet)
        config = config_pda()
        accounts = [
            Meta(payer, True, True), Meta(config, False, True), Meta(program_data_pda()), Meta(pubkey(mint)),
            Meta(pubkey(fee_wallet)), Meta(fee_vault_pda(config), False, True), Meta(pubkey(TOKEN_PROGRAM_ID)),
            Meta(pubkey(SYSTEM_PROGRAM_ID)), Meta(event_authority()), Meta(pubkey(PROGRAM_ID)),
        ]
        signature = send_instructions(rpc, args.payer, [pay_ix("config_init", accounts, u16(args.fee_bps))])
        existing = read_config(rpc)
    if existing is None:
        raise DeployError("Config account is missing after config-init")
    allowed_authorities = {b58encode(payer)}
    if state.data.get("vault"):
        allowed_authorities.add(state.data["vault"])
    if existing["authority"] not in allowed_authorities or existing["mint"] != mint or existing["fee_bps"] != args.fee_bps:
        raise DeployError("existing Config does not match requested initialization")
    state.data.update({"genesis": genesis, "mint": mint, "fee_wallet": existing["fee_wallet"], "fee_bps": args.fee_bps})
    state.save()
    return {
        "ok": True, "command": "config-init", "action": "initialized" if signature else "unchanged",
        "signature": signature, "fee_wallet_create_signature": wallet_signature,
        "config": b58encode(config_pda()), **existing,
    }


def cmd_multisig_create(args: argparse.Namespace, state: State, rpc: Rpc) -> dict[str, Any]:
    if args.threshold != 2:
        raise DeployError("threshold must be exactly 2")
    if len(args.member) != 3 or len(set(args.member)) != 3:
        raise DeployError("members must be exactly 3 distinct public keys")
    members = [pubkey(value) for value in args.member]
    if args.time_lock != 172800 and not (args.rehearsal and args.time_lock == 5):
        raise DeployError("time-lock must be 172800 (only --rehearsal permits 5)")
    genesis = cluster_guard(rpc, args.rehearsal)
    _, payer = load_keypair(args.payer)
    if state.data.get("multisig_create_key"):
        create_path = Path(state.data["multisig_create_key"])
        _, create_key = load_keypair(create_path)
    else:
        create_path = state.directory / "multisig-create-keypair.json"
        if create_path.exists():
            _, create_key = load_keypair(create_path)
        else:
            create_key = create_keypair(create_path)
    multisig = squads_multisig_pda(create_key)
    vault = squads_vault_pda(multisig)
    existing = read_multisig(rpc, b58encode(multisig))
    signature = None
    if existing is None:
        treasury, _creation_fee = program_config(rpc)
        data = option(None) + u16(args.threshold) + u32(3)
        for member in members:
            data += member + u8(7)
        data += u32(args.time_lock) + option(None) + option(None)
        accounts = [
            Meta(squads_program_config_pda()), Meta(pubkey(treasury), False, True), Meta(multisig, False, True),
            Meta(create_key, True, False), Meta(payer, True, True), Meta(pubkey(SYSTEM_PROGRAM_ID)),
        ]
        ix = squads_ix([50, 221, 199, 93, 40, 245, 139, 233], accounts, data)
        signature = send_instructions(rpc, args.payer, [ix], [create_path])
        existing = read_multisig(rpc, b58encode(multisig))
    expected_members = sorted(args.member, key=lambda value: pubkey(value))
    actual_members = [item["key"] for item in (existing or {}).get("members", [])]
    permissions = [item["permissions"] for item in (existing or {}).get("members", [])]
    if (
        existing is None or existing["threshold"] != 2 or existing["time_lock"] != args.time_lock
        or actual_members != expected_members or permissions != [7, 7, 7]
        or existing["config_authority"] is not None or existing["rent_collector"] is not None
    ):
        raise DeployError("existing Squads multisig does not match requested autonomous 2-of-3 configuration")
    state.data.update(
        {
            "genesis": genesis, "multisig_create_key": str(create_path), "multisig": b58encode(multisig),
            "vault": b58encode(vault), "members": expected_members, "threshold": 2, "time_lock": args.time_lock,
        }
    )
    state.save()
    return {
        "ok": True, "command": "multisig-create", "action": "created" if signature else "unchanged",
        "signature": signature, "multisig": b58encode(multisig), "vault": b58encode(vault),
        "threshold": 2, "time_lock": args.time_lock, "members": expected_members,
    }


def cmd_handover(args: argparse.Namespace, state: State, rpc: Rpc) -> dict[str, Any]:
    genesis = cluster_guard(rpc, args.rehearsal)
    require_state(state, "deployer", "vault", "so_size", "expected_sha256")
    _, payer = load_keypair(args.payer)
    if b58encode(payer) != state.data["deployer"]:
        raise DeployError("handover payer is not the recorded deployer")
    vault = pubkey(state.data["vault"])
    config = read_config(rpc)
    if config is None:
        raise DeployError("Config is not initialized")
    propose_signature = None
    if config["authority"] != state.data["vault"] and config["pending_authority"] != state.data["vault"]:
        accounts = [Meta(payer, True, False), Meta(config_pda(), False, True), Meta(event_authority()), Meta(pubkey(PROGRAM_ID))]
        propose_signature = send_instructions(
            rpc, args.payer, [pay_ix("config_propose_authority", accounts, vault)]
        )
        config = read_config(rpc)
    if config is None or (config["authority"] != state.data["vault"] and config["pending_authority"] != state.data["vault"]):
        raise DeployError("Config authority proposal did not persist")
    program = inspect_program(rpc, state.data["so_size"])
    authority_signature = None
    if program is None:
        raise DeployError("program is not deployed")
    if program["upgrade_authority"] != state.data["vault"]:
        if program["upgrade_authority"] != b58encode(payer):
            raise DeployError("deployer no longer controls the program upgrade authority")
        with CliRpcProxy(rpc, args.rehearsal) as cli_url:
            output = run_cli(
                [
                    SOLANA, "--url", cli_url, "--ws", cli_url.replace("http://", "ws://", 1),
                    "--keypair", args.payer, "--output", "json", "program", "set-upgrade-authority", PROGRAM_ID,
                    "--upgrade-authority", args.payer, "--new-upgrade-authority", state.data["vault"],
                    "--skip-new-upgrade-authority-signer-check",
                ]
            )
        try:
            authority_signature = json.loads(output).get("signature")
        except json.JSONDecodeError:
            pass
        program = inspect_program(rpc, state.data["so_size"])
    if (
        program is None
        or program["upgrade_authority"] != state.data["vault"]
        or program["code_sha256"] != state.data["expected_sha256"]
    ):
        raise DeployError("program upgrade authority handover failed")
    state.data["genesis"] = genesis
    state.save()
    return {
        "ok": True, "command": "handover", "config_propose_signature": propose_signature,
        "upgrade_authority_signature": authority_signature, "vault": state.data["vault"],
        "config": {"authority": config["authority"], "pending_authority": config["pending_authority"]},
        "program_data": program["program_data"], "upgrade_authority": program["upgrade_authority"],
    }


def accept_index(state: State, multisig: dict[str, Any], explicit: int | None, action: str) -> int:
    if explicit is not None:
        if explicit < 1:
            raise DeployError("transaction index must be positive")
        return explicit
    index = state.data.get("accept_transaction_index")
    if index is not None:
        return int(index)
    if action != "propose":
        raise DeployError("--transaction-index is required on a member machine without proposal state")
    return int(multisig["transaction_index"]) + 1


def cmd_accept(args: argparse.Namespace, state: State, rpc: Rpc) -> dict[str, Any]:
    genesis = cluster_guard(rpc, args.rehearsal)
    member_seed, member = load_keypair(args.member_key)
    del member_seed
    member_text = b58encode(member)
    multisig_text = args.multisig or state.data.get("multisig")
    if not multisig_text:
        raise DeployError("--multisig is required on a member machine without deployment state")
    multisig_raw = pubkey(multisig_text)
    multisig = read_multisig(rpc, multisig_text)
    if multisig is None:
        raise DeployError("Squads multisig is missing")
    chain_members = [item["key"] for item in multisig["members"]]
    if member_text not in chain_members:
        raise DeployError("member key is not in the on-chain multisig")
    vault = squads_vault_pda(multisig_raw)
    vault_text = b58encode(vault)
    if state.data.get("vault") not in (None, vault_text):
        raise DeployError("recorded vault does not match the canonical Squads vault")
    index = accept_index(state, multisig, args.transaction_index, args.action)
    transaction = squads_transaction_pda(multisig_raw, index)
    proposal_address = squads_proposal_pda(multisig_raw, index)
    wrapped_message, execute_accounts = build_config_accept_message(vault)
    state.data.update(
        {
            "genesis": genesis, "multisig": multisig_text, "vault": vault_text,
            "members": chain_members, "threshold": multisig["threshold"], "time_lock": multisig["time_lock"],
            "accept_transaction_index": index,
        }
    )
    state.save()
    signature = None
    remaining = None
    if args.action == "propose":
        config = read_config(rpc)
        if config and config["authority"] == vault_text:
            return {"ok": True, "command": "accept-config-authority", "action": "propose", "result": "already-accepted", "transaction_index": index}
        # Persist the selected index before submission so a crash after send but
        # before confirmation cannot cause a second transaction to be proposed.
        instructions: list[Instruction] = []
        if rpc.account(b58encode(transaction)) is None:
            create_data = u8(0) + u8(0) + u32(len(wrapped_message)) + wrapped_message + option(None)
            create_accounts = [
                Meta(multisig_raw, False, True), Meta(transaction, False, True), Meta(member, True, False),
                Meta(member, True, True), Meta(pubkey(SYSTEM_PROGRAM_ID)),
            ]
            instructions.append(squads_ix([48, 250, 78, 168, 208, 226, 218, 211], create_accounts, create_data))
        if rpc.account(b58encode(proposal_address)) is None:
            proposal_accounts = [
                Meta(multisig_raw), Meta(proposal_address, False, True), Meta(member, True, False),
                Meta(member, True, True), Meta(pubkey(SYSTEM_PROGRAM_ID)),
            ]
            instructions.append(squads_ix([220, 60, 73, 224, 30, 108, 79, 159], proposal_accounts, u64(index) + u8(0)))
        if instructions:
            signature = send_instructions(rpc, args.member_key, instructions)
        proposal = read_proposal(rpc, multisig_raw, index)
        if proposal is None:
            raise DeployError("proposal was not created")
        result = proposal["status"]
    elif args.action == "approve":
        proposal = read_proposal(rpc, multisig_raw, index)
        if proposal is None:
            raise DeployError("run accept-config-authority propose first")
        if proposal["status"] in ("executed", "cancelled", "rejected"):
            result = proposal["status"]
        elif member_text in proposal["approved"]:
            result = "already-approved"
        else:
            accounts = [Meta(multisig_raw), Meta(member, True, True), Meta(proposal_address, False, True)]
            signature = send_instructions(
                rpc, args.member_key, [squads_ix([144, 37, 164, 136, 188, 216, 42, 248], accounts, option(None))]
            )
            proposal = read_proposal(rpc, multisig_raw, index)
            if proposal is None:
                raise DeployError("proposal disappeared after approval")
            result = proposal["status"]
    else:
        config = read_config(rpc)
        proposal = read_proposal(rpc, multisig_raw, index)
        if config and config["authority"] == vault_text:
            result = "already-executed"
        else:
            if proposal is None:
                raise DeployError("run accept-config-authority propose first")
            if proposal["status"] != "approved" or proposal["timestamp"] is None:
                raise DeployError(f"proposal is not approved (status={proposal['status']})")
            remaining = max(0, int(proposal["timestamp"]) + int(multisig["time_lock"]) - int(time.time()))
            if remaining:
                raise DeployError(f"time-lock has not elapsed; {remaining} seconds remaining")
            base_accounts = [Meta(multisig_raw), Meta(proposal_address, False, True), Meta(transaction), Meta(member, True, False)]
            signature = send_instructions(
                rpc, args.member_key,
                [squads_ix([194, 8, 161, 87, 153, 164, 25, 171], [*base_accounts, *execute_accounts])],
            )
            config = read_config(rpc)
            if config is None or config["authority"] != vault_text or config["pending_authority"] is not None:
                raise DeployError("config_accept_authority did not complete")
            result = "executed"
    state.data["genesis"] = genesis
    state.save()
    return {
        "ok": True, "command": "accept-config-authority", "action": args.action, "result": result,
        "signature": signature, "transaction_index": index, "transaction": b58encode(transaction),
        "proposal": b58encode(proposal_address), "time_lock_remaining": remaining,
    }


def cmd_verify(args: argparse.Namespace, state: State, rpc: Rpc) -> dict[str, Any]:
    genesis = rpc.call("getGenesisHash")
    host = urllib.parse.urlparse(args.url).hostname
    if genesis != DEVNET_GENESIS and not (args.rehearsal and host == "127.0.0.1"):
        raise DeployError("verification RPC is neither devnet nor the rehearsal validator")
    require_state(state, "expected_sha256", "so_size", "multisig", "members")
    expected_sha256 = state.data["expected_sha256"]
    so_size = state.data["so_size"]
    multisig_address = state.data["multisig"]
    expected_members = state.data["members"]
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(char not in "0123456789abcdef" for char in expected_sha256)
    ):
        raise DeployError("deployment state has an invalid expected_sha256")
    if isinstance(so_size, bool) or not isinstance(so_size, int) or so_size < 1:
        raise DeployError("deployment state has an invalid so_size")
    if not isinstance(multisig_address, str):
        raise DeployError("deployment state has an invalid multisig address")
    multisig_raw = pubkey(multisig_address)
    if (
        not isinstance(expected_members, list)
        or len(expected_members) != 3
        or any(not isinstance(member, str) for member in expected_members)
        or len(set(expected_members)) != 3
    ):
        raise DeployError("deployment state must contain exactly 3 distinct expected members")
    for member in expected_members:
        pubkey(member)
    vault = b58encode(squads_vault_pda(multisig_raw))
    if args.rehearsal:
        require_state(state, "mint")
        expected_mint = state.data["mint"]
        if not isinstance(expected_mint, str):
            raise DeployError("deployment state has an invalid rehearsal mint")
        pubkey(expected_mint)
        expected_time_lock = 5
    else:
        expected_mint = DEVNET_USDC_MINT
        expected_time_lock = 172800
    mismatches: list[str] = []
    program = inspect_program(rpc, so_size)
    if program is None:
        raise DeployError("program is not deployed")
    if not program["executable"]:
        mismatches.append("program_not_executable")
    if program["upgrade_authority"] != vault:
        mismatches.append("upgrade_authority")
    if program["code_sha256"] != expected_sha256:
        mismatches.append("code_sha256")
    config = read_config(rpc)
    config_authority_status = None
    if config is None:
        mismatches.append("config_missing")
    else:
        if config["mint"] != expected_mint: mismatches.append("config_mint")
        if config["fee_bps"] != 300: mismatches.append("config_fee_bps")
        if config["authority"] == vault and config["pending_authority"] is None:
            config_authority_status = "accepted"
        elif config["authority"] != vault and config["pending_authority"] == vault:
            config_authority_status = "pending"
        else:
            if config["authority"] != vault: mismatches.append("config_authority")
            if config["pending_authority"] is not None: mismatches.append("config_pending_authority")
    multisig = read_multisig(rpc, multisig_address)
    if multisig is None:
        mismatches.append("multisig_missing")
    else:
        if multisig["threshold"] != 2: mismatches.append("multisig_threshold")
        if multisig["time_lock"] != expected_time_lock: mismatches.append("multisig_time_lock")
        actual = [item["key"] for item in multisig["members"]]
        permissions = [item["permissions"] for item in multisig["members"]]
        if len(actual) != 3: mismatches.append("multisig_member_count")
        if actual != expected_members or permissions != [7, 7, 7]: mismatches.append("multisig_members")
    report = {
        "ok": not mismatches, "command": "verify", "genesis": genesis, "mismatches": mismatches,
        "program": program,
        "config": None if config is None else {
            "mint": config["mint"], "fee_bps": config["fee_bps"], "authority": config["authority"],
            "pending_authority": config["pending_authority"], "authority_status": config_authority_status,
        },
        "multisig": None if multisig is None else {
            "address": multisig_address, "vault": vault, "threshold": multisig["threshold"],
            "time_lock": multisig["time_lock"], "members": multisig["members"],
        },
    }
    if mismatches:
        json_print(report)
        raise SystemExit(1)
    return report


class DeployArgumentParser(argparse.ArgumentParser):
    def parse_args(
        self, args: Sequence[str] | None = None, namespace: argparse.Namespace | None = None
    ) -> argparse.Namespace:
        parsed = super().parse_args(args, namespace)
        try:
            validate_rpc_url(parsed.url, parsed.rehearsal)
        except DeployError as exc:
            self.error(str(exc))
        return parsed


def parser() -> argparse.ArgumentParser:
    result = DeployArgumentParser(description=__doc__)
    result.add_argument("--url", default=DEVNET_RPC, help="Solana JSON-RPC URL")
    result.add_argument("--rehearsal", action="store_true", help="allow a 127.0.0.1 validator and five-second lock")
    result.add_argument(
        "--state-dir", type=Path,
        default=Path(os.environ.get("NAKSHATRA_PAY_DEPLOY_STATE_DIR", Path.home() / ".local/state/nakshatra-pay-devnet")),
    )
    commands = result.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build-check")
    build.add_argument("--so", type=Path, required=True)
    build.add_argument("--expect-sha256", required=True)

    deploy = commands.add_parser("deploy")
    deploy.add_argument("--so", type=Path, required=True)
    deploy.add_argument("--program-keypair", type=Path, required=True)
    deploy.add_argument("--payer", type=Path, required=True)

    config = commands.add_parser("config-init")
    config.add_argument("--fee-bps", type=int, required=True)
    config.add_argument("--payer", type=Path, required=True)
    config.add_argument("--mint", help="rehearsal-only local classic SPL mint")
    config.add_argument("--fee-wallet", help="existing classic SPL token account")

    multisig = commands.add_parser("multisig-create")
    multisig.add_argument("--member", action="append", required=True)
    multisig.add_argument("--threshold", type=int, required=True)
    multisig.add_argument("--time-lock", type=int, required=True)
    multisig.add_argument("--payer", type=Path, required=True)

    handover = commands.add_parser("handover")
    handover.add_argument("--payer", type=Path, required=True)

    accept = commands.add_parser("accept-config-authority")
    accept.add_argument("action", choices=("propose", "approve", "execute"))
    accept.add_argument("--member-key", type=Path, required=True)
    accept.add_argument("--multisig", help="public Squads multisig address (required when local deployment state is absent)")
    accept.add_argument("--transaction-index", type=int, help="public proposal transaction index")

    commands.add_parser("verify")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    state = State(args.state_dir.resolve())
    try:
        rpc = Rpc(args.url)
        if args.command == "build-check":
            report = cmd_build_check(args, state, rpc)
        else:
            handlers = {
                "deploy": cmd_deploy,
                "config-init": cmd_config_init,
                "multisig-create": cmd_multisig_create,
                "handover": cmd_handover,
                "accept-config-authority": cmd_accept,
                "verify": cmd_verify,
            }
            report = handlers[args.command](args, state, rpc)
        json_print(report)
        return 0
    except DeployError as exc:
        json_print({"ok": False, "command": args.command, "error": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
