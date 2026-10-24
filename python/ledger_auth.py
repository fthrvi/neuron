"""Authentication and signed-receipt verification for the credit ledger.

This module deliberately has no dependency on Nakshatra.  The HTTP signature
format and receipt participation signature are wire contracts between the two
repositories; the admission roster is injected by the caller.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import threading
import time
import warnings
from pathlib import Path
from typing import Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.ledger_store import is_reserved


AUTH_SCHEME = "Sthambha-Ed25519"
TIMESTAMP_WINDOW_S = 60
MAX_GENERATED_TOKENS = 65_536
TIER_RANK = {"stranger": 0, "known": 1, "trusted": 2, "self": 3}


# Byte-for-byte protocol copy from nakshatra/scripts/nakshatra_auth.py.  ADR-0006
# requires duplication rather than a cross-repository import because the projects
# release independently.
def canonical_string(method: str, path: str, body: bytes,
                     timestamp_unix: int) -> bytes:
    body_hash = hashlib.sha256(body or b"").hexdigest()
    return (
        f"{method.upper()}\n{path}\n{body_hash}\n{int(timestamp_unix)}"
    ).encode("utf-8")


def verify_request(public_key_hex: str, method: str, path: str,
                   body: bytes, timestamp_unix: int,
                   signature_b64: str) -> bool:
    """Used by inbound-request handlers (e.g. worker's POST /slice).
    Returns False on any failure — never raises."""
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        return False
    if len(pub_bytes) != 32 or len(sig) != 64:
        return False
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig, canonical_string(method, path, body, timestamp_unix))
        return True
    except (InvalidSignature, ValueError):
        return False


class NonceStore(Protocol):
    """Atomic replay-store interface used by :func:`verify_envelope`."""

    def claim_nonce(self, signature_sha256: str, timestamp_unix: int) -> bool:
        """Store an unseen signature digest and return True; return False if seen."""


class InMemoryNonceStore:
    """Thread-safe nonce store for tests and short-lived processes.

    Entries intentionally remain for the lifetime of the object.  A persistent
    implementation may prune entries only after they are outside every accepted
    timestamp window, while preserving the atomic insert-if-absent operation.
    """

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def claim_nonce(self, signature_sha256: str, timestamp_unix: int) -> bool:
        with self._lock:
            if signature_sha256 in self._seen:
                return False
            self._seen[signature_sha256] = timestamp_unix
            return True

    # Kept as a small convenience for callers that use the shorter verb.
    claim = claim_nonce


_AUTH_RE = re.compile(
    r'^Sthambha-Ed25519 keyid="([^"\r\n]+)",'
    r'sig="([^"\r\n]+)",ts="(-?\d+)"$'
)


def _header(headers: Mapping[str, str], name: str) -> str | None:
    """Read a header from either an HTTPMessage or a plain mapping."""
    try:
        value = headers.get(name)
    except (AttributeError, TypeError):
        return None
    if value is not None:
        return value if isinstance(value, str) else None
    wanted = name.lower()
    try:
        for key, candidate in headers.items():
            if isinstance(key, str) and key.lower() == wanted:
                return candidate if isinstance(candidate, str) else None
    except (AttributeError, TypeError):
        return None
    return None


def verify_envelope(
    headers: Mapping[str, str],
    method: str,
    path: str,
    body: bytes,
    roster: Mapping[str, Mapping[str, object]],
    nonce_store: NonceStore,
    now: float | int | None = None,
) -> str | None:
    """Verify one rostered, fresh, previously unseen HTTP request envelope.

    The return value is the signing roster key (``keyid``).  Every parse,
    roster, freshness, signature, or replay failure returns ``None``.
    """
    authorization = _header(headers, "Authorization")
    if authorization is None:
        return None
    match = _AUTH_RE.fullmatch(authorization)
    if match is None:
        return None
    keyid, signature_b64, timestamp_text = match.groups()

    try:
        timestamp = int(timestamp_text)
        current = time.time() if now is None else now
        if (
            isinstance(current, bool)
            or not isinstance(current, (int, float))
            or not math.isfinite(current)
        ):
            return None
        if abs(current - timestamp) > TIMESTAMP_WINDOW_S:
            return None
        row = roster.get(keyid)
        if not isinstance(row, Mapping) or row.get("pubkey", keyid) != keyid:
            return None
        if not verify_request(keyid, method, path, body, timestamp, signature_b64):
            return None
        signature = base64.b64decode(signature_b64, validate=True)
        nonce = hashlib.sha256(signature).hexdigest()
        if not nonce_store.claim_nonce(nonce, timestamp):
            return None
    except (AttributeError, OverflowError, TypeError, ValueError):
        return None
    return keyid


def is_suspended_tier(tier: object) -> bool:
    """True for any case/whitespace variant of ``suspended`` (fail closed)."""
    return isinstance(tier, str) and tier.strip().lower() == "suspended"


def _roster_tier(tier: str) -> str:
    # Only "suspended" is normalised (so a typo'd case cannot fail open); every other tier
    # must match exactly, so "SELF" / "Trusted" stay stranger rather than widening privilege.
    if is_suspended_tier(tier):
        return "suspended"
    return tier if tier in TIER_RANK else "stranger"


def load_roster(path: str | Path) -> dict[str, dict[str, str | None]]:
    """Load a Trisul admission TSV as ``pubkey -> roster row``.

    Rows are ``pubkey name operator tier tenant [coord]``.  As in Trisul's
    admission loader, whitespace-delimited rows are accepted too, unknown tiers
    become ``stranger``, and blank/comment lines are ignored.
    """
    roster: dict[str, dict[str, str | None]] = {}
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t") if "\t" in line else line.split()
        if len(fields) < 5:
            continue
        pubkey, name, operator, tier, tenant = fields[:5]
        if is_reserved(operator):
            warnings.warn(
                f"ignoring roster row for {name!r}: operator {operator!r} is reserved",
                RuntimeWarning,
                stacklevel=2,
            )
            continue
        roster[pubkey] = {
            "pubkey": pubkey,
            "name": name,
            "operator": operator,
            "tier": _roster_tier(tier),
            "tenant": tenant,
            "coord": fields[5] if len(fields) >= 6 else None,
        }
    return roster


class ReceiptError(ValueError):
    """A receipt is structurally invalid or fails its content-integrity checks."""


class SettlementFrozen(ReceiptError):
    """A valid receipt participant is suspended, so settlement must wait."""

    def __init__(self, receipt_id: str | None = None):
        super().__init__("a participant is suspended; settlement is frozen")
        self.receipt_id = receipt_id


def _strict_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReceiptError(f"{field} must be an integer")
    return value


def _output_sha256(tokens: list[int]) -> str:
    canonical = ",".join(str(token) for token in tokens)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validated_receipt(receipt: dict) -> tuple[str, int, str, list[tuple[str, int, int]]]:
    if not isinstance(receipt, dict):
        raise ReceiptError("receipt must be an object")
    fields = {
        "v", "run_id", "n_generated", "generated_tokens", "output_sha256",
        "chain", "worker_signatures",
    }
    if set(receipt) != fields:
        missing = sorted(fields - set(receipt))
        unknown = sorted(set(receipt) - fields)
        detail = f"missing field: {missing[0]}" if missing else f"unknown field: {unknown[0]}"
        raise ReceiptError(f"strict legacy-v1 receipt {detail}")
    if isinstance(receipt["v"], bool) or not isinstance(receipt["v"], int) or receipt["v"] != 1:
        raise ReceiptError("legacy settle accepts only receipt v=1")

    run_id = receipt["run_id"]
    if not isinstance(run_id, str) or not run_id:
        raise ReceiptError("run_id must be a non-empty string")
    n_generated = _strict_int(receipt["n_generated"], "n_generated")
    if n_generated < 0 or n_generated > MAX_GENERATED_TOKENS:
        raise ReceiptError(f"n_generated must be between 0 and {MAX_GENERATED_TOKENS}")
    tokens = receipt["generated_tokens"]
    if not isinstance(tokens, list):
        raise ReceiptError("generated_tokens must be a list")
    if any(isinstance(token, bool) or not isinstance(token, int) for token in tokens):
        raise ReceiptError("generated_tokens must contain only integers")
    if len(tokens) != n_generated:
        raise ReceiptError("n_generated does not match generated_tokens")

    output_hash = receipt["output_sha256"]
    if not isinstance(output_hash, str) or output_hash != _output_sha256(tokens):
        raise ReceiptError("output_sha256 does not match generated_tokens")

    raw_chain = receipt["chain"]
    if not isinstance(raw_chain, list) or not raw_chain:
        raise ReceiptError("chain must be a non-empty list")
    chain: list[tuple[str, int, int]] = []
    node_ids: set[str] = set()
    spki_hashes: set[str] = set()
    for index, stage in enumerate(raw_chain):
        if not isinstance(stage, dict):
            raise ReceiptError(f"chain[{index}] must be an object")
        required_stage = {"node_id", "layer_start", "layer_end"}
        allowed_stage = required_stage | {"spki_hash"}
        if not required_stage <= set(stage) or not set(stage) <= allowed_stage:
            raise ReceiptError(f"chain[{index}] has a non-v1 schema")
        node_id = stage.get("node_id")
        if not isinstance(node_id, str) or not node_id:
            raise ReceiptError(f"chain[{index}].node_id must be a non-empty string")
        if node_id in node_ids:
            raise ReceiptError("duplicate node_id in chain")
        node_ids.add(node_id)
        start = _strict_int(stage.get("layer_start"), f"chain[{index}].layer_start")
        end = _strict_int(stage.get("layer_end"), f"chain[{index}].layer_end")
        if start < 0 or end <= start:
            raise ReceiptError(f"chain[{index}] has an invalid layer range")
        spki = stage.get("spki_hash")
        if spki:
            if not isinstance(spki, str) or spki in spki_hashes:
                raise ReceiptError("duplicate or invalid spki_hash in chain")
            spki_hashes.add(spki)
        chain.append((node_id, start, end))

    ranges = sorted((start, end) for _, start, end in chain)
    if ranges[0][0] != 0:
        raise ReceiptError("layer map must start at 0")
    for (_, end), (next_start, _) in zip(ranges, ranges[1:]):
        if next_start != end:
            raise ReceiptError("layer map contains a gap or overlap")

    signatures = receipt["worker_signatures"]
    if not isinstance(signatures, list):
        raise ReceiptError("worker_signatures must be a list")
    signature_fields = {"node_id", "pubkey", "sig", "layer_start", "layer_end"}
    for index, signature in enumerate(signatures):
        if not isinstance(signature, dict) or set(signature) != signature_fields:
            raise ReceiptError(f"worker_signatures[{index}] has a non-v1 schema")
    return run_id, n_generated, output_hash, chain


def _participation_message(
    run_id: str,
    node_id: str,
    layer_start: int,
    layer_end: int,
    output_sha256: str,
) -> bytes:
    return f"{run_id}|{node_id}|[{layer_start},{layer_end})|{output_sha256}".encode("utf-8")


def _valid_participation(
    entry: object,
    *,
    run_id: str,
    output_sha256: str,
    stages: set[tuple[str, int, int]],
    roster: Mapping[str, Mapping[str, object]],
    frozen_operators: set[str],
) -> tuple[str, str, int, int] | None:
    if not isinstance(entry, dict):
        return None
    if set(entry) != {"node_id", "pubkey", "sig", "layer_start", "layer_end"}:
        return None
    try:
        node_id = entry["node_id"]
        pubkey = entry["pubkey"]
        signature_b64 = entry["sig"]
        start = _strict_int(entry["layer_start"], "worker signature layer_start")
        end = _strict_int(entry["layer_end"], "worker signature layer_end")
    except (KeyError, ReceiptError):
        return None
    if not all(isinstance(value, str) and value for value in (node_id, pubkey, signature_b64)):
        return None
    # Match the signature to its chain stage. Real receipts name a stage by the node's SHORT id
    # (client.py truncates to 14 hex chars) while the worker signs with its full node id, and a
    # release worker's node id IS its public key (bro, 2026-10-13: every real signature failed
    # here and earned nothing). Same layer range required; a short id must be >= 12 hex chars.
    matched = None
    for chain_id, chain_start, chain_end in stages:
        if (chain_start, chain_end) != (start, end):
            continue
        if chain_id == node_id or (len(chain_id) >= 12 and node_id.startswith(chain_id)):
            matched = chain_id
            break
    if matched is None:
        return None
    row = roster.get(pubkey)
    if not isinstance(row, Mapping):
        return None
    # The signer is bound to the rostered key either because its node id IS that key (release
    # workers) or because the roster names it (legacy named nodes). The roster name of a
    # pubkey-identified worker is a human label ("bro"), never its node id.
    if row.get("pubkey", pubkey) != pubkey or (node_id != pubkey and row.get("name") != node_id):
        return None
    message = _participation_message(run_id, node_id, start, end, output_sha256)
    try:
        public_bytes = bytes.fromhex(pubkey)
        signature = base64.b64decode(signature_b64, validate=True)
        if len(public_bytes) != 32 or len(signature) != 64:
            return None
        ed25519.Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, message)
    except (InvalidSignature, TypeError, ValueError):
        return None
    # A valid suspended participant freezes the whole receipt.  Dropping only this share and
    # then storing the reduced receipt would make the omitted value impossible to recover after
    # unsuspension.
    if is_suspended_tier(row.get("tier")):
        raise SettlementFrozen()
    operator = row.get("operator")
    if not isinstance(operator, str) or not operator:
        return None
    if operator in frozen_operators:
        raise SettlementFrozen()
    return matched, operator, start, end


def verify_receipt(
    receipt: dict,
    requester_keyid: str,
    roster: Mapping[str, Mapping[str, object]],
) -> tuple[str, dict[str, int], int]:
    """Validate a receipt and compute credit from proven participation only.

    Invalid receipt structure/content raises :class:`ReceiptError`.  Invalid,
    unrostered, duplicated, or off-chain worker signatures earn no credit.
    Credits accrue to the rostered worker operator; the requester's own stages
    are local/free and therefore produce neither a credit nor a charge.
    """
    requester_row = roster.get(requester_keyid)
    if (
        not isinstance(requester_row, Mapping)
        or requester_row.get("pubkey", requester_keyid) != requester_keyid
    ):
        raise ReceiptError("requester is not in the admission roster")
    requester = requester_row.get("operator")
    if not isinstance(requester, str) or not requester:
        raise ReceiptError("requester roster row has no operator")

    run_id, n_generated, output_hash, chain = _validated_receipt(receipt)
    canonical_chain = sorted(chain, key=lambda stage: (stage[0], stage[1], stage[2]))
    # run_id IS part of the identity. Model output is deterministic, so two genuine runs of the
    # same prompt have identical content; without run_id the second was never paid. Including it
    # is safe because a worker signs a (run_id, output) only for a run its own Inference() served:
    # replaying one real run under an invented run_id carries no valid signature and credits nothing.
    content = {
        "chain": canonical_chain,
        "n_generated": n_generated,
        "output_sha256": output_hash,
        "requester": requester,
        "run_id": run_id,
    }
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
    receipt_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    credited: dict[str, int] = {}
    credited_stages: set[tuple[str, int, int]] = set()
    stages = set(chain)
    frozen_operators = {
        str(row["operator"])
        for row in roster.values()
        if isinstance(row, Mapping)
        and isinstance(row.get("operator"), str)
        and is_suspended_tier(row.get("tier"))
    }
    for entry in receipt.get("worker_signatures") or []:
        try:
            valid = _valid_participation(
                entry,
                run_id=run_id,
                output_sha256=output_hash,
                stages=stages,
                roster=roster,
                frozen_operators=frozen_operators,
            )
        except SettlementFrozen as exc:
            exc.receipt_id = receipt_id
            raise
        if valid is None:
            continue
        node_id, operator, start, end = valid
        stage = (node_id, start, end)
        if stage in credited_stages:
            continue
        credited_stages.add(stage)
        if operator == requester:
            continue
        credited[operator] = credited.get(operator, 0) + n_generated * (end - start)

    units = sum(credited.values())
    return receipt_id, credited, units
