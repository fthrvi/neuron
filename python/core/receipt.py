"""
Compute receipts — workers sign one of these per completed job.

Pathway C of the network design:
  - Workers don't run chain
  - Workers sign a Receipt per job they complete
  - Coordinator ingests receipts, batches them
  - Chain (compute-jobs pallet) verifies sigs and emits NRN

Trust model: receipts are signed with the worker's Ed25519 key.
Coordinator can drop receipts but cannot fabricate them.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field

from core.identity import NodeIdentity
from core.paths import neuron_home


RECEIPT_VERSION = 1


@dataclass
class Receipt:
    """A signed attestation that a worker completed a specific job."""

    job_id: str
    worker_node_id: str         # blake2b(pubkey) hex — matches identity.node_id
    worker_pubkey: str          # hex-encoded Ed25519 public key (32 bytes)
    input_hash: str             # sha256 hex of the canonical request payload
    output_hash: str            # sha256 hex of the result payload
    compute_class: str          # e.g. "qwen3-coder-30b" — what was run
    tokens_generated: int = 0
    duration_ms: int = 0
    timestamp: float = field(default_factory=time.time)
    version: int = RECEIPT_VERSION

    def canonical_dict(self) -> dict:
        """Stable, sorted dict for signing/verification."""
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.canonical_dict(), sort_keys=True)


def hash_payload(data: dict | str | bytes) -> str:
    """sha256 hex of a canonical payload. dict → sorted json; str → utf-8."""
    if isinstance(data, dict):
        raw = json.dumps(data, sort_keys=True).encode()
    elif isinstance(data, str):
        raw = data.encode("utf-8")
    elif isinstance(data, bytes):
        raw = data
    else:
        raise TypeError(f"unsupported payload type: {type(data)}")
    return hashlib.sha256(raw).hexdigest()


def sign_receipt(receipt: Receipt, identity: NodeIdentity) -> dict:
    """
    Sign a receipt with the worker's identity. Returns the signed envelope:
      { ...receipt fields..., "_signature": hex, "_signer": node_id }
    """
    if receipt.worker_node_id != identity.node_id:
        raise ValueError(
            f"receipt worker_node_id {receipt.worker_node_id!r} "
            f"!= identity.node_id {identity.node_id!r}"
        )
    return identity.sign_dict(receipt.canonical_dict())


def verify_receipt(envelope: dict, expected_pubkey: bytes | None = None) -> bool:
    """
    Verify a signed receipt envelope.

    Checks:
      1. Signature is valid for the embedded pubkey
      2. Embedded pubkey hashes to the embedded worker_node_id
      3. (Optional) pubkey matches a registered worker

    Returns True iff all checks pass.
    """
    sig_hex = envelope.get("_signature")
    signer = envelope.get("_signer")
    if not sig_hex or not signer:
        return False

    pubkey_hex = envelope.get("worker_pubkey")
    worker_id = envelope.get("worker_node_id")
    if not pubkey_hex or not worker_id:
        return False

    try:
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return False

    # Embedded pubkey must hash to the embedded worker_node_id
    derived_id = hashlib.blake2b(pubkey_bytes, digest_size=20).hexdigest()
    if derived_id != worker_id or signer != worker_id:
        return False

    # If caller supplied an expected pubkey (from a registry), it must match
    if expected_pubkey is not None and expected_pubkey != pubkey_bytes:
        return False

    # Reconstruct canonical payload (drop the _signature/_signer envelope keys)
    clean = {k: v for k, v in envelope.items() if not k.startswith("_")}
    payload = json.dumps(clean, sort_keys=True).encode()

    return NodeIdentity.verify(pubkey_bytes, payload, sig_bytes)


def receipts_dir():
    """Where coordinator persists ingested receipts."""
    d = neuron_home() / "receipts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def append_receipt(envelope: dict) -> None:
    """Append an ingested envelope to receipts.jsonl (one per line)."""
    path = receipts_dir() / "receipts.jsonl"
    with path.open("a") as f:
        f.write(json.dumps(envelope, sort_keys=True) + "\n")
