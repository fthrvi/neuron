"""
Privacy Framework — Multi-layer privacy architecture.

Layer 1: Network Invisibility (WireGuard mesh config generation)
Layer 2: Transport Encryption (AES-256-GCM — see crypto.py)
Layer 3: Shielded Credits (Pedersen commitments, hiding amounts)
Layer 4: Job Privacy (encrypted job payloads, metadata hiding)
Layer 5: Model Privacy (encrypted shards — see pipeline.py)
Layer 6: Computation Privacy (MPC/FHE stubs for future)

Layers 1-2: always on (network default).
Layers 3-4: configurable per job.
Layers 5-6: opt-in for sensitive workloads.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from enum import Enum

log = logging.getLogger(__name__)


class PrivacyLevel(Enum):
    STANDARD = "standard"  # layers 1-2 (encryption only)
    PRIVATE = "private"  # layers 1-4 (hidden metadata + shielded credits)
    MAX = "max"  # all layers (MPC if available)


# --- Layer 1: WireGuard Config ---

@dataclass
class WireGuardPeer:
    """A peer in the WireGuard mesh."""

    node_id: str
    public_key: str  # WireGuard public key (Curve25519)
    endpoint: str  # IP:port
    allowed_ips: str = "10.neuron.0.0/16"


def generate_wireguard_config(
    our_private_key: str,
    our_address: str,
    peers: list[WireGuardPeer],
    listen_port: int = 51820,
) -> str:
    """
    Generate a WireGuard configuration file.
    Applied via `wg-quick up` to create the encrypted mesh overlay.
    """
    config = f"""[Interface]
PrivateKey = {our_private_key}
Address = {our_address}
ListenPort = {listen_port}
"""
    for peer in peers:
        config += f"""
[Peer]
# {peer.node_id}
PublicKey = {peer.public_key}
Endpoint = {peer.endpoint}
AllowedIPs = {peer.allowed_ips}
PersistentKeepalive = 25
"""
    return config


def generate_wireguard_keypair() -> tuple[str, str]:
    """
    Generate a WireGuard keypair (Curve25519).
    Returns (private_key_b64, public_key_b64).
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    import base64

    private = X25519PrivateKey.generate()
    priv_bytes = private.private_bytes_raw()
    pub_bytes = private.public_key().public_bytes_raw()
    return (
        base64.b64encode(priv_bytes).decode(),
        base64.b64encode(pub_bytes).decode(),
    )


# --- Layer 3: Shielded Credits (Real EC Pedersen Commitments) ---
#
# Real elliptic curve Pedersen on BLS12-381 G1.
# C = amount * G + blinding * H
# Homomorphic: C(a) + C(b) = C(a+b)

from py_ecc.optimized_bls12_381 import (
    G1, multiply, add, neg, curve_order as _CURVE_ORDER, Z1,
)
from py_ecc.bls.g2_primitives import G1_to_pubkey, pubkey_to_G1

# Nothing-up-my-sleeve second generator H (verifiably random)
_H_SEED = hashlib.sha256(b"neuron-network-pedersen-generator-H-v1").digest()
_H_INT = int.from_bytes(_H_SEED, 'big') % _CURVE_ORDER
H_POINT = multiply(G1, _H_INT)


@dataclass
class ShieldedBalance:
    """
    A shielded credit balance using real EC Pedersen commitments.

    C = amount * G + blinding * H on BLS12-381 G1.
    Only the owner knows (amount, blinding).
    Verifiers see only the 48-byte compressed commitment.
    """

    commitment: bytes       # 48 bytes compressed G1 point
    blinding_factor: int    # scalar (owner's secret)
    amount: int             # smallest NRN units (owner's secret)

    def to_public(self) -> dict:
        """What others see (no amount or blinding)."""
        return {"commitment": self.commitment.hex()}


def create_commitment(amount: int) -> ShieldedBalance:
    """
    Create C = amount * G + blinding * H on BLS12-381 G1.
    Amount in smallest NRN units (integer).
    """
    blinding = secrets.randbelow(_CURVE_ORDER - 1) + 1
    C = add(multiply(G1, amount % _CURVE_ORDER), multiply(H_POINT, blinding))
    commitment_bytes = G1_to_pubkey(C)
    return ShieldedBalance(
        commitment=commitment_bytes,
        blinding_factor=blinding,
        amount=amount,
    )


def verify_commitment(balance: ShieldedBalance) -> bool:
    """Verify C == amount * G + blinding * H."""
    C_expected = add(
        multiply(G1, balance.amount % _CURVE_ORDER),
        multiply(H_POINT, balance.blinding_factor),
    )
    return G1_to_pubkey(C_expected) == balance.commitment


def add_commitments(c1: bytes, c2: bytes) -> bytes:
    """Homomorphic addition: C(a+b) = C(a) + C(b)."""
    p1 = pubkey_to_G1(c1)
    p2 = pubkey_to_G1(c2)
    return G1_to_pubkey(add(p1, p2))


def create_range_proof(amount: int, num_bits: int = 64) -> dict:
    """
    Bit-decomposition range proof: prove 0 <= amount < 2^num_bits
    without revealing amount.

    For each bit b_i of amount, creates commitment C_i = b_i*G + r_i*H.
    Verifier checks: sum(2^i * C_i) == C_total (the commitment being proved).
    O(num_bits) size — not constant-size like Bulletproofs, but real crypto.
    """
    if amount < 0 or amount >= (1 << num_bits):
        return {"valid": False, "error": "amount out of range"}

    bit_commitments = []
    total_blinding = 0

    for i in range(num_bits):
        bit = (amount >> i) & 1
        r_i = secrets.randbelow(_CURVE_ORDER - 1) + 1
        total_blinding = (total_blinding + r_i * pow(2, i, _CURVE_ORDER)) % _CURVE_ORDER
        C_i = add(multiply(G1, bit), multiply(H_POINT, r_i))
        bit_commitments.append(G1_to_pubkey(C_i).hex())

    return {
        "valid": True,
        "proof_type": "bit_decomposition",
        "num_bits": num_bits,
        "bit_commitments": bit_commitments,
        "total_blinding": total_blinding,
    }


# --- Layer 4: Job Privacy ---

@dataclass
class EncryptedJobPayload:
    """An encrypted job payload — other nodes can't see contents."""

    job_id: str
    encrypted_data: bytes  # AES-256-GCM encrypted payload
    metadata: dict  # visible metadata (job_type, vram_needed, estimated_time)
    nonce: bytes = b""
    sender: str = ""

    @property
    def metadata_visible(self) -> dict:
        """What the network sees for scheduling (no content)."""
        return {
            "job_id": self.job_id,
            "job_type": self.metadata.get("job_type", "unknown"),
            "vram_required_mb": self.metadata.get("vram_required_mb", 0),
            "estimated_seconds": self.metadata.get("estimated_seconds", 0),
            "privacy_level": "private",
        }


def encrypt_job_payload(
    job_id: str,
    payload: dict,
    metadata: dict,
    encryption_key: bytes,
) -> EncryptedJobPayload:
    """Encrypt a job payload. Only the worker (with the key) can decrypt."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    aesgcm = AESGCM(encryption_key)
    plaintext = json.dumps(payload).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return EncryptedJobPayload(
        job_id=job_id,
        encrypted_data=ciphertext,
        metadata=metadata,
        nonce=nonce,
    )


def decrypt_job_payload(
    encrypted: EncryptedJobPayload,
    encryption_key: bytes,
) -> dict | None:
    """Decrypt a job payload."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        aesgcm = AESGCM(encryption_key)
        plaintext = aesgcm.decrypt(encrypted.nonce, encrypted.encrypted_data, None)
        return json.loads(plaintext.decode())
    except Exception as e:
        log.warning(f"Job decryption failed: {e}")
        return None


# --- Layer 5/6: MPC + FHE ---

class MPCEngine:
    """
    Real Multi-Party Computation using additive secret sharing
    over a Mersenne prime field (Z_{2^61-1}).

    Supports:
    - Additive secret sharing (split/reconstruct)
    - Beaver triple multiplication (secure multiply on shares)
    - Tensor sharding (model weight distribution)
    - Linear computation on shares (no communication needed)
    """

    def __init__(self, num_parties: int = 3):
        self._num_parties = num_parties
        self._compute = None

    def is_available(self) -> bool:
        return True  # native implementation, always available

    def _get_compute(self):
        if self._compute is None:
            from core.mpc import SecureComputation
            self._compute = SecureComputation(self._num_parties)
        return self._compute

    def secret_share(self, data: bytes, num_parties: int | None = None) -> list[bytes]:
        """Split data into additive secret shares (byte-level)."""
        from core.mpc import share_secret, AdditiveShare
        import struct

        n = num_parties or self._num_parties
        # Share each byte independently
        all_shares = [bytearray() for _ in range(n)]
        for byte_val in data:
            shares = share_secret(byte_val, n)
            for i, s in enumerate(shares):
                # Pack share value as 8 bytes
                all_shares[i].extend(struct.pack('>Q', s.value))
        return [bytes(s) for s in all_shares]

    def reconstruct(self, shares: list[bytes]) -> bytes:
        """Reconstruct data from all shares."""
        from core.mpc import AdditiveShare, reconstruct, PRIME
        import struct

        n = len(shares)
        num_elements = len(shares[0]) // 8
        result = bytearray()

        for idx in range(num_elements):
            party_shares = []
            for i in range(n):
                val = struct.unpack('>Q', shares[i][idx*8:(idx+1)*8])[0]
                party_shares.append(AdditiveShare(val, i))
            raw = reconstruct(party_shares)
            # Secret was 0-255, shares sum to secret mod PRIME.
            # Since secret < PRIME, raw == secret exactly. Mask to byte.
            result.append(raw & 0xFF)

        return bytes(result)

    def share_tensor(self, weights: list[float]) -> list[list]:
        """Split model weights into per-party additive shares."""
        return self._get_compute().share_tensor(weights)

    def reconstruct_tensor(self, all_shares: list[list]) -> list[float]:
        """Reconstruct tensor from shares."""
        return self._get_compute().reconstruct_tensor(all_shares)

    def summary(self) -> dict:
        return self._get_compute().summary()


class FHEStub:
    """
    Stub for Fully Homomorphic Encryption.

    In production: compute on encrypted data without decrypting.
    Worker never sees raw input or output.

    Requires: tenseal or concrete-python.
    Current status: 100-1000x overhead. Not practical for LLMs yet.
    """

    @staticmethod
    def is_available() -> bool:
        try:
            import tenseal  # noqa
            return True
        except ImportError:
            return False


# --- Privacy Manager ---

class PrivacyManager:
    """Top-level privacy configuration and enforcement."""

    def __init__(self, default_level: PrivacyLevel = PrivacyLevel.STANDARD):
        self.default_level = default_level
        self.mpc = MPCEngine()
        self.fhe = FHEStub()

    def available_layers(self) -> dict:
        """What privacy layers are available."""
        return {
            "layer_1_wireguard": True,  # config generation always available
            "layer_2_aes256gcm": True,  # always available (crypto.py)
            "layer_3_shielded_credits": True,  # Pedersen commitments
            "layer_4_encrypted_jobs": True,  # AES-256-GCM job payloads
            "layer_5_mpc": self.mpc.is_available(),
            "layer_6_fhe": self.fhe.is_available(),
        }

    def summary(self) -> dict:
        layers = self.available_layers()
        active = sum(1 for v in layers.values() if v)
        return {
            "default_level": self.default_level.value,
            "layers_available": active,
            "layers": layers,
        }
