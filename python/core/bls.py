"""
BLS12-381 Threshold Signatures for Prithvi Network.

Each node has a BLS keypair alongside its Ed25519 identity.
Job completion attestation uses threshold BLS: k-of-n nodes
produce partial signatures that combine into one aggregate.

Uses py_ecc (pure Python, slow but correct). Can swap for
blspy (C bindings) later for production speed.
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
from dataclasses import dataclass, field

from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import G1_to_pubkey, pubkey_to_G1
from py_ecc.bls.g2_primitives import G2_to_signature, signature_to_G2
from py_ecc.optimized_bls12_381 import (
    G1, G2, Z1, Z2,
    multiply, add, neg,
    curve_order as CURVE_ORDER,
)

log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# BLS Identity — per-node keypair
# ═══════════════════════════════════════════════════════════════

@dataclass
class BLSIdentity:
    """BLS12-381 keypair for a node."""
    private_key: int
    public_key: bytes  # 48 bytes compressed G1

    @classmethod
    def generate(cls) -> BLSIdentity:
        """Generate a new random BLS keypair."""
        sk = secrets.randbelow(CURVE_ORDER - 1) + 1
        pk = bls.SkToPk(sk)
        return cls(private_key=sk, public_key=pk)

    @classmethod
    def from_seed(cls, seed: bytes) -> BLSIdentity:
        """Derive BLS keypair from a seed (deterministic)."""
        sk_bytes = hashlib.blake2b(seed, digest_size=32).digest()
        sk = int.from_bytes(sk_bytes, 'big') % (CURVE_ORDER - 1) + 1
        pk = bls.SkToPk(sk)
        return cls(private_key=sk, public_key=pk)

    def sign(self, message: bytes) -> bytes:
        """Sign a message. Returns 96 bytes (compressed G2 point)."""
        return bls.Sign(self.private_key, message)

    def proof_of_possession(self) -> bytes:
        """Generate Proof of Possession — proves we own the private key.
        Signs our own public key to prevent rogue key attacks."""
        return bls.Sign(self.private_key, self.public_key)

    @staticmethod
    def verify_pop(public_key: bytes, pop: bytes) -> bool:
        """Verify a Proof of Possession."""
        return bls.Verify(public_key, public_key, pop)

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a single signature."""
        if len(public_key) != 48 or len(signature) != 96:
            return False
        try:
            return bls.Verify(public_key, message, signature)
        except Exception:
            return False

    @staticmethod
    def aggregate_signatures(signatures: list[bytes]) -> bytes:
        """Aggregate multiple signatures into one."""
        for sig in signatures:
            if len(sig) != 96:
                raise ValueError("invalid signature length (expected 96 bytes)")
        return bls.Aggregate(signatures)

    @staticmethod
    def verify_aggregate(public_keys: list[bytes], messages: list[bytes],
                         aggregate_sig: bytes) -> bool:
        """Verify aggregate signature (each pubkey signed a different message)."""
        for pk in public_keys:
            if len(pk) != 48:
                return False
        if len(aggregate_sig) != 96:
            return False
        try:
            if len(set(messages)) == 1:
                return bls.FastAggregateVerify(public_keys, messages[0], aggregate_sig)
            return bls.AggregateVerify(public_keys, messages, aggregate_sig)
        except Exception:
            return False


# ═══════════════════════════════════════════════════════════════
# Threshold BLS — Shamir polynomial over the BLS scalar field
# ═══════════════════════════════════════════════════════════════

class ThresholdBLS:
    """
    Threshold BLS signatures using Shamir's Secret Sharing
    over the BLS12-381 scalar field.

    A master secret key is split into n shares with threshold k.
    Any k nodes can produce partial signatures that combine
    into a valid signature under the master public key.
    """

    @staticmethod
    def generate_shares(threshold: int, total: int) -> tuple[bytes, list[tuple[int, int]]]:
        """
        Generate a master keypair and split the secret key into shares.

        Returns:
            (master_public_key, [(x_value, share), ...])
        """
        if threshold > total:
            raise ValueError("threshold must be <= total")

        # Random polynomial: f(x) = a0 + a1*x + ... + a_{k-1}*x^{k-1}
        # where a0 = master secret key
        coeffs = [secrets.randbelow(CURVE_ORDER - 1) + 1 for _ in range(threshold)]
        master_sk = coeffs[0]
        master_pk = bls.SkToPk(master_sk)

        # Evaluate polynomial at x=1,2,...,total
        shares = []
        for i in range(total):
            x = i + 1
            # Horner's method
            y = 0
            for c in reversed(coeffs):
                y = (y * x + c) % CURVE_ORDER
            shares.append((x, y))

        return master_pk, shares

    @staticmethod
    def partial_sign(share: tuple[int, int], message: bytes) -> tuple[int, bytes]:
        """
        Sign with a key share. Returns (x_value, partial_signature).
        """
        x, sk_share = share
        sig = bls.Sign(sk_share, message)
        return (x, sig)

    @staticmethod
    def combine_partials(partials: list[tuple[int, bytes]], threshold: int) -> bytes:
        """
        Combine partial signatures using Lagrange interpolation
        on G2 points to recover the full signature.

        partials: list of (x_value, partial_signature)
        threshold: minimum number of partials needed
        """
        if len(partials) < threshold:
            raise ValueError(f"need {threshold} partials, got {len(partials)}")

        # Use only `threshold` partials
        partials = partials[:threshold]
        x_vals = [p[0] for p in partials]

        # Validate unique x-values (duplicates break Lagrange interpolation)
        if len(set(x_vals)) != len(x_vals):
            raise ValueError("duplicate x-values in partial signatures")

        # Compute Lagrange coefficients in the scalar field
        result = Z2  # point at infinity on G2
        for i, (xi, sig_bytes) in enumerate(partials):
            # Lagrange basis: L_i(0) = product((0 - xj) / (xi - xj)) for j != i
            numerator = 1
            denominator = 1
            for j, xj in enumerate(x_vals):
                if i != j:
                    numerator = (numerator * (-xj)) % CURVE_ORDER
                    denominator = (denominator * (xi - xj)) % CURVE_ORDER

            # Modular inverse of denominator
            lagrange = (numerator * pow(denominator, CURVE_ORDER - 2, CURVE_ORDER)) % CURVE_ORDER

            # Multiply partial signature (G2 point) by Lagrange coefficient
            sig_point = signature_to_G2(sig_bytes)
            weighted = multiply(sig_point, lagrange)
            result = add(result, weighted)

        return G2_to_signature(result)


# ═══════════════════════════════════════════════════════════════
# Job Attestation — practical threshold signing for compute jobs
# ═══════════════════════════════════════════════════════════════

def attest_job(job_id: str, result_hash: str, node_shares: list[tuple[int, int]],
               threshold: int) -> tuple[bytes, bytes]:
    """
    Multiple nodes attest to a job result using threshold BLS.

    Returns (aggregate_signature, message) — verify with master public key
    stored separately (from ThresholdBLS.generate_shares).
    """
    message = f"job:{job_id}:result:{result_hash}".encode()

    partials = []
    for share in node_shares:
        x, partial_sig = ThresholdBLS.partial_sign(share, message)
        partials.append((x, partial_sig))

    combined = ThresholdBLS.combine_partials(partials, threshold)
    return combined, message


def verify_attestation(master_pk: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a threshold attestation against the master public key."""
    return bls.Verify(master_pk, message, signature)
