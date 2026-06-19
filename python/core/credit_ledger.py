"""
credit_ledger.py — reciprocal-compute CREDITS, the v1 incentive flywheel (no token, no chain).

Strategy: trisul/research/2026-06-19-incentive-layer-strategy.md. The #1 strategic gap vs shard
is that a stranger has no reason to plug a GPU into our mesh. v1 adds the pull WITHOUT a token:
a node EARNS credits for verified compute it serves, and SPENDS them to consume compute
(BitTorrent tit-for-tat for GPUs). Pure off-chain ledger, zero securities surface. The token
(SPL on Solana, USD-priced) is v2, only once there's real cross-operator usage to denominate.

This module is the accounting core. It is DELIBERATELY self-contained — it consumes a
nakshatra-style distributed run receipt as a plain dict (the data boundary; no cross-project
import per the four-project architecture) and re-verifies the invariants it relies on, so a
malicious caller can't mint credits from a forged receipt.

The proof-of-compute artifact = nakshatra's #20 `scripts/receipt.py` receipt:
  {run_id, n_generated, generated_tokens[], output_sha256,
   chain: [{node_id, layer_start, layer_end, ...}], ...}

Work + reciprocity model (v1):
  - units(worker_i)  = n_generated × (layer_end_i − layer_start_i)   # tokens × layers served
  - total            = Σ units(worker_i)                              # what the run cost
  - each serving worker is CREDITED its units; the requester is DEBITED `total`.
  - An operator who serves ≥ it consumes stays positive; a pure consumer goes negative and is
    throttled by `can_consume` until it contributes. That gradient IS the flywheel.

Sybil/fraud guards (v1 — layered, see strategy §5):
  - receipt is structurally + integrity verified (output_sha256 recomputed) before ANY credit.
  - earning is admission-gated: only peers at/above `min_earn_tier` earn (a stranger GPU can't
    farm credits). Injected `tier_of` (no import of the admission module).
  - credit is OPTIMISTIC + reversible: `dispute(run_id)` claws a settlement back when a random
    spot-check re-execution fails. (TEE attestation is the v2 upgrade for untrusted public GPUs.)
  - settlement is idempotent per run_id (receipt replay can't double-credit).
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

# Trust tiers (mirror admission.py / #17): higher rank = more trusted.
TIER_RANK = {"stranger": 0, "known": 1, "trusted": 2, "self": 3}


class CreditError(Exception):
    """A receipt could not be settled (invalid/forged) — no credit is awarded."""


def _output_sha256(tokens) -> str:
    """Canonical token-list hash — MUST match nakshatra receipt.output_sha256 (comma-joined ints)."""
    return hashlib.sha256(",".join(str(int(t)) for t in tokens).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CreditDelta:
    run_id: str
    credited: Dict[str, int]          # node_id -> units earned
    requester: str
    debited: int                      # units the requester paid (== total)
    total: int

    def net_for(self, account: str) -> int:
        d = self.credited.get(account, 0)
        if account == self.requester:
            d -= self.debited
        return d


class CreditLedger:
    """In-memory reciprocal-compute credit ledger. Persistence (JSON/sqlite) is a thin wrapper
    over `balances()`/`replay()` — out of scope for v1 core."""

    def __init__(self, *, tier_of: Optional[Callable[[str], str]] = None,
                 min_earn_tier: str = "known", grace: int = 0):
        self._bal: Dict[str, int] = defaultdict(int)
        self._settled: Dict[str, CreditDelta] = {}     # run_id -> delta (idempotency + dispute)
        self._tier_of = tier_of
        self._min_earn_rank = TIER_RANK[min_earn_tier]
        self.grace = int(grace)                         # bootstrap allowance for a fresh consumer

    # ---- verification (self-contained; no nakshatra import) ----
    @staticmethod
    def verify(receipt: dict) -> Tuple[bool, List[str]]:
        """Re-check the invariants credit relies on. Returns (ok, problems)."""
        problems: List[str] = []
        for k in ("run_id", "n_generated", "generated_tokens", "output_sha256", "chain"):
            if k not in receipt:
                problems.append(f"missing field: {k}")
        if problems:
            return False, problems
        gen = receipt["generated_tokens"]
        if len(gen) != receipt["n_generated"]:
            problems.append("n_generated != len(generated_tokens)")
        if _output_sha256(gen) != receipt["output_sha256"]:
            problems.append("output_sha256 does not match generated_tokens (forged/tampered)")
        chain = receipt["chain"]
        if not chain:
            problems.append("empty chain")
        ids = [c.get("node_id") for c in chain]
        if len(set(ids)) != len(ids):
            problems.append("duplicate node_id in chain")
        try:
            for c in chain:
                if int(c["layer_end"]) <= int(c["layer_start"]):
                    problems.append(f"non-positive layer range for {c.get('node_id')}")
        except (KeyError, TypeError, ValueError):
            problems.append("chain missing/invalid layer_start/layer_end")
        return (len(problems) == 0, problems)

    def _earns(self, node_id: str) -> bool:
        if self._tier_of is None:
            return True
        return TIER_RANK.get(self._tier_of(node_id), 0) >= self._min_earn_rank

    # ---- settlement ----
    def settle(self, receipt: dict, requester: str) -> CreditDelta:
        """Verify a run receipt and apply credits. Idempotent per run_id. Raises CreditError on
        an invalid receipt (no credit). The requester always pays; only admission-eligible
        workers earn (ineligible ones do the work but aren't credited — anti-Sybil)."""
        run_id = receipt.get("run_id")
        if run_id is None:
            raise CreditError("receipt has no run_id")
        if run_id in self._settled:
            return self._settled[run_id]                # replay → no double-credit
        ok, problems = self.verify(receipt)
        if not ok:
            raise CreditError(f"unverifiable receipt {run_id!r}: {'; '.join(problems)}")

        n = int(receipt["n_generated"])
        credited: Dict[str, int] = {}
        total = 0
        for c in receipt["chain"]:
            units = n * (int(c["layer_end"]) - int(c["layer_start"]))
            total += units                              # requester pays for ALL work served
            if self._earns(c["node_id"]):
                credited[c["node_id"]] = credited.get(c["node_id"], 0) + units
        for node_id, units in credited.items():
            self._bal[node_id] += units
        self._bal[requester] -= total
        delta = CreditDelta(run_id=run_id, credited=credited, requester=requester,
                            debited=total, total=total)
        self._settled[run_id] = delta
        return delta

    def dispute(self, run_id: str) -> bool:
        """Claw back a settled receipt (a spot-check re-execution failed). Reverses the deltas."""
        delta = self._settled.pop(run_id, None)
        if delta is None:
            return False
        for node_id, units in delta.credited.items():
            self._bal[node_id] -= units
        self._bal[delta.requester] += delta.debited
        return True

    # ---- queries / gates ----
    def balance(self, account: str) -> int:
        return self._bal.get(account, 0)

    def can_consume(self, account: str, est_cost: int) -> bool:
        """Reciprocal gate: you may consume only up to what you've earned (+ a bootstrap grace).
        Pure consumers go negative and are blocked until they serve."""
        return self.balance(account) + self.grace >= int(est_cost)

    @staticmethod
    def estimate_cost(n_tokens: int, num_blocks: int) -> int:
        """What a run of n_tokens over a num_blocks model will cost the requester (== total units)."""
        return int(n_tokens) * int(num_blocks)

    def balances(self) -> Dict[str, int]:
        return {k: v for k, v in self._bal.items() if v != 0}

    # ---- persistence (snapshot/restore; the service writes these to disk) ----
    def snapshot(self) -> dict:
        return {
            "balances": dict(self._bal),
            "settled": {rid: {"credited": d.credited, "requester": d.requester,
                              "debited": d.debited, "total": d.total}
                        for rid, d in self._settled.items()},
        }

    def restore(self, snap: dict) -> None:
        self._bal = defaultdict(int, {k: int(v) for k, v in snap.get("balances", {}).items()})
        self._settled = {}
        for rid, d in snap.get("settled", {}).items():
            self._settled[rid] = CreditDelta(
                run_id=rid, credited={k: int(v) for k, v in d["credited"].items()},
                requester=d["requester"], debited=int(d["debited"]), total=int(d["total"]))
