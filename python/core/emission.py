"""
Token Emission & Staking — NRN token economics.

Emission schedule (from whitepaper):
  E(n) = E₀ × e^(−λn)
  E₀ = 50 NRN per block, λ = ln(2)/100
  At 100 nodes: emission halves. At 500: 1.56 NRN/block.
  Hard cap: 21,000,000 NRN.

Per-block distribution:
  45% → Availability rewards
  45% → Compute rewards
  10% → Validators

Staking:
  Stake NRN → earn compute credits
  C(s) = s × 10 × (1 + rep/1000) per day
  Credits non-transferable, expire in 30 days

Demurrage:
  Idle unstaked tokens decay 2%/month
  Keeps supply circulating

Fee burn:
  Base fees burned (deflationary)
  Priority tips paid to workers
"""
from __future__ import annotations

import math
import logging
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# Emission constants
E0 = 50.0  # initial emission per block
LAMBDA = math.log(2) / 100  # halving at 100 nodes
HARD_CAP = 21_000_000.0
BLOCKS_PER_DAY = 14_400  # assuming ~6s block time

# Distribution split
AVAILABILITY_SHARE = 0.45
COMPUTE_SHARE = 0.45
VALIDATOR_SHARE = 0.10

# Staking
STAKE_CREDIT_RATE = 10.0  # credits per NRN staked per day
CREDIT_EXPIRY_DAYS = 30

# Demurrage
DEMURRAGE_RATE = 0.02  # 2% per month on idle unstaked tokens
DEMURRAGE_PERIOD_DAYS = 30

# Fee burn
BASE_FEE_BURN_RATE = 0.50  # 50% of base fees burned


def emission_per_block(network_size: int) -> float:
    """Calculate NRN emission for a single block given network size."""
    return E0 * math.exp(-LAMBDA * network_size)


def emission_per_day(network_size: int) -> float:
    """Total NRN emitted per day."""
    return emission_per_block(network_size) * BLOCKS_PER_DAY


def total_supply_at_size(network_size: int) -> float:
    """Approximate total supply emitted up to this network size."""
    # Integral of E0 * e^(-λn) from 0 to n = E0/λ * (1 - e^(-λn))
    return min(HARD_CAP, (E0 / LAMBDA) * (1 - math.exp(-LAMBDA * network_size)) * BLOCKS_PER_DAY)


@dataclass
class StakePosition:
    """A node's staking position."""

    node_id: str
    staked_amount: float = 0.0
    staked_at: float = 0.0
    credits_earned: float = 0.0
    credits_spent: float = 0.0
    last_credit_calc: float = 0.0

    @property
    def credits_available(self) -> float:
        return max(0.0, self.credits_earned - self.credits_spent)


@dataclass
class EmissionState:
    """Current emission state of the network."""

    total_minted: float = 0.0
    total_burned: float = 0.0
    current_block: int = 0
    network_size: int = 0
    emission_rate: float = E0  # current per-block rate


class EmissionSchedule:
    """
    Manages the NRN token emission schedule and staking.

    Called once per block (checkpoint) to:
      1. Calculate emission for this block
      2. Distribute to availability/compute/validators
      3. Apply demurrage on idle tokens
      4. Burn base fees
      5. Calculate staking credits
    """

    def __init__(self):
        self.state = EmissionState()
        self.stakes: dict[str, StakePosition] = {}

    def mint_block(
        self,
        network_size: int,
        availability_nodes: list[tuple[str, float]],  # (node_id, benchmark_score)
        compute_jobs: list[tuple[str, float, float]],  # (node_id, benchmark, duration)
        validators: list[str],
    ) -> dict:
        """
        Process one block of emission.
        Returns distribution details.
        """
        self.state.network_size = network_size
        self.state.current_block += 1

        # Check hard cap
        if self.state.total_minted >= HARD_CAP:
            return {"emission": 0, "capped": True}

        # Calculate emission
        emission = emission_per_block(network_size)
        remaining = HARD_CAP - self.state.total_minted
        emission = min(emission, remaining)

        self.state.emission_rate = emission
        self.state.total_minted += emission

        # Distribute
        avail_pool = emission * AVAILABILITY_SHARE
        compute_pool = emission * COMPUTE_SHARE
        validator_pool = emission * VALIDATOR_SHARE

        distribution = {
            "block": self.state.current_block,
            "emission": round(emission, 6),
            "availability": {},
            "compute": {},
            "validators": {},
        }

        # Availability rewards (weighted by benchmark score × uptime)
        total_bench = sum(score for _, score in availability_nodes) or 1.0
        for node_id, score in availability_nodes:
            share = (score / total_bench) * avail_pool
            distribution["availability"][node_id] = round(share, 6)

        # Compute rewards (weighted by benchmark × duration)
        total_work = sum(bench * dur for _, bench, dur in compute_jobs) or 1.0
        for node_id, bench, dur in compute_jobs:
            share = ((bench * dur) / total_work) * compute_pool
            distribution["compute"][node_id] = round(share, 6)

        # Validator rewards (equal split)
        if validators:
            per_validator = validator_pool / len(validators)
            for v in validators:
                distribution["validators"][v] = round(per_validator, 6)

        return distribution

    # --- Staking ---

    def stake(self, node_id: str, amount: float) -> bool:
        """Stake NRN tokens to earn compute credits."""
        if amount <= 0:
            return False
        if node_id not in self.stakes:
            self.stakes[node_id] = StakePosition(node_id=node_id)
        pos = self.stakes[node_id]
        pos.staked_amount += amount
        pos.staked_at = time.time()
        pos.last_credit_calc = time.time()
        log.info(f"Emission: {node_id[:12]} staked {amount:.4f} NRN (total={pos.staked_amount:.4f})")
        return True

    def unstake(self, node_id: str, amount: float) -> float:
        """Unstake NRN tokens. Returns actual amount unstaked."""
        pos = self.stakes.get(node_id)
        if not pos:
            return 0.0
        actual = min(amount, pos.staked_amount)
        pos.staked_amount -= actual
        return actual

    def calculate_credits(self, node_id: str, reputation: float = 0.0) -> float:
        """
        Calculate earned compute credits from staking.
        C(s) = s × 10 × (1 + rep/1000) per day
        """
        pos = self.stakes.get(node_id)
        if not pos or pos.staked_amount <= 0:
            return 0.0

        now = time.time()
        days = (now - pos.last_credit_calc) / 86400
        if days <= 0:
            return 0.0

        credits = pos.staked_amount * STAKE_CREDIT_RATE * (1 + reputation / 1000) * days
        pos.credits_earned += credits
        pos.last_credit_calc = now
        return round(credits, 6)

    # --- Demurrage ---

    def apply_demurrage(self, balances: dict[str, float]) -> dict[str, float]:
        """
        Apply demurrage to idle unstaked tokens.
        2% per month on unstaked balances.
        Returns the decayed amounts per node.
        """
        decayed = {}
        for node_id, balance in balances.items():
            staked = self.stakes.get(node_id)
            unstaked = balance - (staked.staked_amount if staked else 0)
            if unstaked > 0:
                decay = unstaked * DEMURRAGE_RATE / DEMURRAGE_PERIOD_DAYS
                decayed[node_id] = round(decay, 6)
        return decayed

    # --- Fee Burn ---

    def burn_fee(self, amount: float) -> float:
        """Burn a portion of a transaction fee. Returns burned amount."""
        burned = amount * BASE_FEE_BURN_RATE
        self.state.total_burned += burned
        return round(burned, 6)

    # --- Queries ---

    def emission_table(self, max_nodes: int = 1000) -> list[dict]:
        """Generate emission table for different network sizes."""
        sizes = [1, 5, 10, 25, 50, 100, 200, 500, 1000]
        return [
            {
                "nodes": n,
                "per_block": round(emission_per_block(n), 4),
                "per_day": round(emission_per_day(n), 2),
                "total_supply_est": round(total_supply_at_size(n), 0),
            }
            for n in sizes if n <= max_nodes
        ]

    def summary(self) -> dict:
        return {
            "total_minted": round(self.state.total_minted, 4),
            "total_burned": round(self.state.total_burned, 4),
            "circulating": round(self.state.total_minted - self.state.total_burned, 4),
            "emission_rate": round(self.state.emission_rate, 4),
            "block": self.state.current_block,
            "network_size": self.state.network_size,
            "hard_cap": HARD_CAP,
            "cap_reached_pct": round(self.state.total_minted / HARD_CAP * 100, 2),
            "total_staked": round(sum(s.staked_amount for s in self.stakes.values()), 4),
        }
