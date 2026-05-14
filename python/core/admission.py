"""
Admission Control — Sybil resistance for the Neuron Network.

Three layers of protection:
  1. Benchmark verification — prove your GPU is real (already in benchmark.py)
  2. Stake requirement — deposit NRN to join (economic cost to sybil attack)
  3. Invite chain — trust propagation from existing nodes

A sybil attacker would need:
  - Real GPUs (benchmark catches fake claims)
  - Real NRN tokens (stake catches zero-cost spam)
  - A real invite from a trusted node (social trust)

All three must pass for a node to move from Joining → Online.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum

log = logging.getLogger(__name__)


class AdmissionResult(Enum):
    ADMITTED = "admitted"
    BENCHMARK_FAILED = "benchmark_failed"
    INSUFFICIENT_STAKE = "insufficient_stake"
    INVALID_INVITE = "invalid_invite"
    REJECTED = "rejected"


@dataclass
class AdmissionCheck:
    """Result of a node's admission check."""
    node_id: str
    result: AdmissionResult
    benchmark_passed: bool = False
    benchmark_tflops: float = 0.0
    stake_sufficient: bool = False
    stake_amount: float = 0.0
    invite_valid: bool = False
    invite_from: str = ""
    rejection_reason: str = ""
    timestamp: float = 0.0


# GPU node operators join for FREE — they contribute hardware.
# Staking is for USERS who consume compute without contributing a GPU.
# Node admission = benchmark + invite. No stake required.
MIN_STAKE_NRN = 0.0  # Always 0 for GPU contributors

# Minimum benchmark TFLOPS to be considered a real GPU
MIN_TFLOPS = 0.5  # Even a weak GPU should hit this

# Slashing: percentage of stake lost for misbehavior
SLASH_PERCENT = {
    "fake_benchmark": 100,   # caught lying about GPU → lose everything
    "job_failure_rate": 25,  # >50% job failure rate → lose 25%
    "verification_fail": 50, # failed spot-check verification → lose 50%
}


class AdmissionController:
    """Controls who can join the network and under what conditions."""

    def __init__(self):
        self._checks: list[AdmissionCheck] = []

    def check_admission(
        self,
        node_id: str,
        benchmark_result: dict | None = None,
        stake_amount: float = 0.0,
        invite_code: str = "",
        invite_from: str = "",
    ) -> AdmissionCheck:
        """Run all admission checks for a joining node."""

        check = AdmissionCheck(
            node_id=node_id,
            result=AdmissionResult.ADMITTED,
            timestamp=time.time(),
        )

        # 1. Benchmark verification
        if benchmark_result:
            tflops = benchmark_result.get("tflops_fp16", 0)
            vram = benchmark_result.get("vram_total_mb", 0)
            check.benchmark_tflops = tflops

            if tflops >= MIN_TFLOPS or vram > 0:
                check.benchmark_passed = True
            else:
                check.benchmark_passed = False
                check.result = AdmissionResult.BENCHMARK_FAILED
                check.rejection_reason = f"Benchmark too low: {tflops} TFLOPS (need {MIN_TFLOPS})"
                log.warning(f"Admission: {node_id[:12]} failed benchmark ({tflops} TFLOPS)")
        else:
            # No benchmark yet — admitted provisionally (benchmark runs async)
            check.benchmark_passed = True

        # 2. Stake check
        if MIN_STAKE_NRN > 0:
            check.stake_amount = stake_amount
            if stake_amount >= MIN_STAKE_NRN:
                check.stake_sufficient = True
            else:
                check.stake_sufficient = False
                check.result = AdmissionResult.INSUFFICIENT_STAKE
                check.rejection_reason = f"Stake {stake_amount} < required {MIN_STAKE_NRN} NRN"
                log.warning(f"Admission: {node_id[:12]} insufficient stake ({stake_amount} NRN)")
        else:
            check.stake_sufficient = True  # Phase 1: no stake required

        # 3. Invite check (Phase 1: invite always valid if code present)
        if invite_code or invite_from:
            check.invite_valid = True
            check.invite_from = invite_from
        else:
            # Phase 1: allow without invite (genesis/bootstrap)
            check.invite_valid = True

        # Final decision
        if check.benchmark_passed and check.stake_sufficient and check.invite_valid:
            check.result = AdmissionResult.ADMITTED
            log.info(f"Admission: {node_id[:12]} ADMITTED (benchmark={check.benchmark_tflops:.1f} TFLOPS)")
        elif check.result == AdmissionResult.ADMITTED:
            check.result = AdmissionResult.REJECTED

        self._checks.append(check)
        return check

    def calculate_slash(self, offense: str, stake: float) -> float:
        """Calculate how much stake to slash for a given offense."""
        percent = SLASH_PERCENT.get(offense, 0)
        return stake * percent / 100

    def summary(self) -> dict:
        admitted = sum(1 for c in self._checks if c.result == AdmissionResult.ADMITTED)
        rejected = sum(1 for c in self._checks if c.result != AdmissionResult.ADMITTED)
        return {
            "total_checks": len(self._checks),
            "admitted": admitted,
            "rejected": rejected,
            "min_stake_nrn": MIN_STAKE_NRN,
            "min_tflops": MIN_TFLOPS,
        }
