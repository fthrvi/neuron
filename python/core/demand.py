"""
Demand-Aware Rebalancing — Route models to where they're needed.

From mesh-llm pattern: every node tracks request rates per model.
Demand maps propagate via heartbeat gossip. Standby nodes promote
to active when demand exceeds supply.

This replaces pure load-balancing with demand-signal-based routing.

Usage:
    from core.demand import get_demand_tracker
    dt = get_demand_tracker()
    dt.record_request("qwen3:14b")         # on each inference
    dt.merge_remote(peer_demand_map)         # from heartbeat gossip
    suggestion = dt.get_rebalance_suggestion()  # what to load/unload
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

SNAPSHOT_INTERVAL = 60  # seconds between demand snapshots
PROMOTION_THRESHOLD_RPM = 5  # requests/min to trigger model promotion
IMBALANCE_RATIO = 3.0  # demand vs supply ratio to trigger rebalance
IDLE_EVICTION_MINUTES = 30  # unload model after 30min with 0 requests


@dataclass
class ModelDemand:
    """Demand tracking for a single model."""
    model: str
    local_requests: int = 0
    network_requests: int = 0  # aggregated from gossip
    servers: int = 0           # nodes currently serving this model
    last_request: float = 0.0
    requests_per_min: float = 0.0

    @property
    def supply_ratio(self) -> float:
        """Demand / supply. >1 means more demand than capacity."""
        if self.servers == 0:
            return float('inf') if self.requests_per_min > 0 else 0.0
        return self.requests_per_min / self.servers


@dataclass
class RebalanceSuggestion:
    """What the demand tracker suggests doing."""
    action: str           # "load", "unload", "none"
    model: str
    reason: str
    urgency: float = 0.0  # 0=low, 1=critical


class DemandTracker:
    """Tracks per-model demand and suggests rebalancing actions."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.models: dict[str, ModelDemand] = {}
        self._snapshot_time = time.time()
        self._period_requests: dict[str, int] = {}

    def record_request(self, model: str):
        """Record a request for a model. Called on each inference."""
        if model not in self.models:
            self.models[model] = ModelDemand(model=model)

        self.models[model].local_requests += 1
        self.models[model].last_request = time.time()
        self._period_requests[model] = self._period_requests.get(model, 0) + 1

    def snapshot(self) -> dict[str, int]:
        """Take a snapshot of requests since last snapshot.

        Called periodically (e.g., every heartbeat cycle).
        Returns demand map to include in heartbeat gossip.
        """
        now = time.time()
        elapsed = now - self._snapshot_time
        if elapsed < 1:
            elapsed = 1

        # Compute requests/min for each model
        for model, count in self._period_requests.items():
            if model not in self.models:
                self.models[model] = ModelDemand(model=model)
            self.models[model].requests_per_min = count * 60 / elapsed

        snapshot = dict(self._period_requests)
        self._period_requests.clear()
        self._snapshot_time = now
        return snapshot

    def merge_remote(self, peer_demand: dict[str, int], peer_models: list[str] = None):
        """Merge demand data from a remote peer (via heartbeat gossip).

        Args:
            peer_demand: {model: request_count} from remote node
            peer_models: list of models the remote node is serving
        """
        for model, count in peer_demand.items():
            if model not in self.models:
                self.models[model] = ModelDemand(model=model)
            # Use max to capture peak demand, not sum (avoids double-counting)
            self.models[model].network_requests = max(
                self.models[model].network_requests, count
            )

        # Track how many nodes serve each model
        if peer_models:
            # Reset server counts (rebuilt each gossip round)
            for m in self.models.values():
                m.servers = 0
            for model in peer_models:
                if model in self.models:
                    self.models[model].servers += 1

    def get_rebalance_suggestions(self) -> list[RebalanceSuggestion]:
        """Analyze demand vs supply and suggest rebalancing actions."""
        suggestions = []
        now = time.time()

        for model, demand in self.models.items():
            # Model with demand but no servers → LOAD
            if demand.servers == 0 and demand.requests_per_min > PROMOTION_THRESHOLD_RPM:
                suggestions.append(RebalanceSuggestion(
                    action="load",
                    model=model,
                    reason=f"{demand.requests_per_min:.0f} req/min but 0 servers",
                    urgency=min(1.0, demand.requests_per_min / 20),
                ))

            # Demand/supply imbalance → LOAD on more nodes
            elif demand.supply_ratio > IMBALANCE_RATIO and demand.requests_per_min > PROMOTION_THRESHOLD_RPM:
                suggestions.append(RebalanceSuggestion(
                    action="load",
                    model=model,
                    reason=f"supply ratio {demand.supply_ratio:.1f}x — overloaded",
                    urgency=min(1.0, demand.supply_ratio / 10),
                ))

            # Idle model → UNLOAD candidate
            elif (demand.last_request > 0 and
                  (now - demand.last_request) > IDLE_EVICTION_MINUTES * 60 and
                  demand.requests_per_min < 0.1):
                idle_min = (now - demand.last_request) / 60
                suggestions.append(RebalanceSuggestion(
                    action="unload",
                    model=model,
                    reason=f"idle for {idle_min:.0f}min",
                    urgency=0.3,
                ))

        # Sort by urgency
        suggestions.sort(key=lambda s: s.urgency, reverse=True)
        return suggestions

    def get_demand_map(self) -> dict:
        """Get the full demand map for monitoring/debugging."""
        return {
            model: {
                "local_requests": d.local_requests,
                "network_requests": d.network_requests,
                "servers": d.servers,
                "rpm": round(d.requests_per_min, 1),
                "supply_ratio": round(d.supply_ratio, 2) if d.supply_ratio != float('inf') else "inf",
                "idle_min": round((time.time() - d.last_request) / 60, 1) if d.last_request else None,
            }
            for model, d in self.models.items()
        }


def get_demand_tracker() -> DemandTracker:
    return DemandTracker()
