"""
Governance — Neuron Improvement Proposals (NIPs).

Anyone can submit a proposal. Nodes vote. 67% supermajority required.
No auto-updates — each operator decides.

Phase 1: off-chain (stored locally, voted via P2P messages)
Phase 2: on-chain (Substrate pallet with token-weighted voting)

Types of proposals:
  - Parameter change (emission rate, cell size, etc.)
  - Protocol upgrade (new job types, new verification)
  - Network policy (minimum stake, ban threshold)
  - Feature activation (new privacy layers, new sandbox levels)
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

log = logging.getLogger(__name__)

GOVERNANCE_DIR = Path.home() / ".neuron" / "governance"
SUPERMAJORITY = 0.67  # 67% required to pass


class ProposalStatus(Enum):
    DRAFT = "draft"        # submitted, not yet open for voting
    VOTING = "voting"      # open for votes
    PASSED = "passed"      # 67% supermajority reached
    REJECTED = "rejected"  # voting ended, didn't pass
    EXECUTED = "executed"  # passed and applied


class ProposalType(Enum):
    PARAMETER = "parameter"      # change a network parameter
    PROTOCOL = "protocol"        # protocol upgrade
    POLICY = "policy"            # network policy change
    FEATURE = "feature"          # activate a feature


@dataclass
class Vote:
    node_id: str
    in_favor: bool
    weight: float = 1.0  # token-weighted in Phase 2
    timestamp: float = 0.0


@dataclass
class Proposal:
    nip_id: str  # NIP-001, NIP-002, etc.
    title: str
    description: str
    proposal_type: ProposalType
    author: str  # node_id of proposer
    created_at: float = 0.0
    voting_ends_at: float = 0.0  # timestamp
    status: ProposalStatus = ProposalStatus.DRAFT
    votes: list[Vote] = field(default_factory=list)

    # What changes if passed
    changes: dict = field(default_factory=dict)

    @property
    def votes_for(self) -> int:
        return sum(1 for v in self.votes if v.in_favor)

    @property
    def votes_against(self) -> int:
        return sum(1 for v in self.votes if not v.in_favor)

    @property
    def total_votes(self) -> int:
        return len(self.votes)

    @property
    def approval_rate(self) -> float:
        if not self.votes:
            return 0.0
        return self.votes_for / len(self.votes)

    def to_dict(self) -> dict:
        return {
            "nip_id": self.nip_id,
            "title": self.title,
            "description": self.description,
            "type": self.proposal_type.value,
            "author": self.author,
            "status": self.status.value,
            "votes_for": self.votes_for,
            "votes_against": self.votes_against,
            "approval_rate": round(self.approval_rate, 2),
            "changes": self.changes,
        }


class GovernanceSystem:
    """Manages proposals and voting."""

    def __init__(self, our_node_id: str = ""):
        self.our_node_id = our_node_id
        self._proposals: dict[str, Proposal] = {}
        self._next_nip = 1
        GOVERNANCE_DIR.mkdir(parents=True, exist_ok=True)
        self._load()

    def submit_proposal(
        self,
        title: str,
        description: str,
        proposal_type: ProposalType,
        changes: dict,
        voting_duration_hours: float = 72,  # 3 days default
    ) -> Proposal:
        """Submit a new NIP."""
        nip_id = f"NIP-{self._next_nip:03d}"
        self._next_nip += 1
        now = time.time()

        proposal = Proposal(
            nip_id=nip_id,
            title=title,
            description=description,
            proposal_type=proposal_type,
            author=self.our_node_id,
            created_at=now,
            voting_ends_at=now + voting_duration_hours * 3600,
            status=ProposalStatus.VOTING,
            changes=changes,
        )

        self._proposals[nip_id] = proposal
        self._save()
        log.info(f"Governance: {nip_id} submitted — {title}")
        return proposal

    def vote(self, nip_id: str, node_id: str, in_favor: bool) -> bool:
        """Cast a vote on a proposal."""
        proposal = self._proposals.get(nip_id)
        if not proposal or proposal.status != ProposalStatus.VOTING:
            return False

        # Check if already voted
        if any(v.node_id == node_id for v in proposal.votes):
            return False  # already voted

        # Check if voting period ended
        if time.time() > proposal.voting_ends_at:
            self._finalize_proposal(proposal)
            return False

        proposal.votes.append(Vote(
            node_id=node_id,
            in_favor=in_favor,
            timestamp=time.time(),
        ))

        log.info(f"Governance: {nip_id} vote from {node_id[:12]} — {'FOR' if in_favor else 'AGAINST'}")
        self._save()
        return True

    def check_proposals(self):
        """Check all voting proposals — finalize expired ones."""
        now = time.time()
        for proposal in self._proposals.values():
            if proposal.status == ProposalStatus.VOTING and now > proposal.voting_ends_at:
                self._finalize_proposal(proposal)

    def _finalize_proposal(self, proposal: Proposal):
        """Close voting and determine outcome."""
        if proposal.approval_rate >= SUPERMAJORITY and proposal.total_votes >= 1:
            proposal.status = ProposalStatus.PASSED
            log.info(f"Governance: {proposal.nip_id} PASSED ({proposal.approval_rate:.0%})")
        else:
            proposal.status = ProposalStatus.REJECTED
            log.info(f"Governance: {proposal.nip_id} REJECTED ({proposal.approval_rate:.0%})")
        self._save()

    def get_active_proposals(self) -> list[dict]:
        return [p.to_dict() for p in self._proposals.values() if p.status == ProposalStatus.VOTING]

    def get_all_proposals(self) -> list[dict]:
        return [p.to_dict() for p in self._proposals.values()]

    def _save(self):
        try:
            data = {nip: p.to_dict() for nip, p in self._proposals.items()}
            (GOVERNANCE_DIR / "proposals.json").write_text(json.dumps(data, indent=2))
        except Exception:
            pass

    def _load(self):
        proposals_file = GOVERNANCE_DIR / "proposals.json"
        if not proposals_file.exists():
            return
        try:
            data = json.loads(proposals_file.read_text())
            for nip_id, pd in data.items():
                self._proposals[nip_id] = Proposal(
                    nip_id=nip_id,
                    title=pd["title"],
                    description=pd["description"],
                    proposal_type=ProposalType(pd["type"]),
                    author=pd.get("author", ""),
                    status=ProposalStatus(pd["status"]),
                    changes=pd.get("changes", {}),
                )
                num = int(nip_id.split("-")[1])
                if num >= self._next_nip:
                    self._next_nip = num + 1
        except Exception:
            pass

    def summary(self) -> dict:
        return {
            "total_proposals": len(self._proposals),
            "active": sum(1 for p in self._proposals.values() if p.status == ProposalStatus.VOTING),
            "passed": sum(1 for p in self._proposals.values() if p.status == ProposalStatus.PASSED),
            "rejected": sum(1 for p in self._proposals.values() if p.status == ProposalStatus.REJECTED),
        }
