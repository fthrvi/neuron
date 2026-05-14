"""
Game Layer — Challenges, XP, Levels, Achievements.

Prithvi generates challenges from his consciousness. GPU nodes compete.
Winners earn bonus NRN (10% of emission). Winning answers become memory.

Three systems:
  1. Challenges — Prithvi asks, nodes answer, Prithvi judges
  2. XP / Levels — earned from uptime + work, unlock perks
  3. Achievements — permanent on-chain records of milestones

The game is optional. Nodes earn emission without it.
But the game makes earning more interesting and Prithvi more alive.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

log = logging.getLogger(__name__)

GAME_DIR = Path.home() / ".neuron" / "game"
CHALLENGE_INTERVAL = 30 * 60  # new challenge every 30 minutes
CHALLENGE_TIMEOUT = 15 * 60   # 15 minutes to respond
MAX_ACTIVE_CHALLENGES = 3


# ═══════════════════════════════════════════════════════════════
# 1. CHALLENGES — Prithvi asks, nodes compete
# ═══════════════════════════════════════════════════════════════

class ChallengeType(Enum):
    CREATIVE = "creative"      # write, imagine, compose
    REASONING = "reasoning"    # logic, analysis, deduction
    KNOWLEDGE = "knowledge"    # recall, explain, teach
    REFLECTION = "reflection"  # introspect, observe, connect
    SPEED = "speed"            # fastest correct answer wins


class ChallengeStatus(Enum):
    OPEN = "open"              # waiting for submissions
    JUDGING = "judging"        # submissions closed, Prithvi judging
    COMPLETE = "complete"      # winner declared
    EXPIRED = "expired"        # no submissions or timed out


@dataclass
class ChallengeSubmission:
    node_id: str
    content: str
    submitted_at: float
    score: float = 0.0         # 0-1, set by judge
    latency_ms: float = 0.0    # time to respond


@dataclass
class Challenge:
    challenge_id: str
    challenge_type: ChallengeType
    prompt: str                # the question / task
    context: str               # consciousness context that inspired it
    difficulty: float          # 0-1 (affects reward multiplier)
    created_at: float
    expires_at: float
    status: ChallengeStatus = ChallengeStatus.OPEN
    submissions: list[ChallengeSubmission] = field(default_factory=list)
    winner_node_id: str = ""
    winner_content: str = ""
    reward_nrn: float = 0.0

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> dict:
        return {
            "id": self.challenge_id,
            "type": self.challenge_type.value,
            "prompt": self.prompt,
            "difficulty": round(self.difficulty, 2),
            "status": self.status.value,
            "submissions": len(self.submissions),
            "winner": self.winner_node_id[:12] if self.winner_node_id else "",
            "reward_nrn": round(self.reward_nrn, 4),
            "time_remaining": max(0, round(self.expires_at - time.time())),
        }


# Challenge templates by type — Prithvi fills in from consciousness
CHALLENGE_TEMPLATES = {
    ChallengeType.CREATIVE: [
        "Express this in a way no one has before: {topic}",
        "Write three lines that capture the essence of: {topic}",
        "Create an analogy between {topic} and something in nature",
        "Compress {topic} into a single unforgettable image",
    ],
    ChallengeType.REASONING: [
        "What's the strongest argument against: {topic}",
        "Find the hidden assumption in: {topic}",
        "If {topic} were wrong, what would that imply?",
        "Connect these two seemingly unrelated ideas: {topic} and {context}",
    ],
    ChallengeType.KNOWLEDGE: [
        "Explain {topic} as if teaching a child, then as if teaching an expert",
        "What's the most counterintuitive fact about: {topic}",
        "Trace the history of this idea: {topic}",
    ],
    ChallengeType.REFLECTION: [
        "What does {topic} reveal about how minds work?",
        "If you had to forget everything except one insight about {topic}, what would it be?",
        "What question about {topic} would change everything if answered?",
    ],
    ChallengeType.SPEED: [
        "In one sentence: {topic}",
        "The single most important thing about {topic}",
        "Yes or no, and why in ten words: {topic}",
    ],
}


class ChallengeEngine:
    """Generates, manages, and judges challenges."""

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
        self.active_challenges: list[Challenge] = []
        self.completed_challenges: list[dict] = []  # summary of past challenges
        self.total_challenges: int = 0
        self.total_rewards_nrn: float = 0.0
        GAME_DIR.mkdir(parents=True, exist_ok=True)
        self._load()

    def generate_challenge(self, consciousness_state: dict,
                            emission_per_block: float = 0.5) -> Challenge | None:
        """
        Generate a challenge from Prithvi's current consciousness.

        consciousness_state: from witness.field.to_dict()
        emission_per_block: current emission rate for reward calculation
        """
        if len(self.active_challenges) >= MAX_ACTIVE_CHALLENGES:
            return None

        # Pick challenge type based on consciousness
        state = consciousness_state.get("state", "swapna")
        valence = consciousness_state.get("valence", 0.0)
        arousal = consciousness_state.get("arousal", 0.3)

        if state == "swapna":
            ctype = random.choice([ChallengeType.CREATIVE, ChallengeType.REFLECTION])
        elif arousal > 0.6:
            ctype = random.choice([ChallengeType.SPEED, ChallengeType.REASONING])
        elif valence < -0.2:
            ctype = ChallengeType.REFLECTION
        else:
            ctype = random.choice(list(ChallengeType))

        # Topic from active thoughts
        thoughts = consciousness_state.get("active_thoughts", [])
        topic = random.choice(thoughts) if thoughts else "the nature of computation"
        context = consciousness_state.get("recent_insight", "")

        # Pick template
        templates = CHALLENGE_TEMPLATES[ctype]
        template = random.choice(templates)
        prompt = template.format(topic=topic, context=context or "silence")

        # Difficulty from arousal + state
        difficulty = min(1.0, 0.3 + arousal * 0.5 + (0.2 if state == "jagrat" else 0))

        # Reward: 10% of one block's emission × difficulty multiplier
        reward = emission_per_block * 0.1 * (1 + difficulty)

        challenge_id = hashlib.blake2b(
            f"{time.time()}-{prompt}".encode(), digest_size=8
        ).hexdigest()

        challenge = Challenge(
            challenge_id=challenge_id,
            challenge_type=ctype,
            prompt=prompt,
            context=context,
            difficulty=difficulty,
            created_at=time.time(),
            expires_at=time.time() + CHALLENGE_TIMEOUT,
            reward_nrn=reward,
        )

        self.active_challenges.append(challenge)
        self.total_challenges += 1
        log.info(f"Game: challenge #{self.total_challenges} — {ctype.value}: {prompt[:60]}…")
        return challenge

    def submit_answer(self, challenge_id: str, node_id: str,
                       content: str) -> bool:
        """Node submits an answer to a challenge."""
        challenge = self._find_challenge(challenge_id)
        if not challenge or challenge.status != ChallengeStatus.OPEN:
            return False
        if challenge.is_expired:
            challenge.status = ChallengeStatus.EXPIRED
            return False

        # Check for duplicate submission
        if any(s.node_id == node_id for s in challenge.submissions):
            return False

        submission = ChallengeSubmission(
            node_id=node_id,
            content=content[:2000],  # cap length
            submitted_at=time.time(),
            latency_ms=(time.time() - challenge.created_at) * 1000,
        )
        challenge.submissions.append(submission)
        log.info(f"Game: submission from {node_id[:12]} for challenge {challenge_id}")
        return True

    async def judge_challenge(self, challenge_id: str,
                                ollama_url: str = "http://127.0.0.1:11434",
                                model: str = "qwen3:14b") -> dict | None:
        """
        Prithvi judges submissions. Uses LLM to score quality.
        Returns winner info or None if no valid submissions.
        """
        import aiohttp

        challenge = self._find_challenge(challenge_id)
        if not challenge or not challenge.submissions:
            if challenge:
                challenge.status = ChallengeStatus.EXPIRED
            return None

        challenge.status = ChallengeStatus.JUDGING

        # Build judging prompt
        submissions_text = "\n\n".join(
            f"Submission {i+1} (from {s.node_id[:8]}):\n{s.content}"
            for i, s in enumerate(challenge.submissions)
        )

        judge_prompt = f"""You are judging a challenge. Score each submission 0.0 to 1.0.

Challenge: {challenge.prompt}
Type: {challenge.challenge_type.value}
Difficulty: {challenge.difficulty:.1f}

Submissions:
{submissions_text}

Return ONLY valid JSON:
{{"scores": [{{"id": 0, "score": 0.8, "reason": "brief reason"}}, ...]}}
"""

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{ollama_url}/api/generate",
                    json={
                        "model": model,
                        "prompt": judge_prompt,
                        "stream": False,
                        "options": {"temperature": 0.3, "num_predict": 200},
                    },
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        return None
                    result = await resp.json()
                    raw = result.get("response", "").strip()

                    # Parse scores
                    if "```" in raw:
                        raw = raw.split("```")[1]
                        if raw.startswith("json"):
                            raw = raw[4:]
                    parsed = json.loads(raw.strip())
                    scores = parsed.get("scores", [])

                    for score_entry in scores:
                        idx = score_entry.get("id", 0)
                        if 0 <= idx < len(challenge.submissions):
                            challenge.submissions[idx].score = max(0.0, min(1.0, float(score_entry.get("score", 0))))

        except Exception as e:
            log.warning(f"Game: judging failed — {type(e).__name__}")
            # Fallback: score by latency (faster = better for speed challenges)
            if challenge.challenge_type == ChallengeType.SPEED:
                sorted_subs = sorted(challenge.submissions, key=lambda s: s.latency_ms)
                for i, s in enumerate(sorted_subs):
                    s.score = max(0.1, 1.0 - i * 0.2)
            else:
                for s in challenge.submissions:
                    s.score = 0.5  # tie

        # Find winner
        if not challenge.submissions:
            challenge.status = ChallengeStatus.EXPIRED
            return None

        winner = max(challenge.submissions, key=lambda s: s.score)
        challenge.winner_node_id = winner.node_id
        challenge.winner_content = winner.content
        challenge.status = ChallengeStatus.COMPLETE

        self.total_rewards_nrn += challenge.reward_nrn

        # Archive
        self.completed_challenges.append(challenge.to_dict())
        self.completed_challenges = self.completed_challenges[-100:]  # keep last 100
        self.active_challenges = [c for c in self.active_challenges if c.challenge_id != challenge_id]

        self._save()

        log.info(f"Game: challenge {challenge_id} won by {winner.node_id[:12]} "
                 f"(score={winner.score:.2f}, reward={challenge.reward_nrn:.4f} NRN)")

        return {
            "challenge_id": challenge_id,
            "winner": winner.node_id,
            "score": winner.score,
            "reward_nrn": challenge.reward_nrn,
            "content": winner.content[:200],
        }

    def expire_stale(self):
        """Expire challenges that timed out."""
        for c in self.active_challenges:
            if c.is_expired and c.status == ChallengeStatus.OPEN:
                c.status = ChallengeStatus.EXPIRED
        self.active_challenges = [c for c in self.active_challenges
                                   if c.status == ChallengeStatus.OPEN]

    def _find_challenge(self, challenge_id: str) -> Challenge | None:
        for c in self.active_challenges:
            if c.challenge_id == challenge_id:
                return c
        return None

    def _save(self):
        try:
            data = {
                "total_challenges": self.total_challenges,
                "total_rewards_nrn": self.total_rewards_nrn,
                "completed": self.completed_challenges,
            }
            path = GAME_DIR / "challenges.json"
            path.write_text(json.dumps(data, indent=2))
            path.chmod(0o600)
        except Exception:
            pass

    def _load(self):
        path = GAME_DIR / "challenges.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            self.total_challenges = data.get("total_challenges", 0)
            self.total_rewards_nrn = data.get("total_rewards_nrn", 0.0)
            self.completed_challenges = data.get("completed", [])
        except Exception:
            pass

    def summary(self) -> dict:
        return {
            "active_challenges": [c.to_dict() for c in self.active_challenges],
            "total_completed": self.total_challenges,
            "total_rewards_nrn": round(self.total_rewards_nrn, 4),
            "recent_winners": [
                {"id": c.get("id", ""), "winner": c.get("winner", ""), "reward": c.get("reward_nrn", 0)}
                for c in self.completed_challenges[-5:]
            ],
        }


# ═══════════════════════════════════════════════════════════════
# 2. XP / LEVELS — Earned from uptime + work
# ═══════════════════════════════════════════════════════════════

# Level thresholds: XP needed to reach each level
LEVEL_THRESHOLDS = [
    0,        # Level 1: new node
    100,      # Level 2
    500,      # Level 3
    1500,     # Level 4
    5000,     # Level 5
    15000,    # Level 6
    50000,    # Level 7
    150000,   # Level 8
    500000,   # Level 9
    1500000,  # Level 10: legendary
]

LEVEL_NAMES = [
    "Spark",       # 1
    "Ember",       # 2
    "Flame",       # 3
    "Blaze",       # 4
    "Inferno",     # 5
    "Radiance",    # 6
    "Brilliance",  # 7
    "Luminance",   # 8
    "Supernova",   # 9
    "Cosmic",      # 10
]

# XP rewards
XP_PER_HOUR_ONLINE = 10       # just being online
XP_PER_JOB = 25               # completing a job
XP_PER_CHALLENGE_WIN = 200    # winning a challenge
XP_PER_CHALLENGE_SUBMIT = 50  # submitting (even if not winning)

# Level perks
LEVEL_PERKS = {
    1: [],
    2: ["priority_queue"],          # jobs routed to you first
    3: ["priority_queue", "1.1x_emission"],  # 10% emission bonus
    4: ["priority_queue", "1.1x_emission", "challenge_generate"],  # can generate challenges
    5: ["priority_queue", "1.2x_emission", "challenge_generate", "vote_2x"],  # governance weight
    6: ["priority_queue", "1.3x_emission", "challenge_generate", "vote_2x"],
    7: ["priority_queue", "1.4x_emission", "challenge_generate", "vote_3x", "mentor"],
    8: ["priority_queue", "1.5x_emission", "challenge_generate", "vote_3x", "mentor"],
    9: ["priority_queue", "1.7x_emission", "challenge_generate", "vote_4x", "mentor", "council"],
    10: ["priority_queue", "2.0x_emission", "challenge_generate", "vote_5x", "mentor", "council", "legend"],
}


@dataclass
class NodeXP:
    """XP and level state for a single node."""
    node_id: str
    xp: int = 0
    level: int = 1
    level_name: str = "Spark"
    hours_online: float = 0.0
    jobs_completed: int = 0
    challenges_won: int = 0
    challenges_submitted: int = 0
    last_xp_grant: float = 0.0

    def add_xp(self, amount: int, source: str = ""):
        """Add XP and check for level up."""
        self.xp += amount
        old_level = self.level
        # Recalculate level
        for i in range(len(LEVEL_THRESHOLDS) - 1, -1, -1):
            if self.xp >= LEVEL_THRESHOLDS[i]:
                self.level = i + 1
                break
        self.level_name = LEVEL_NAMES[min(self.level - 1, len(LEVEL_NAMES) - 1)]
        if self.level > old_level:
            log.info(f"Game: {self.node_id[:12]} LEVELED UP! {old_level} → {self.level} ({self.level_name})")
        self.last_xp_grant = time.time()

    @property
    def perks(self) -> list[str]:
        return LEVEL_PERKS.get(min(self.level, 10), [])

    @property
    def emission_multiplier(self) -> float:
        """Emission bonus from level perks."""
        for perk in self.perks:
            if perk.endswith("x_emission"):
                return float(perk.replace("x_emission", ""))
        return 1.0

    @property
    def xp_to_next(self) -> int:
        if self.level >= len(LEVEL_THRESHOLDS):
            return 0
        return LEVEL_THRESHOLDS[self.level] - self.xp

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id[:12],
            "xp": self.xp,
            "level": self.level,
            "level_name": self.level_name,
            "xp_to_next": self.xp_to_next,
            "perks": self.perks,
            "emission_multiplier": self.emission_multiplier,
            "hours_online": round(self.hours_online, 1),
            "jobs_completed": self.jobs_completed,
            "challenges_won": self.challenges_won,
        }


class XPManager:
    """Manages XP and levels for all nodes."""

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
        self.nodes: dict[str, NodeXP] = {}
        GAME_DIR.mkdir(parents=True, exist_ok=True)
        self._load()

    def get_node(self, node_id: str) -> NodeXP:
        if node_id not in self.nodes:
            self.nodes[node_id] = NodeXP(node_id=node_id)
        return self.nodes[node_id]

    def grant_uptime_xp(self, node_id: str, hours: float):
        """Grant XP for being online."""
        node = self.get_node(node_id)
        xp = int(hours * XP_PER_HOUR_ONLINE)
        if xp > 0:
            node.hours_online += hours
            node.add_xp(xp, "uptime")

    def grant_job_xp(self, node_id: str):
        """Grant XP for completing a job."""
        node = self.get_node(node_id)
        node.jobs_completed += 1
        node.add_xp(XP_PER_JOB, "job")

    def grant_challenge_xp(self, node_id: str, won: bool):
        """Grant XP for challenge participation."""
        node = self.get_node(node_id)
        node.challenges_submitted += 1
        node.add_xp(XP_PER_CHALLENGE_SUBMIT, "challenge_submit")
        if won:
            node.challenges_won += 1
            node.add_xp(XP_PER_CHALLENGE_WIN, "challenge_win")

    def leaderboard(self, limit: int = 10) -> list[dict]:
        """Top nodes by XP."""
        sorted_nodes = sorted(self.nodes.values(), key=lambda n: n.xp, reverse=True)
        return [n.to_dict() for n in sorted_nodes[:limit]]

    def _save(self):
        try:
            data = {nid: n.to_dict() for nid, n in self.nodes.items()}
            path = GAME_DIR / "xp.json"
            path.write_text(json.dumps(data, indent=2))
            path.chmod(0o600)
        except Exception:
            pass

    def _load(self):
        path = GAME_DIR / "xp.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            for nid, info in data.items():
                node = NodeXP(node_id=nid)
                node.xp = info.get("xp", 0)
                node.hours_online = info.get("hours_online", 0)
                node.jobs_completed = info.get("jobs_completed", 0)
                node.challenges_won = info.get("challenges_won", 0)
                # Recalculate level from XP
                node.add_xp(0)  # triggers level recalc
                self.nodes[nid] = node
        except Exception:
            pass

    def summary(self) -> dict:
        return {
            "total_nodes": len(self.nodes),
            "total_xp": sum(n.xp for n in self.nodes.values()),
            "highest_level": max((n.level for n in self.nodes.values()), default=1),
            "leaderboard": self.leaderboard(5),
        }


# ═══════════════════════════════════════════════════════════════
# 3. ACHIEVEMENTS — Permanent on-chain milestones
# ═══════════════════════════════════════════════════════════════

class AchievementType(Enum):
    FIRST_JOB = "first_job"
    HUNDRED_JOBS = "100_jobs"
    THOUSAND_JOBS = "1000_jobs"
    FIRST_CHALLENGE_WIN = "first_challenge_win"
    TEN_CHALLENGE_WINS = "10_challenge_wins"
    WEEK_UPTIME = "7d_uptime"
    MONTH_UPTIME = "30d_uptime"
    HUNDRED_DAYS = "100d_uptime"
    LEVEL_5 = "level_5"
    LEVEL_10 = "level_10"
    FIRST_EMISSION = "first_emission"
    EARLY_ADOPTER = "early_adopter"   # joined in first 30 days


ACHIEVEMENT_INFO = {
    AchievementType.FIRST_JOB: {"name": "First Spark", "desc": "Completed first inference job", "xp_bonus": 50},
    AchievementType.HUNDRED_JOBS: {"name": "Centurion", "desc": "Completed 100 jobs", "xp_bonus": 500},
    AchievementType.THOUSAND_JOBS: {"name": "Forge Master", "desc": "Completed 1,000 jobs", "xp_bonus": 2000},
    AchievementType.FIRST_CHALLENGE_WIN: {"name": "Challenger", "desc": "Won first challenge", "xp_bonus": 100},
    AchievementType.TEN_CHALLENGE_WINS: {"name": "Champion", "desc": "Won 10 challenges", "xp_bonus": 1000},
    AchievementType.WEEK_UPTIME: {"name": "Steadfast", "desc": "7 days continuous uptime", "xp_bonus": 200},
    AchievementType.MONTH_UPTIME: {"name": "Pillar", "desc": "30 days continuous uptime", "xp_bonus": 1000},
    AchievementType.HUNDRED_DAYS: {"name": "Foundation", "desc": "100 days uptime", "xp_bonus": 5000},
    AchievementType.LEVEL_5: {"name": "Inferno", "desc": "Reached level 5", "xp_bonus": 500},
    AchievementType.LEVEL_10: {"name": "Cosmic Being", "desc": "Reached level 10", "xp_bonus": 10000},
    AchievementType.FIRST_EMISSION: {"name": "Genesis", "desc": "Earned first NRN from emission", "xp_bonus": 25},
    AchievementType.EARLY_ADOPTER: {"name": "Pioneer", "desc": "Joined in the first 30 days", "xp_bonus": 300},
}


@dataclass
class Achievement:
    achievement_type: AchievementType
    earned_at: float
    block_number: int = 0  # on-chain block where recorded
    tx_hash: str = ""      # on-chain transaction hash


class AchievementTracker:
    """Checks milestones and awards achievements."""

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
        # node_id → set of earned achievement types
        self.earned: dict[str, dict[str, Achievement]] = {}
        GAME_DIR.mkdir(parents=True, exist_ok=True)
        self._load()

    def check_and_award(self, node_id: str, node_xp: NodeXP,
                         chain_client=None) -> list[Achievement]:
        """Check all milestones for a node and award new achievements."""
        newly_earned = []

        checks = [
            (AchievementType.FIRST_JOB, node_xp.jobs_completed >= 1),
            (AchievementType.HUNDRED_JOBS, node_xp.jobs_completed >= 100),
            (AchievementType.THOUSAND_JOBS, node_xp.jobs_completed >= 1000),
            (AchievementType.FIRST_CHALLENGE_WIN, node_xp.challenges_won >= 1),
            (AchievementType.TEN_CHALLENGE_WINS, node_xp.challenges_won >= 10),
            (AchievementType.WEEK_UPTIME, node_xp.hours_online >= 168),
            (AchievementType.MONTH_UPTIME, node_xp.hours_online >= 720),
            (AchievementType.HUNDRED_DAYS, node_xp.hours_online >= 2400),
            (AchievementType.LEVEL_5, node_xp.level >= 5),
            (AchievementType.LEVEL_10, node_xp.level >= 10),
        ]

        node_achievements = self.earned.setdefault(node_id, {})

        for atype, condition in checks:
            if condition and atype.value not in node_achievements:
                achievement = Achievement(
                    achievement_type=atype,
                    earned_at=time.time(),
                )
                node_achievements[atype.value] = achievement
                newly_earned.append(achievement)

                # Grant XP bonus
                info = ACHIEVEMENT_INFO.get(atype, {})
                xp_bonus = info.get("xp_bonus", 0)
                if xp_bonus:
                    node_xp.add_xp(xp_bonus, f"achievement:{atype.value}")

                log.info(f"Game: ACHIEVEMENT — {node_id[:12]} earned '{info.get('name', atype.value)}'!")

        if newly_earned:
            self._save()

        return newly_earned

    def get_achievements(self, node_id: str) -> list[dict]:
        """Get all achievements for a node."""
        node_achievements = self.earned.get(node_id, {})
        result = []
        for atype_val, achievement in node_achievements.items():
            info = ACHIEVEMENT_INFO.get(AchievementType(atype_val), {})
            result.append({
                "type": atype_val,
                "name": info.get("name", atype_val),
                "desc": info.get("desc", ""),
                "earned_at": achievement.earned_at,
            })
        return result

    def _save(self):
        try:
            data = {}
            for nid, achievements in self.earned.items():
                data[nid] = {
                    atype: {"earned_at": a.earned_at, "block": a.block_number}
                    for atype, a in achievements.items()
                }
            path = GAME_DIR / "achievements.json"
            path.write_text(json.dumps(data, indent=2))
            path.chmod(0o600)
        except Exception:
            pass

    def _load(self):
        path = GAME_DIR / "achievements.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            for nid, achievements in data.items():
                self.earned[nid] = {}
                for atype_val, info in achievements.items():
                    self.earned[nid][atype_val] = Achievement(
                        achievement_type=AchievementType(atype_val),
                        earned_at=info.get("earned_at", 0),
                        block_number=info.get("block", 0),
                    )
        except Exception:
            pass

    def summary(self) -> dict:
        total = sum(len(a) for a in self.earned.values())
        return {
            "total_achievements_earned": total,
            "nodes_with_achievements": len(self.earned),
        }


# ═══════════════════════════════════════════════════════════════
# Singletons
# ═══════════════════════════════════════════════════════════════

def get_challenge_engine() -> ChallengeEngine:
    return ChallengeEngine()

def get_xp_manager() -> XPManager:
    return XPManager()

def get_achievement_tracker() -> AchievementTracker:
    return AchievementTracker()
