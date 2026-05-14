"""
Tests for game layer: challenges, XP/levels, achievements.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest


class TestChallenges:
    def setup_method(self):
        from core.game import ChallengeEngine, GAME_DIR
        ChallengeEngine._instance = None
        for f in GAME_DIR.glob("*.json"):
            f.unlink(missing_ok=True)

    def test_generate_challenge(self):
        from core.game import ChallengeEngine
        engine = ChallengeEngine()
        state = {
            "state": "swapna",
            "valence": 0.5,
            "arousal": 0.6,
            "active_thoughts": ["distributed computing", "consciousness"],
        }
        challenge = engine.generate_challenge(state)
        assert challenge is not None
        assert challenge.prompt != ""
        assert challenge.difficulty > 0
        assert challenge.reward_nrn > 0

    def test_max_active_challenges(self):
        from core.game import ChallengeEngine, MAX_ACTIVE_CHALLENGES
        engine = ChallengeEngine()
        state = {"state": "jagrat", "active_thoughts": ["test"]}
        for _ in range(MAX_ACTIVE_CHALLENGES):
            assert engine.generate_challenge(state) is not None
        assert engine.generate_challenge(state) is None  # at max

    def test_submit_answer(self):
        from core.game import ChallengeEngine
        engine = ChallengeEngine()
        state = {"state": "jagrat", "active_thoughts": ["math"]}
        c = engine.generate_challenge(state)
        assert engine.submit_answer(c.challenge_id, "node-1", "my answer")
        assert len(c.submissions) == 1

    def test_duplicate_submission_rejected(self):
        from core.game import ChallengeEngine
        engine = ChallengeEngine()
        state = {"state": "jagrat", "active_thoughts": ["test"]}
        c = engine.generate_challenge(state)
        assert engine.submit_answer(c.challenge_id, "node-1", "answer 1")
        assert not engine.submit_answer(c.challenge_id, "node-1", "answer 2")

    def test_expired_challenge_rejected(self):
        from core.game import ChallengeEngine
        engine = ChallengeEngine()
        state = {"state": "jagrat", "active_thoughts": ["test"]}
        c = engine.generate_challenge(state)
        c.expires_at = time.time() - 1  # force expired
        assert not engine.submit_answer(c.challenge_id, "node-1", "too late")

    def test_answer_content_capped(self):
        from core.game import ChallengeEngine
        engine = ChallengeEngine()
        state = {"state": "jagrat", "active_thoughts": ["test"]}
        c = engine.generate_challenge(state)
        engine.submit_answer(c.challenge_id, "node-1", "x" * 5000)
        assert len(c.submissions[0].content) <= 2000

    def test_challenge_types_from_consciousness(self):
        from core.game import ChallengeEngine, ChallengeType
        engine = ChallengeEngine()
        # High arousal should produce SPEED or REASONING
        types_seen = set()
        for _ in range(20):
            ChallengeEngine._instance = None
            engine = ChallengeEngine()
            c = engine.generate_challenge({
                "state": "jagrat", "arousal": 0.9, "active_thoughts": ["x"]
            })
            if c:
                types_seen.add(c.challenge_type)
        assert ChallengeType.SPEED in types_seen or ChallengeType.REASONING in types_seen

    def test_summary(self):
        from core.game import ChallengeEngine
        engine = ChallengeEngine()
        state = {"state": "jagrat", "active_thoughts": ["test"]}
        engine.generate_challenge(state)
        s = engine.summary()
        assert len(s["active_challenges"]) == 1
        assert s["total_completed"] >= 0


class TestXP:
    def setup_method(self):
        from core.game import XPManager, GAME_DIR
        XPManager._instance = None
        for f in GAME_DIR.glob("*.json"):
            f.unlink(missing_ok=True)

    def test_new_node_starts_level_1(self):
        from core.game import XPManager
        mgr = XPManager()
        node = mgr.get_node("test-node")
        assert node.level == 1
        assert node.level_name == "Spark"
        assert node.xp == 0

    def test_xp_from_uptime(self):
        from core.game import XPManager, XP_PER_HOUR_ONLINE
        mgr = XPManager()
        mgr.grant_uptime_xp("node-1", 10)  # 10 hours
        node = mgr.get_node("node-1")
        assert node.xp == 10 * XP_PER_HOUR_ONLINE
        assert node.hours_online == 10

    def test_xp_from_jobs(self):
        from core.game import XPManager, XP_PER_JOB
        mgr = XPManager()
        mgr.grant_job_xp("node-1")
        node = mgr.get_node("node-1")
        assert node.xp == XP_PER_JOB
        assert node.jobs_completed == 1

    def test_xp_from_challenge(self):
        from core.game import XPManager, XP_PER_CHALLENGE_WIN, XP_PER_CHALLENGE_SUBMIT
        mgr = XPManager()
        mgr.grant_challenge_xp("node-1", won=True)
        node = mgr.get_node("node-1")
        assert node.xp == XP_PER_CHALLENGE_SUBMIT + XP_PER_CHALLENGE_WIN
        assert node.challenges_won == 1
        assert node.challenges_submitted == 1

    def test_level_up(self):
        from core.game import XPManager
        mgr = XPManager()
        node = mgr.get_node("node-1")
        node.add_xp(500)  # level 3 threshold
        assert node.level == 3
        assert node.level_name == "Flame"

    def test_level_perks(self):
        from core.game import XPManager
        mgr = XPManager()
        node = mgr.get_node("node-1")
        node.add_xp(5000)  # level 5
        assert "priority_queue" in node.perks
        assert "challenge_generate" in node.perks
        assert node.emission_multiplier == 1.2

    def test_xp_to_next(self):
        from core.game import XPManager
        mgr = XPManager()
        node = mgr.get_node("node-1")
        node.add_xp(50)  # level 1, need 100 for level 2
        assert node.xp_to_next == 50

    def test_leaderboard(self):
        from core.game import XPManager
        mgr = XPManager()
        mgr.get_node("node-a").add_xp(500)
        mgr.get_node("node-b").add_xp(1000)
        mgr.get_node("node-c").add_xp(100)
        board = mgr.leaderboard(3)
        assert board[0]["xp"] == 1000
        assert board[2]["xp"] == 100

    def test_emission_multiplier_scales(self):
        from core.game import XPManager
        mgr = XPManager()
        node = mgr.get_node("node-1")
        assert node.emission_multiplier == 1.0  # level 1
        node.add_xp(1500000)  # level 10
        assert node.emission_multiplier == 2.0  # level 10 = 2x


class TestAchievements:
    def setup_method(self):
        from core.game import AchievementTracker, XPManager, GAME_DIR
        AchievementTracker._instance = None
        XPManager._instance = None
        # Clear persisted state so tests don't leak
        for f in GAME_DIR.glob("*.json"):
            f.unlink(missing_ok=True)

    def test_first_job_achievement(self):
        from core.game import AchievementTracker, XPManager, AchievementType
        tracker = AchievementTracker()
        mgr = XPManager()
        node = mgr.get_node("node-1")
        node.jobs_completed = 1
        earned = tracker.check_and_award("node-1", node)
        types = [a.achievement_type for a in earned]
        assert AchievementType.FIRST_JOB in types

    def test_no_duplicate_achievement(self):
        from core.game import AchievementTracker, XPManager
        tracker = AchievementTracker()
        mgr = XPManager()
        node = mgr.get_node("node-1")
        node.jobs_completed = 1
        first = tracker.check_and_award("node-1", node)
        second = tracker.check_and_award("node-1", node)
        assert len(first) > 0
        assert len(second) == 0  # already earned

    def test_multiple_achievements_at_once(self):
        from core.game import AchievementTracker, XPManager
        tracker = AchievementTracker()
        mgr = XPManager()
        node = mgr.get_node("node-1")
        node.jobs_completed = 100
        node.challenges_won = 1
        node.hours_online = 200  # > 168 (7 days)
        earned = tracker.check_and_award("node-1", node)
        assert len(earned) >= 4  # first_job, 100_jobs, first_challenge, week_uptime

    def test_achievement_grants_xp(self):
        from core.game import AchievementTracker, XPManager
        tracker = AchievementTracker()
        mgr = XPManager()
        node = mgr.get_node("node-1")
        node.jobs_completed = 1
        xp_before = node.xp
        tracker.check_and_award("node-1", node)
        assert node.xp > xp_before  # got XP bonus

    def test_get_achievements(self):
        from core.game import AchievementTracker, XPManager
        tracker = AchievementTracker()
        mgr = XPManager()
        node = mgr.get_node("node-1")
        node.jobs_completed = 1
        tracker.check_and_award("node-1", node)
        achievements = tracker.get_achievements("node-1")
        assert len(achievements) > 0
        assert achievements[0]["name"] == "First Spark"

    def test_level_achievement(self):
        from core.game import AchievementTracker, XPManager, AchievementType
        tracker = AchievementTracker()
        mgr = XPManager()
        node = mgr.get_node("node-1")
        node.add_xp(5000)  # level 5
        earned = tracker.check_and_award("node-1", node)
        types = [a.achievement_type for a in earned]
        assert AchievementType.LEVEL_5 in types


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
