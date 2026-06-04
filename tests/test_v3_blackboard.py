"""Tests for v3 BlackboardAggregator."""

from agies.engine.v3.aggregator.blackboard import BlackboardAggregator
from agies.engine.v3.aggregator.models import (
    IntentResult,
    KnowledgeEntry,
    AgentPhaseResult,
    CachedIntent,
)


class TestBlackboardAggregator:
    def test_empty_blackboard(self):
        """Fresh blackboard should have no knowledge."""
        bb = BlackboardAggregator()
        assert bb.get_prior_knowledge("test_func") == ""
        assert bb.intent_cache_stats()["cached_functions"] == 0

    def test_record_and_retrieve_knowledge(self):
        """Recorded knowledge should be retrievable."""
        bb = BlackboardAggregator()
        bb.record_knowledge("Helper.parse", "No input validation")
        prior = bb.get_prior_knowledge("Helper.parse")
        assert "PRIOR_KNOWLEDGE" in prior
        assert "No input validation" in prior

    def test_get_prior_empty_for_unrecorded(self):
        """Unrecorded functions return empty string."""
        bb = BlackboardAggregator()
        assert bb.get_prior_knowledge("nonexistent") == ""

    def test_cache_intent_and_retrieve(self):
        """Cached IntentResult should be retrievable."""
        bb = BlackboardAggregator()
        result = IntentResult(
            func_name="validatePath",
            file_path="src/util.py",
            intent="Checks if path is safe",
            key_logic="replace('..', '')",
        )
        bb.cache_intent(result)
        cached = bb.get_intent("validatePath", "src/util.py")
        assert cached is not None
        assert cached.intent == "Checks if path is safe"
        assert cached.key_logic == "replace('..', '')"

    def test_cache_miss_returns_none(self):
        """Getting non-existent intent returns None."""
        bb = BlackboardAggregator()
        assert bb.get_intent("missing", "none.py") is None

    def test_cache_hit_counter(self):
        """Cache hits should be counted."""
        bb = BlackboardAggregator()
        result = IntentResult(func_name="f", file_path="a.py")
        bb.cache_intent(result)

        bb.get_intent("f", "a.py")
        bb.get_intent("f", "a.py")
        stats = bb.intent_cache_stats()
        assert stats["total_cache_hits"] == 2

    def test_multiple_knowledge_entries_same_key(self):
        """Multiple entries for same key should all be retrievable."""
        bb = BlackboardAggregator()
        bb.record_knowledge("f1", "observation 1")
        bb.record_knowledge("f1", "observation 2")
        prior = bb.get_prior_knowledge("f1")
        assert "observation 1" in prior
        assert "observation 2" in prior

    def test_get_all_prior_knowledge(self):
        """get_all_prior_knowledge should combine multiple functions."""
        bb = BlackboardAggregator()
        bb.record_knowledge("f1", "info about f1")
        bb.record_knowledge("f2", "info about f2")
        combined = bb.get_all_prior_knowledge(["f1", "f2", "f3"])
        assert "info about f1" in combined
        assert "info about f2" in combined

    def test_record_phase_result(self):
        """Phase results should be storable and retrievable."""
        bb = BlackboardAggregator()
        result = AgentPhaseResult(
            path_id="rce-001",
            vuln_type="rce",
            score=0.85,
            is_vulnerable=True,
            confidence=8,
            analysis="Test analysis",
            contradictions=[{"func": "validatePath", "contradiction_type": "incomplete_sanitization"}],
        )
        bb.record_phase_result(result)
        results = bb.get_phase_results()
        assert len(results) == 1
        assert results[0].path_id == "rce-001"

    def test_summary_format(self):
        """Summary should contain expected fields."""
        bb = BlackboardAggregator()
        bb.record_knowledge("f1", "val")
        summary = bb.summary()
        assert "knowledge entries" in summary

    def test_merge_knowledge_from_agents(self):
        """Merge knowledge from phase results should work."""
        bb = BlackboardAggregator()
        results = [
            AgentPhaseResult(path_id="p1", vuln_type="rce", score=0.5, analysis="Analysis 1"),
            AgentPhaseResult(path_id="p2", vuln_type="lfi", score=0.3, analysis="Analysis 2"),
        ]
        bb.merge_knowledge_from_agents(results)
        assert bb.get_prior_knowledge("path:p1") != ""
        assert bb.get_prior_knowledge("path:p2") != ""
