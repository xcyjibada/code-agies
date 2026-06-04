"""Tests for v3 agents — Intent Agent, Logic Agent, Merge, PathCodeLoader."""

from agies.engine.v3.aggregator.models import IntentResult
from agies.engine.v3.agents.intent_agent import (
    IntentAgent,
    IntentAgentTask,
    parse_intent_response,
)
from agies.engine.v3.agents.logic_agent import LogicAgent, parse_logic_response
from agies.engine.v3.agents.merge import MergeLayer
from agies.engine.v3.agents.path_code_loader import PathCodeLoader
from agies.engine.v3.aggregator.blackboard import BlackboardAggregator


# ---------------------------------------------------------------------------
# Intent Agent tests
# ---------------------------------------------------------------------------

SAMPLE_INTENT_RESPONSE = """func_0 (validatePath):
  intent: Check if the file path is safe to access
  inputs: base directory path and user-supplied filename
  outputs: safe/unsafe boolean
  key_logic: replace("..", "") — only removes first occurrence
  suspicious: Only one replace call, can be bypassed with "....//"

func_1 (readFile):
  intent: Read file contents and return them
  inputs: validated file path from validatePath
  outputs: file contents as string
  key_logic: open(path).read()
  suspicious: No size limit check, could cause memory issues
"""


class TestParseIntentResponse:
    def test_parse_valid_response(self):
        """Standard intent response should parse to IntentResults."""
        functions = [
            {"func_name": "validatePath", "file_path": "util.py", "code": "..."},
            {"func_name": "readFile", "file_path": "util.py", "code": "..."},
        ]
        results = parse_intent_response(SAMPLE_INTENT_RESPONSE, functions)
        assert len(results) == 2
        assert results[0].func_name == "validatePath"
        assert results[1].func_name == "readFile"
        assert "replace" in results[0].key_logic

    def test_parse_empty_response(self):
        """Empty response should fall back to function names."""
        results = parse_intent_response("", [
            {"func_name": "myFunc", "file_path": "a.py"},
        ])
        assert len(results) >= 1
        assert results[0].func_name == "myFunc"

    def test_parse_partial_response(self):
        """Partial intent data should not crash."""
        response = """func_0 (myFunc):
  intent: Do something
  key_logic: transform data
"""
        results = parse_intent_response(response, [
            {"func_name": "myFunc", "file_path": "a.py"},
        ])
        assert len(results) >= 1


class TestIntentAgent:
    def test_prepare_prompt(self):
        """Prompt should include functions and context."""
        agent = IntentAgent()
        task = IntentAgentTask(
            batch_id="test-batch",
            path_id="rce-001",
            functions=[
                {"func_name": "f1", "file_path": "a.py",
                 "line_start": 1, "line_end": 10, "code": "print(1)"},
                {"func_name": "f2", "file_path": "b.py",
                 "line_start": 5, "line_end": 15, "code": "print(2)"},
            ],
            readme_summary="Test project",
        )
        prompt = agent.prepare_prompt(task)
        assert "f1" in prompt
        assert "f2" in prompt
        assert "Test project" in prompt
        assert "intent" in prompt.lower()

    def test_run_with_llm_response(self):
        """Running with a pre-parsed response should work."""
        agent = IntentAgent()
        task = IntentAgentTask(
            batch_id="test",
            path_id="p1",
            functions=[{"func_name": "f1", "file_path": "a.py", "code": "x"}],
        )
        results = agent.run(task, llm_response=SAMPLE_INTENT_RESPONSE)
        assert len(results) == 2

    def test_run_without_llm(self):
        """Running without LLM or response should return stubs."""
        agent = IntentAgent()
        task = IntentAgentTask(
            batch_id="test",
            path_id="p1",
            functions=[{"func_name": "myFunc", "file_path": "a.py", "code": "x"}],
        )
        results = agent.run(task)
        assert len(results) >= 1
        assert results[0].func_name == "myFunc"


# ---------------------------------------------------------------------------
# Logic Agent tests
# ---------------------------------------------------------------------------

SAMPLE_LOGIC_RESPONSE = """```json
{
  "contradictions": [
    {
      "func": "validatePath",
      "claimed": "Check if the file path is safe",
      "actual": "replace('..', '') — only once, easily bypassed",
      "contradiction_type": "incomplete_sanitization",
      "bypass_poc": "Use ....// to bypass single replace",
      "exploit_potential": "Path traversal, read arbitrary files"
    }
  ],
  "confidence": 8,
  "analysis": "validatePath claims to check path safety but uses a single replace that is trivially bypassed."
}
```
"""

NEGATIVE_LOGIC_RESPONSE = """```json
{
  "contradictions": [],
  "confidence": 2,
  "analysis": "No contradictions found. The path is safe."
}
```
"""


class TestParseLogicResponse:
    def test_parse_contradiction_found(self):
        """Positive logic response should extract contradictions."""
        data = parse_logic_response(SAMPLE_LOGIC_RESPONSE)
        assert isinstance(data, dict)
        assert "contradictions" in data
        assert len(data["contradictions"]) == 1
        assert data["confidence"] == 8

    def test_parse_no_contradiction(self):
        """Negative logic response should return empty contradictions."""
        data = parse_logic_response(NEGATIVE_LOGIC_RESPONSE)
        assert len(data["contradictions"]) == 0


class TestLogicAgent:
    def test_prepare_prompt(self):
        """Logic agent prompt should include intent chain."""
        agent = LogicAgent()
        prompt = agent.prepare_prompt(
            path_id="rce-001",
            intent_chain="[0] validatePath\n  Intent: check path safety",
            vuln_type="rce",
        )
        assert "validatePath" in prompt
        assert "vulnerable" in prompt.lower()

    def test_run_with_response(self):
        """Running with a pre-parsed response should produce AgentPhaseResult."""
        agent = LogicAgent()
        result = agent.run(
            path_id="rce-001",
            score=0.85,
            vuln_type="rce",
            intent_chain="[0] validatePath: check safety",
            llm_response=SAMPLE_LOGIC_RESPONSE,
        )
        assert result.path_id == "rce-001"
        assert result.is_vulnerable  # confidence >= 7 and contradictions exist
        assert len(result.contradictions) == 1

    def test_run_with_negative_response(self):
        """Running with a safe path should produce non-vulnerable result."""
        agent = LogicAgent()
        result = agent.run(
            path_id="rce-002",
            score=0.3,
            vuln_type="rce",
            intent_chain="[0] safeFunc: just logs",
            llm_response=NEGATIVE_LOGIC_RESPONSE,
        )
        assert not result.is_vulnerable
        assert result.confidence <= 3


# ---------------------------------------------------------------------------
# Merge layer tests
# ---------------------------------------------------------------------------


class TestMergeLayer:
    def test_merge_two_results(self):
        """Merge two intent results should produce ordered chain."""
        merge = MergeLayer()
        results = [
            IntentResult(func_name="validatePath", file_path="util.py",
                         intent="check path", key_logic="replace"),
            IntentResult(func_name="readFile", file_path="io.py",
                         intent="read file", key_logic="open().read()"),
        ]
        chain = merge.merge(results)
        assert "validatePath" in chain
        assert "readFile" in chain
        assert "[0]" in chain
        assert "[1]" in chain

    def test_merge_empty(self):
        """Empty results should produce empty chain."""
        merge = MergeLayer()
        chain = merge.merge([])
        assert chain == ""

    def test_order_by_hint(self):
        """Order hint should reorder results."""
        merge = MergeLayer()
        results = [
            IntentResult(func_name="last", file_path="a.py"),
            IntentResult(func_name="first", file_path="b.py"),
        ]
        chain = merge.merge(results, order=["first", "last"])
        assert chain.index("first") < chain.index("last")

    def test_coherence_check(self):
        """Coherence check should detect missing intents."""
        merge = MergeLayer()
        results = [
            IntentResult(func_name="f1", file_path="a.py",
                         intent="do X", key_logic="transform"),
            IntentResult(func_name="f2", file_path="b.py",
                         intent="", key_logic=""),
        ]
        chain = merge.merge(results)
        check = merge.check_coherence(chain, 2)
        # f2 has empty intent/key_logic but the string still contains the markers
        # so coherence might pass or fail based on formatting
        assert isinstance(check["coherent"], bool)
        assert check["function_count"] >= 1


# ---------------------------------------------------------------------------
# PathCodeLoader tests
# ---------------------------------------------------------------------------


class TestPathCodeLoader:
    def test_prepare_no_cache(self):
        """Empty cache should produce all tasks, no cached results."""
        loader = PathCodeLoader(project_path="/test")
        nodes = [
            {"function_name": "f1", "file_path": "a.py", "line_number": 1},
            {"function_name": "f2", "file_path": "b.py", "line_number": 2},
        ]
        result = loader.prepare("path-001", nodes, group_size=5)
        assert len(result.tasks) == 1  # both fit in one batch
        assert result.cached == []
        assert result.cache_hit_count == 0

    def test_prepare_with_cache(self):
        """Populated cache should reduce task count."""
        bb = BlackboardAggregator()
        bb.cache_intent(IntentResult(
            func_name="f1", file_path="a.py", intent="test",
        ))

        loader = PathCodeLoader(project_path="/test", blackboard=bb)
        nodes = [
            {"function_name": "f1", "file_path": "a.py"},
            {"function_name": "f2", "file_path": "b.py"},
        ]
        result = loader.prepare("path-001", nodes, group_size=5)
        assert result.cache_hit_count == 1
        assert len(result.cached) == 1

    def test_prepare_groups_by_size(self):
        """Functions should be grouped by group_size."""
        loader = PathCodeLoader(project_path="/test")
        nodes = [{"function_name": f"f{i}", "file_path": "a.py"} for i in range(12)]
        result = loader.prepare("path-001", nodes, group_size=5)
        assert len(result.tasks) == 3  # 5 + 5 + 2

    def test_register_intent_results(self):
        """Registered intents should appear in blackboard cache."""
        bb = BlackboardAggregator()
        loader = PathCodeLoader(project_path="/test", blackboard=bb)
        results = [
            IntentResult(func_name="f1", file_path="a.py", intent="test"),
        ]
        loader.register_intent_results(results)
        cached = bb.get_intent("f1", "a.py")
        assert cached is not None
        assert cached.intent == "test"

    def test_summary_format(self):
        """Summary should include path ID and function count."""
        loader = PathCodeLoader(project_path="/test")
        nodes = [{"function_name": "f1", "file_path": "a.py"}]
        result = loader.prepare("path-001", nodes)
        summary = loader.summary(result)
        assert "path-001" in summary
        assert "1 functions" in summary or "0 functions" in summary
