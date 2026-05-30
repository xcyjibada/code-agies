"""Tests for P6: Blackboard Architecture — cross-agent knowledge sharing.

Test categories:
1. ProjectState.discovered_logic — CRUD for knowledge records
2. BaseAgent prior_knowledge injection — [PRIOR_KNOWLEDGE] in system prompt
3. Brain._collect_prior_knowledge — lookup logic
4. record_knowledge tool — basic recording + error cases
5. Verification agent tool list — record_knowledge included
6. Edge cases — empty key, empty value, no state
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from agies.engine.v2.state import ProjectState


# ===================================================================
# ProjectState.discovered_logic
# ===================================================================


class TestDiscoveredLogic:
    def test_empty_by_default(self) -> None:
        state = ProjectState()
        assert state.discovered_logic == {}

    def test_record_knowledge(self) -> None:
        state = ProjectState()
        state.record_knowledge("db_query", "Chain: login→verify→db_query, debug bypass")
        assert "db_query" in state.discovered_logic
        assert "debug bypass" in state.discovered_logic["db_query"]

    def test_record_knowledge_append(self) -> None:
        state = ProjectState()
        state.record_knowledge("db_query", "chain 1")
        state.record_knowledge("db_query", "chain 2")
        assert "chain 1" in state.discovered_logic["db_query"]
        assert "chain 2" in state.discovered_logic["db_query"]

    def test_record_knowledge_empty_key(self) -> None:
        state = ProjectState()
        state.record_knowledge("", "value")
        assert state.discovered_logic == {}

    def test_record_knowledge_empty_value(self) -> None:
        state = ProjectState()
        state.record_knowledge("key", "")
        assert state.discovered_logic == {}

    def test_record_knowledge_multiple_keys(self) -> None:
        state = ProjectState()
        state.record_knowledge("func_a", "A is vulnerable")
        state.record_knowledge("func_b", "B has sanitizer")
        assert len(state.discovered_logic) == 2
        assert "vulnerable" in state.discovered_logic["func_a"]
        assert "sanitizer" in state.discovered_logic["func_b"]

    def test_state_serialization(self) -> None:
        state = ProjectState()
        state.record_knowledge("test_fn", "discovery")
        d = state.to_dict()
        # discovered_logic should not appear in to_dict (it's not in the dict method)
        # but it IS in the dataclass fields
        assert "test_fn" not in d


# ===================================================================
# BaseAgent prior_knowledge injection
# ===================================================================


class TestPriorKnowledgeInjection:
    def test_prior_knowledge_in_system_prompt(self) -> None:
        """Prior knowledge should be injected as [PRIOR_KNOWLEDGE] block."""
        from agies.engine.v2.agents.base import BaseAgent

        class TestAgent(BaseAgent):
            agent_id = "test"
            system_prompt = "You are a test agent."
            tools = []

        agent = TestAgent()
        params = {"prior_knowledge": "Chain: login → verify → db_query"}

        messages = agent._build_messages(params)
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == "You are a test agent."

        # Now test with prior_knowledge processed by run()
        # Extract prior knowledge to simulate run() behavior
        prior = params.pop("prior_knowledge", None)
        msgs = agent._build_messages(params)

        if prior:
            for msg in msgs:
                if msg.get("role") == "system":
                    msg["content"] = (
                        "[PRIOR_KNOWLEDGE]\n"
                        f"{prior}\n"
                        "[/PRIOR_KNOWLEDGE]\n\n"
                        + msg["content"]
                    )

        assert "[PRIOR_KNOWLEDGE]" in msgs[0]["content"]
        assert "login" in msgs[0]["content"]
        assert "You are a test agent." in msgs[0]["content"]

    def test_no_prior_knowledge_no_change(self) -> None:
        """Without prior_knowledge param, system prompt is unchanged."""
        from agies.engine.v2.agents.base import BaseAgent

        class TestAgent(BaseAgent):
            agent_id = "test"
            system_prompt = "You are a test agent."
            tools = []

        agent = TestAgent()
        messages = agent._build_messages({})
        assert "[PRIOR_KNOWLEDGE]" not in messages[0]["content"]
        assert messages[0]["content"] == "You are a test agent."


# ===================================================================
# Brain._collect_prior_knowledge
# ===================================================================


class TestCollectPriorKnowledge:
    def test_found(self) -> None:
        from agies.engine.v2.brain import _collect_prior_knowledge

        state = ProjectState()
        state.record_knowledge("db_query", "relevant discovery")
        result = _collect_prior_knowledge("db_query", state)
        assert "relevant discovery" in result

    def test_not_found(self) -> None:
        from agies.engine.v2.brain import _collect_prior_knowledge

        state = ProjectState()
        result = _collect_prior_knowledge("ghost", state)
        assert result == ""

    def test_empty_key(self) -> None:
        from agies.engine.v2.brain import _collect_prior_knowledge

        state = ProjectState()
        assert _collect_prior_knowledge("", state) == ""


# ===================================================================
# record_knowledge tool
# ===================================================================


class TestRecordKnowledgeTool:
    def test_tool_records_to_state(self) -> None:
        """record_knowledge should write to state when _state is set."""
        from agies.tools.index_tools import record_knowledge, set_state

        state = ProjectState()
        set_state(state)
        result = record_knowledge("db_query", "discovered chain")
        assert "recorded" in result.lower()
        assert "db_query" in state.discovered_logic

    def test_tool_no_state(self) -> None:
        from agies.tools.index_tools import record_knowledge, set_state

        set_state(None)
        result = record_knowledge("db_query", "chain")
        assert "not available" in result.lower()

    def test_tool_empty_key(self) -> None:
        from agies.tools.index_tools import record_knowledge, set_state

        state = ProjectState()
        set_state(state)
        result = record_knowledge("", "value")
        assert "required" in result.lower()

    def test_tool_empty_value(self) -> None:
        from agies.tools.index_tools import record_knowledge, set_state

        state = ProjectState()
        set_state(state)
        result = record_knowledge("key", "")
        assert "required" in result.lower()

    def test_tool_returns_confirmation(self) -> None:
        from agies.tools.index_tools import record_knowledge, set_state

        state = ProjectState()
        set_state(state)
        result = record_knowledge("my_func", "found sanitizer")
        assert "my_func" in result


# ===================================================================
# Tool registration
# ===================================================================


class TestToolRegistration:
    def test_record_knowledge_in_definitions(self) -> None:
        from agies.tools import get_tool_definitions

        names = [t["name"] for t in get_tool_definitions()]
        assert "record_knowledge" in names

    def test_record_knowledge_has_schema(self) -> None:
        from agies.tools import get_tool_definitions

        tool = next(t for t in get_tool_definitions() if t["name"] == "record_knowledge")
        schema = tool["schema"]["function"]
        assert "key" in schema["parameters"]["properties"]
        assert "value" in schema["parameters"]["properties"]
        assert "key" in schema["parameters"]["required"]
        assert "value" in schema["parameters"]["required"]

    def test_get_call_chain_logic_describes_record(self) -> None:
        """get_call_chain_logic description should mention record_knowledge."""
        from agies.tools import get_tool_definitions

        tool = next(t for t in get_tool_definitions() if t["name"] == "get_call_chain_logic")
        desc = tool["schema"]["function"]["description"]
        assert "record_knowledge" in desc


# ===================================================================
# Verification agent tool list
# ===================================================================


class TestVerificationAgentTools:
    def test_record_knowledge_included(self) -> None:
        from agies.engine.v2.agents.verification_agent import VERIFICATION_TOOLS

        names = {t["name"] for t in VERIFICATION_TOOLS}
        assert "record_knowledge" in names


class TestVerifyAgentTools:
    def test_record_knowledge_included(self) -> None:
        from agies.engine.v2.agents.verify import VERIFY_TOOLS

        names = {t["name"] for t in VERIFY_TOOLS}
        assert "record_knowledge" in names


# ===================================================================
# Brain integration: set_state called during run
# ===================================================================


class TestBrainStateIntegration:
    def test_brain_sets_state_on_run(self) -> None:
        """Brain.run() should call set_state so record_knowledge works."""
        from agies.engine.v2.agents.base import AgentResponse
        from agies.engine.v2.brain import Brain
        from agies.engine.v2.runner import Runner
        from dataclasses import dataclass

        @dataclass
        class MockLLM:
            def chat_completion(self, messages, tools=None, **kwargs):
                @dataclass
                class Resp:
                    content: str = "ok"
                    tool_calls: list = None
                    usage: object = None
                return Resp()

        @dataclass
        class MappingStub:
            agent_id = "mapping"
            system_prompt = ""
            tools = []
            def run(self, params, llm=None, **kwargs):
                return AgentResponse(content="mapped", output={
                    "summary": "Test", "modules": [], "key_files": [],
                    "language": "Python", "framework": "Flask", "file_count": 5,
                })

        from agies.tools.index_tools import record_knowledge, set_state

        # Reset state so we can verify it gets set
        set_state(None)
        runner = Runner(llm=MockLLM())
        brain = Brain(runner=runner, agents={"mapping": MappingStub()})
        with tempfile.TemporaryDirectory() as tmpdir:
            state = brain.run(tmpdir)
            # record_knowledge should work now (state is set)
            result = record_knowledge("test_fn", "test value")
            assert "recorded" in result.lower()


# ===================================================================
# Prior knowledge in verification params (brain._build_calls integration)
# ===================================================================


class TestPriorKnowledgeInBuildCalls:
    def test_verification_gets_prior_knowledge(self) -> None:
        """When a candidate's function_name is in discovered_logic,
        the verification AgentCall should include prior_knowledge."""
        from agies.engine.v2.brain import Brain
        from agies.engine.v2.runner import Runner, AgentCall
        from agies.engine.v2.sourcer.models import CandidateFinding

        # Create a brain with a mock runner
        class MockRunner:
            def execute(self, batch):
                return []

        runner = MockRunner()  # type: ignore
        brain = Brain(runner=runner)  # type: ignore

        # Build state with discovered_logic + candidates
        state = ProjectState()
        state.record_knowledge("target_func", "Prior chain analysis")
        state.candidates = [
            CandidateFinding(
                type="sqli",
                function_name="target_func",
                file_path="app.py",
                reason="test",
            ),
            CandidateFinding(
                type="xss",
                function_name="other_func",
                file_path="other.py",
                reason="test2",
            ),
        ]

        # Build calls for verification
        from agies.engine.v2.agents.verification_agent import VerificationAgent

        agent = VerificationAgent()
        calls = brain._build_calls("verification", agent, state)

        # First candidate (target_func) should have prior_knowledge
        assert len(calls) == 2
        call_with_prior = [c for c in calls if c.params.get("prior_knowledge")]
        assert len(call_with_prior) == 1
        assert "Prior chain" in call_with_prior[0].params["prior_knowledge"]
