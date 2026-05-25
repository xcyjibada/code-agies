"""Tests for engine/runner.py — Runner, AgentCall, AgentResult."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from agies.engine.agents.base import AgentResponse, BaseAgent
from agies.engine.runner import AgentCall, AgentResult, Runner


# ---------------------------------------------------------------------------
# Stub agent (concrete subclass of BaseAgent)
# ---------------------------------------------------------------------------


class StubAgent(BaseAgent):
    """Agent that echoes params into output for deterministic testing."""

    agent_id = "stub"
    system_prompt = "stub"
    tools = []

    def __init__(self, agent_id: str = "stub") -> None:
        super().__init__()
        self.agent_id = agent_id

    def run(
        self,
        params: dict[str, Any],
        llm: Any = None,
        **llm_kwargs: Any,
    ) -> AgentResponse:
        return AgentResponse(
            content="stub ok",
            output=dict(params),
            total_tokens=0,
        )


class FailingAgent(BaseAgent):
    """Agent that always raises."""

    agent_id = "failing"
    system_prompt = "failing"
    tools = []

    def run(
        self,
        params: dict[str, Any],
        llm: Any = None,
        **llm_kwargs: Any,
    ) -> AgentResponse:
        raise RuntimeError("intentional failure")


class SlowAgent(BaseAgent):
    """Agent that records call order for concurrency verification."""

    agent_id = "slow"
    system_prompt = "slow"
    tools = []

    def __init__(self, tracker: list[str]) -> None:
        super().__init__()
        self.tracker = tracker

    def run(
        self,
        params: dict[str, Any],
        llm: Any = None,
        **llm_kwargs: Any,
    ) -> AgentResponse:
        self.tracker.append(self.agent_id)
        return AgentResponse(content=f"{self.agent_id} done", output=dict(params))


# ---------------------------------------------------------------------------
# Mock LLM (minimal, unused by stub agents)
# ---------------------------------------------------------------------------


@dataclass
class MockLLM:
    def chat_completion(self, messages, tools=None, **kwargs):
        from agies.engine.agents.base import ToolCall  # noqa: PLC0415
        return type("Resp", (), {"content": "mock", "tool_calls": None, "usage": None})()


# ---------------------------------------------------------------------------
# AgentCall / AgentResult data
# ---------------------------------------------------------------------------


class TestAgentCall:
    def test_defaults(self) -> None:
        c = AgentCall(agent_name="test", agent=StubAgent())
        assert c.params == {}

    def test_with_params(self) -> None:
        c = AgentCall(agent_name="t", agent=StubAgent(), params={"x": 1})
        assert c.params["x"] == 1


class TestAgentResult:
    def test_default_error_none(self) -> None:
        r = AgentResult(agent_name="t", params={}, response=AgentResponse())
        assert r.error is None

    def test_with_error(self) -> None:
        r = AgentResult(agent_name="t", params={}, response=AgentResponse(), error="fail")
        assert r.error == "fail"


# ---------------------------------------------------------------------------
# Runner — execute
# ---------------------------------------------------------------------------


class TestRunnerExecute:
    def test_empty_batch(self) -> None:
        runner = Runner(llm=MockLLM())
        results = runner.execute([])
        assert results == []

    def test_single_call(self) -> None:
        runner = Runner(llm=MockLLM())
        agent = StubAgent()
        batch = [AgentCall(agent_name="stub", agent=agent, params={"key": "val"})]
        results = runner.execute(batch)

        assert len(results) == 1
        assert results[0].agent_name == "stub"
        assert results[0].response.output == {"key": "val"}
        assert results[0].error is None

    def test_multiple_calls(self) -> None:
        runner = Runner(llm=MockLLM())
        a1 = StubAgent(agent_id="a1")
        a2 = StubAgent(agent_id="a2")
        batch = [
            AgentCall(agent_name="a1", agent=a1, params={"n": 1}),
            AgentCall(agent_name="a2", agent=a2, params={"n": 2}),
        ]
        results = runner.execute(batch)

        assert len(results) == 2
        assert results[0].response.output == {"n": 1}
        assert results[1].response.output == {"n": 2}

    def test_agent_error_isolation(self) -> None:
        """A failing agent should not prevent others from running."""
        runner = Runner(llm=MockLLM())
        ok = StubAgent(agent_id="ok")
        fail = FailingAgent()
        batch = [
            AgentCall(agent_name="ok", agent=ok, params={"x": 1}),
            AgentCall(agent_name="fail", agent=fail, params={}),
            AgentCall(agent_name="ok2", agent=ok, params={"x": 2}),
        ]
        results = runner.execute(batch)

        assert len(results) == 3
        # First agent succeeded
        assert results[0].error is None
        assert results[0].response.output == {"x": 1}
        # Second agent failed
        assert results[1].error is not None
        assert "intentional failure" in results[1].error
        # Third agent still ran
        assert results[2].error is None
        assert results[2].response.output == {"x": 2}

    def test_llm_passed_to_agent(self) -> None:
        """The same LLM instance should be passed to every agent call."""
        llm = MockLLM()
        runner = Runner(llm=llm)

        class Inspector(StubAgent):
            def run(self, params, _llm=None, **kwargs):
                assert _llm is llm
                return AgentResponse(content="ok")

        agent = Inspector()
        results = runner.execute([AgentCall(agent_name="i", agent=agent)])
        assert results[0].error is None
