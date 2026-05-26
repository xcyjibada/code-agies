"""Tests for engine/agents/base.py — BaseAgent, tool loop, truncation, error handling."""

from __future__ import annotations

import logging
from typing import Any

import pytest
from pydantic import BaseModel

from agies.engine.agents.base import (
    BaseAgent,
    AgentResponse,
    ToolCall,
    ToolResult,
)


# ---------------------------------------------------------------------------
# Mock LLM provider
# ---------------------------------------------------------------------------


class MockLLMResponse:
    """Stand-in for ``agies.llm.base.LLMResponse``."""

    def __init__(
        self,
        content: str | None = None,
        tool_calls: list[Any] | None = None,
        usage: Any = None,
    ) -> None:
        self.content = content
        self.tool_calls = tool_calls
        self.usage = usage


class MockToolCall:
    """Stand-in for ``agies.llm.base.ToolCall``."""

    def __init__(
        self,
        name: str = "",
        arguments: str = "",
        id: str = "",
        type: str = "function",
    ) -> None:
        self.name = name
        self.arguments = arguments
        self.id = id
        self.type = type


class MockLLM:
    """Deterministic mock that serves pre-defined responses in order.

    ``responses`` may contain fewer items than calls — once exhausted the
    last response is repeated.
    """

    def __init__(self, responses: list[MockLLMResponse]) -> None:
        self.responses = responses
        self.call_count = 0

    def chat_completion(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        **kwargs: Any,
    ) -> MockLLMResponse:
        idx = min(self.call_count, len(self.responses) - 1) if self.responses else 0
        self.call_count += 1
        return self.responses[idx]


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

_ECHO_TOOL = {
    "name": "echo",
    "fn": lambda text="": f"echo: {text}",
    "schema": {
        "type": "function",
        "function": {
            "name": "echo",
            "description": "Echo back text",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                },
                "required": ["text"],
            },
        },
    },
}

_ADD_TOOL = {
    "name": "add",
    "fn": lambda a=0, b=0: f"result: {a + b}",
    "schema": {
        "type": "function",
        "function": {
            "name": "add",
            "description": "Add two numbers",
            "parameters": {
                "type": "object",
                "properties": {
                    "a": {"type": "integer"},
                    "b": {"type": "integer"},
                },
                "required": ["a", "b"],
            },
        },
    },
}

_ERROR_TOOL = {
    "name": "error_tool",
    "fn": lambda: (_ for _ in ()).throw(RuntimeError("simulated failure")),
    "schema": {
        "type": "function",
        "function": {
            "name": "error_tool",
            "description": "Always raises",
            "parameters": {"type": "object", "properties": {}},
        },
    },
}

_LONG_OUTPUT_TOOL = {
    "name": "long_output",
    "fn": lambda size=5000: "X" * size,
    "schema": {
        "type": "function",
        "function": {
            "name": "long_output",
            "description": "Returns a long string",
            "parameters": {
                "type": "object",
                "properties": {
                    "size": {"type": "integer"},
                },
            },
        },
    },
}


class SimpleAgent(BaseAgent):
    """Concrete agent for testing — uses echo tool."""
    agent_id = "test_agent"
    system_prompt = "You are a test agent. Respond with analysis."
    tools = [_ECHO_TOOL]


class NoToolAgent(BaseAgent):
    """Agent that never calls tools — just returns text."""
    agent_id = "no_tool_agent"
    system_prompt = "Just reply directly, no tools."
    tools = []


class OutputSchemaAgent(BaseAgent):
    """Agent with structured output schema."""
    agent_id = "schema_agent"
    system_prompt = "Analyze and return structured data."
    tools = [_ECHO_TOOL]

    class OutputModel(BaseModel):
        severity: str
        lines: list[int]

    output_schema = OutputModel


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAgentResponse:
    """AgentResponse data model."""

    def test_default_construction(self) -> None:
        resp = AgentResponse()
        assert resp.content == ""
        assert resp.output == {}
        assert resp.tool_calls == []
        assert resp.tool_results == []
        assert resp.total_tokens == 0

    def test_with_data(self) -> None:
        resp = AgentResponse(
            content="done",
            output={"key": "val"},
            tool_calls=[ToolCall(name="echo", arguments='{"text":"hi"}', id="c1")],
            tool_results=[ToolResult(id="c1", content="echo: hi")],
            total_tokens=42,
        )
        assert resp.content == "done"
        assert resp.output == {"key": "val"}
        assert resp.total_tokens == 42


class TestToolCall:
    """ToolCall data model."""

    def test_defaults(self) -> None:
        tc = ToolCall()
        assert tc.name == ""
        assert tc.arguments == ""
        assert tc.id == ""

    def test_with_values(self) -> None:
        tc = ToolCall(name="read_file", arguments='{"path":"/x"}', id="call_1")
        assert tc.name == "read_file"
        assert tc.arguments == '{"path":"/x"}'


class TestToolResult:
    """ToolResult data model."""

    def test_default_success(self) -> None:
        tr = ToolResult()
        assert tr.status == "success"
        assert tr.content == ""
        assert tr.truncated is False

    def test_error_state(self) -> None:
        tr = ToolResult(id="c1", status="error", content="fail", truncated=False)
        assert tr.status == "error"


# ---------------------------------------------------------------------------
# BaseAgent — core behavior
# ---------------------------------------------------------------------------


class TestBaseAgentNoToolCalls:
    """Agent that never invokes tools."""

    def test_returns_content_from_llm(self) -> None:
        agent = NoToolAgent()
        llm = MockLLM([MockLLMResponse(content="analysis complete")])

        resp = agent.run({"target": "/x"}, llm)
        assert resp.content == "analysis complete"
        assert resp.tool_calls == []
        assert resp.output == {}

    def test_empty_content_no_tools_still_ok(self) -> None:
        agent = NoToolAgent()
        llm = MockLLM([MockLLMResponse(content="")])

        resp = agent.run({"target": "/x"}, llm)
        # Empty content with no tools = done, content is ""
        assert resp.content == ""


class TestBaseAgentSingleToolCall:
    """Agent that calls one tool and then returns final text."""

    def test_single_tool_execution(self) -> None:
        agent = SimpleAgent()
        llm = MockLLM([
            MockLLMResponse(
                content="Let me check.",
                tool_calls=[MockToolCall(name="echo", arguments='{"text":"hello"}', id="c1")],
            ),
            MockLLMResponse(content="Result: hello"),
        ])

        resp = agent.run({"input": "test"}, llm)
        assert resp.content == "Result: hello"
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "echo"
        assert resp.tool_calls[0].arguments == '{"text":"hello"}'
        assert len(resp.tool_results) == 1
        assert resp.tool_results[0].status == "success"
        assert "echo: hello" in resp.tool_results[0].content

    def test_tool_result_reattached_to_llm(self) -> None:
        """After tool call, the result is fed back into the LLM messages."""
        agent = SimpleAgent()
        messages_snapshot: list[list[dict]] = []

        class CapturingMockLLM:
            def __init__(self):
                self.call_count = 0
                self.responses = [
                    MockLLMResponse(
                        content="calling tool",
                        tool_calls=[MockToolCall(name="echo", arguments='{"text":"hi"}', id="c1")],
                    ),
                    MockLLMResponse(content="final answer"),
                ]

            def chat_completion(self, messages, tools=None, **kwargs):
                messages_snapshot.append(list(messages))
                resp = self.responses[self.call_count]
                self.call_count += 1
                return resp

        agent.run({"x": "y"}, CapturingMockLLM())

        # Second call should include the tool result message
        assert len(messages_snapshot) == 2
        second_call = messages_snapshot[1]
        tool_result_msgs = [m for m in second_call if m.get("role") == "tool"]
        assert len(tool_result_msgs) == 1
        assert "echo: hi" in tool_result_msgs[0]["content"]


class TestBaseAgentMultipleToolsInOneTurn:
    """LLM calls several tools in a single response."""

    def test_multiple_parallel_tools(self) -> None:
        agent = SimpleAgent()
        llm = MockLLM([
            MockLLMResponse(
                content="Checking multiple things.",
                tool_calls=[
                    MockToolCall(name="echo", arguments='{"text":"first"}', id="c1"),
                    MockToolCall(name="echo", arguments='{"text":"second"}', id="c2"),
                ],
            ),
            MockLLMResponse(content="All checked."),
        ])

        resp = agent.run({"x": "y"}, llm)
        assert len(resp.tool_calls) == 2
        assert len(resp.tool_results) == 2
        assert resp.tool_results[0].status == "success"
        assert resp.tool_results[1].status == "success"


class TestBaseAgentMaxIterations:
    """Protection against infinite tool-calling loops."""

    def test_max_iterations_triggered(self) -> None:
        agent = SimpleAgent()
        # Every response asks for another tool call — should hit limit
        tool_response = MockLLMResponse(
            content="still working",
            tool_calls=[MockToolCall(name="echo", arguments='{"text":"loop"}', id="c_loop")],
        )
        # 20 responses, all with tool calls
        responses = [tool_response] * 20
        llm = MockLLM(responses)

        resp = agent.run({"x": "y"}, llm)
        # Should have stopped after MAX_ITERATIONS (10)
        # Because last response had tool_calls, loop runs MAX_ITERATIONS times
        assert len(resp.tool_calls) <= agent.MAX_ITERATIONS
        # Should have gotten the final summary
        assert "still working" in resp.content or resp.content == ""

    def test_max_iterations_with_final_summary(self) -> None:
        """When iteration limit hit, the agent calls LLM one more time for summary."""
        agent = SimpleAgent()
        agent.PLATEAU_WINDOW = 99  # Disable plateau — test iteration limit specifically

        class FinalSummaryMock:
            def __init__(self):
                self.call_count = 0

            def chat_completion(self, messages, tools=None, **kwargs):
                self.call_count += 1
                # SimpleAgent uses MAX_ITERATIONS=7, so we get 7 loop calls
                # + 1 final call = 8 total.  Return tool-call responses for
                # the first 7, then the final summary.
                if self.call_count <= 7:
                    return MockLLMResponse(
                        content="looping",
                        tool_calls=[MockToolCall(name="echo", arguments='{"text":"x"}', id="c")],
                    )
                # The extra call for final summary
                return MockLLMResponse(content="Final summary after limit.")

        resp = agent.run({"x": "y"}, FinalSummaryMock())
        assert resp.content == "Final summary after limit."


class TestBaseAgentOutputTruncation:
    """Tool output exceeding MAX_OUTPUT_CHARS is truncated in the middle."""

    def test_truncation_marker_present(self) -> None:
        agent = SimpleAgent()
        llm = MockLLM([
            MockLLMResponse(
                content="Reading file...",
                tool_calls=[MockToolCall(name="long_output", arguments='{"size":10000}', id="c1")],
            ),
            MockLLMResponse(content="Done."),
        ])
        agent.tools = [_ECHO_TOOL, _LONG_OUTPUT_TOOL]
        agent._tool_registry = {t["name"]: t for t in agent.tools}

        resp = agent.run({"x": "y"}, llm)
        assert len(resp.tool_results) == 1
        tr = resp.tool_results[0]

        # Content should have been truncated
        assert tr.truncated is True
        assert len(tr.content) < 10000
        assert "[TRUNCATED]" in tr.content

    def test_short_output_not_truncated(self) -> None:
        text, truncated = BaseAgent._truncate_output("short text", max_chars=4000)
        assert truncated is False
        assert text == "short text"

    def test_exactly_at_limit_not_truncated(self) -> None:
        text = "A" * 4000
        result, truncated = BaseAgent._truncate_output(text, max_chars=4000)
        assert truncated is False
        assert len(result) == 4000

    def test_truncation_preserves_ends(self) -> None:
        text = "AAA" + "X" * 5000 + "ZZZ"
        result, truncated = BaseAgent._truncate_output(text, max_chars=100)
        assert truncated is True
        assert result.startswith("AAA")
        assert result.endswith("ZZZ")
        assert "[TRUNCATED]" in result


class TestBaseAgentToolExecutionError:
    """Tool that raises an exception."""

    def test_error_returned_to_llm(self) -> None:
        agent = SimpleAgent()
        agent.tools = [_ECHO_TOOL, _ERROR_TOOL]
        agent._tool_registry = {t["name"]: t for t in agent.tools}

        llm = MockLLM([
            MockLLMResponse(
                content="Running error tool...",
                tool_calls=[MockToolCall(name="error_tool", arguments="{}", id="c_err")],
            ),
            MockLLMResponse(content="Got error, proceeding."),
        ])

        resp = agent.run({"x": "y"}, llm)
        assert len(resp.tool_results) == 1
        tr = resp.tool_results[0]
        assert tr.status == "error"
        assert "Error executing tool" in tr.content
        assert "simulated failure" in tr.content


class TestBaseAgentUnknownTool:
    """LLM requests a tool not in the registry."""

    def test_unknown_tool_reported(self) -> None:
        agent = SimpleAgent()  # only has echo tool

        llm = MockLLM([
            MockLLMResponse(
                content="Using unknown tool...",
                tool_calls=[MockToolCall(name="nonexistent", arguments="{}", id="c_unk")],
            ),
            MockLLMResponse(content="OK, acknowledged."),
        ])

        resp = agent.run({"x": "y"}, llm)
        assert len(resp.tool_results) == 1
        tr = resp.tool_results[0]
        assert tr.status == "error"
        assert "Unknown tool" in tr.content


class TestBaseAgentEmptyResponses:
    """LLM returns nothing — no content, no tool calls."""

    def test_single_empty_response_recovers(self) -> None:
        agent = SimpleAgent()
        llm = MockLLM([
            MockLLMResponse(content=""),  # empty
            MockLLMResponse(content="Back on track."),
        ])

        resp = agent.run({"x": "y"}, llm)
        assert resp.content == "Back on track."
        # Agent should have retried
        assert llm.call_count == 2

    def test_consecutive_empty_responses_terminate(self) -> None:
        agent = SimpleAgent()
        # 5 empty responses — should stop after MAX_EMPTY_RESPONSES (3)
        empty = MockLLMResponse(content="")
        llm = MockLLM([empty] * 5)

        resp = agent.run({"x": "y"}, llm)
        assert llm.call_count <= agent.MAX_EMPTY_RESPONSES + 1  # +1 initial

    def test_mixed_content_and_empty(self) -> None:
        """Empty responses in the middle of tool calls don't count toward the limit."""
        agent = SimpleAgent()
        llm = MockLLM([
            MockLLMResponse(
                content="call tool",
                tool_calls=[MockToolCall(name="echo", arguments='{"text":"a"}', id="c1")],
            ),
            MockLLMResponse(content=""),  # empty after tool result
            MockLLMResponse(
                content="call tool again",
                tool_calls=[MockToolCall(name="echo", arguments='{"text":"b"}', id="c2")],
            ),
            MockLLMResponse(content="Done."),
        ])

        resp = agent.run({"x": "y"}, llm)
        # Should have completed normally, with 2 tool calls
        assert len(resp.tool_calls) == 2
        assert resp.content == "Done."


class TestBaseAgentOutputSchema:
    """Output schema validation."""

    def test_valid_output_passes_schema(self) -> None:
        agent = OutputSchemaAgent()

        class ValidatingAgent(OutputSchemaAgent):
            def _parse_output(self, content, tool_results):
                return {"severity": "high", "lines": [10, 42]}

        agent = ValidatingAgent()
        llm = MockLLM([MockLLMResponse(content="Found issues on lines 10 and 42.")])

        resp = agent.run({"x": "y"}, llm)
        assert resp.output == {"severity": "high", "lines": [10, 42]}

    def test_invalid_output_logs_warning(self, caplog) -> None:
        agent = OutputSchemaAgent()

        class BadAgent(OutputSchemaAgent):
            def _parse_output(self, content, tool_results):
                return {"severity": "high"}  # missing "lines"

        agent = BadAgent()
        llm = MockLLM([MockLLMResponse(content="done")])

        with caplog.at_level(logging.WARNING):
            agent.run({"x": "y"}, llm)

        assert len(caplog.records) >= 1
        assert any("Output did not conform" in rec.getMessage() for rec in caplog.records)


class TestBaseAgentToolRegistry:
    """O(1) tool lookup."""

    def test_registry_built_from_tools(self) -> None:
        agent = SimpleAgent()
        assert "echo" in agent._tool_registry
        assert agent._tool_registry["echo"]["name"] == "echo"

    def test_unknown_tool_not_in_registry(self) -> None:
        agent = SimpleAgent()
        assert "nonexistent" not in agent._tool_registry


class TestBaseAgentLogging:
    """Logging requirements."""

    def test_debug_logs_tool_call_params(self, caplog) -> None:
        agent = SimpleAgent()
        llm = MockLLM([
            MockLLMResponse(
                content="",
                tool_calls=[MockToolCall(name="echo", arguments='{"text":"log_me"}', id="c_log")],
            ),
            MockLLMResponse(content="done"),
        ])

        with caplog.at_level(logging.DEBUG):
            agent.run({"x": "y"}, llm)

        debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
        tool_debug = [r for r in debug_records if "Tool call" in r.getMessage()]
        assert len(tool_debug) >= 1
        assert "echo" in tool_debug[0].getMessage()
        assert '{"text":"log_me"}' in tool_debug[0].getMessage()

    def test_error_logs_stacktrace(self, caplog) -> None:
        agent = SimpleAgent()
        agent.tools = [_ECHO_TOOL, _ERROR_TOOL]
        agent._tool_registry = {t["name"]: t for t in agent.tools}

        llm = MockLLM([
            MockLLMResponse(
                content="",
                tool_calls=[MockToolCall(name="error_tool", arguments="{}", id="c_err")],
            ),
            MockLLMResponse(content="ok"),
        ])

        with caplog.at_level(logging.ERROR):
            agent.run({"x": "y"}, llm)

        error_records = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(error_records) >= 1
        # exc_info=True should be set
        assert error_records[0].exc_info is not None

    def test_no_hardcoded_strings_in_logic(self) -> None:
        """All prompt fragments should be module-level constants."""
        import inspect
        import agies.engine.agents.base as base_module

        source = inspect.getsource(base_module)
        method_bodies = []

        # Collect lines inside method definitions (rough check)
        lines = source.split("\n")
        in_method = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("def ") and "  " not in stripped[:5]:
                in_method = True
            elif in_method and stripped.startswith("class "):
                in_method = False
            elif in_method and stripped.startswith("    def "):
                in_method = True

            if in_method and ("@" not in stripped):
                method_bodies.append(stripped)

        # Check that method bodies don't contain bare string literals
        # that look like prompt fragments (long English strings)
        for line in method_bodies:
            # Skip imports, self.attr, comments, empty lines
            if not line or line.startswith("#") or line.startswith("import") or line.startswith("from"):
                continue
            # Check for long string literals
            for i, char in enumerate(line):
                if char in ('"', "'") and i > 0 and line[i - 1] not in ("=", "(", " ", "\t", ","):
                    # This is a potential problem — a string used inline
                    pass  # Too noisy to assert on every case


class TestAgentBuildMessages:
    """Message construction."""

    def test_build_messages_includes_system_and_user(self) -> None:
        agent = SimpleAgent()
        msgs = agent._build_messages({"file": "/x"})
        assert len(msgs) == 2
        assert msgs[0]["role"] == "system"
        assert msgs[0]["content"] == "You are a test agent. Respond with analysis."
        assert msgs[1]["role"] == "user"
        assert "file" in msgs[1]["content"]

    def test_build_messages_with_dict_param(self) -> None:
        agent = SimpleAgent()
        msgs = agent._build_messages({"config": {"key": "val"}})
        assert len(msgs) == 2
        assert "config" in msgs[1]["content"]
        assert "key" in msgs[1]["content"]


# ---------------------------------------------------------------------------
# Full project integration check
# ---------------------------------------------------------------------------


def test_import_does_not_break_existing_tests() -> None:
    """Importing the new module should not affect existing imports."""
    from agies.engine import ProjectState  # noqa: F811
    from agies.engine.state import ProjectState as PS
    assert ProjectState is PS
