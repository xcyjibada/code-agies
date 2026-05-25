"""Tests for engine/agents/mapping.py — MappingAgent."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

from agies.engine.agents.base import AgentResponse, ToolResult
from agies.engine.agents.mapping import (
    MAPPING_TOOLS,
    MappingAgent,
    MappingOutput,
    ModuleEntry,
    KeyFileEntry,
    TrustAssumption,
)
from agies.engine.brain import Brain
from agies.engine.runner import Runner
from agies.engine.state import ProjectState


# ---------------------------------------------------------------------------
# _parse_output
# ---------------------------------------------------------------------------


class TestParseOutput:
    """MappingAgent._parse output — JSON extraction from LLM text."""

    def make_agent(self) -> MappingAgent:
        return MappingAgent()

    def test_extracts_json_from_code_block(self) -> None:
        agent = self.make_agent()
        content = """I found a Flask app.

```json
{
  "summary": "A Flask web app",
  "language": "Python",
  "framework": "Flask",
  "file_count": 15,
  "modules": [{"name": "app", "path": "/app", "description": "main"}],
  "key_files": [{"path": "app.py", "role": "entry"}]
}
```"""
        result = agent._parse_output(content, [])
        assert result["summary"] == "A Flask web app"
        assert result["language"] == "Python"
        assert result["framework"] == "Flask"
        assert result["file_count"] == 15
        assert len(result["modules"]) == 1
        assert len(result["key_files"]) == 1

    def test_extracts_json_without_fence(self) -> None:
        agent = self.make_agent()
        content = 'Here is the map:\n{"summary": "test", "language": "Go"}\n'
        result = agent._parse_output(content, [])
        assert result["summary"] == "test"
        assert result["language"] == "Go"

    def test_extracts_json_with_language_tag_only(self) -> None:
        agent = self.make_agent()
        content = "```json\n{\"summary\": \"s\", \"language\": \"Rust\"}\n```"
        result = agent._parse_output(content, [])
        assert result["language"] == "Rust"

    def test_empty_content_returns_empty_dict(self) -> None:
        agent = self.make_agent()
        assert agent._parse_output("", []) == {}

    def test_no_json_in_content_returns_empty_dict(self) -> None:
        agent = self.make_agent()
        assert agent._parse_output("Just some text without JSON", []) == {}

    def test_normalises_keys(self) -> None:
        agent = self.make_agent()
        content = """```json
{
  "summary": "s",
  "language": "Python",
  "framework": "Django",
  "file_count": 10,
  "modules": [],
  "key_files": [],
  "unknown_key": "should be dropped"
}
```"""
        result = agent._parse_output(content, [])
        assert "unknown_key" not in result
        assert result["summary"] == "s"

    def test_fills_defaults_for_missing_fields(self) -> None:
        agent = self.make_agent()
        content = '{"summary": "s", "language": "Py"}'
        result = agent._parse_output(content, [])
        assert result["file_count"] == 0
        assert result["modules"] == []
        assert result["key_files"] == []
        assert result["framework"] == ""
        assert result["trust_assumptions"] == []

    def test_parses_trust_assumptions(self) -> None:
        agent = self.make_agent()
        content = """```json
{
  "summary": "E-commerce app",
  "language": "Java",
  "trust_assumptions": [
    {"assumption": "Price comes from client", "risk_category": "input_tampering"},
    {"assumption": "Coupon count in DB without lock", "risk_category": "race_condition"}
  ]
}
```"""
        result = agent._parse_output(content, [])
        assert len(result["trust_assumptions"]) == 2
        assert result["trust_assumptions"][0]["risk_category"] == "input_tampering"
        assert "race_condition" in result["trust_assumptions"][1]["risk_category"]


class TestExtractJson:
    """MappingAgent._extract_json."""

    def test_code_block(self) -> None:
        text = "Text\n```json\n{\"a\": 1}\n```\ntext"
        assert MappingAgent._extract_json(text) == '{"a": 1}'

    def test_code_block_no_lang(self) -> None:
        text = "```\n{\"a\": 1}\n```"
        assert MappingAgent._extract_json(text) == '{"a": 1}'

    def test_bare_braces(self) -> None:
        text = "prefix {\"a\": {\"b\": 2}} suffix"
        assert MappingAgent._extract_json(text) == '{"a": {"b": 2}}'

    def test_no_json(self) -> None:
        assert MappingAgent._extract_json("just text") is None

    def test_only_opening_brace(self) -> None:
        """Unmatched opening brace should return None."""
        assert MappingAgent._extract_json("{ no closing") is None


# ---------------------------------------------------------------------------
# _normalise
# ---------------------------------------------------------------------------


class TestNormalise:
    def test_keeps_allowed_keys(self) -> None:
        result = MappingAgent._normalise({
            "summary": "s",
            "language": "Py",
            "framework": "Flask",
            "file_count": 5,
            "modules": [],
            "key_files": [],
            "trust_assumptions": [],
        })
        assert set(result.keys()) == {
            "summary", "language", "framework",
            "file_count", "modules", "key_files",
            "trust_assumptions",
        }

    def test_drops_unexpected_keys(self) -> None:
        result = MappingAgent._normalise({"summary": "s", "language": "Py", "extra": "bad"})
        assert "extra" not in result


# ---------------------------------------------------------------------------
# MappingOutput schema
# ---------------------------------------------------------------------------


class TestMappingOutput:
    def test_valid(self) -> None:
        m = MappingOutput(
            summary="A web app",
            language="Python",
            framework="FastAPI",
            file_count=20,
            modules=[ModuleEntry(name="api", path="api/", description="API layer")],
            key_files=[KeyFileEntry(path="main.py", role="entry")],
        )
        assert m.language == "Python"

    def test_invalid_missing_required(self) -> None:
        with pytest.raises(ValueError):
            MappingOutput(language="Py")  # missing summary

    def test_defaults(self) -> None:
        m = MappingOutput(summary="x", language="x")
        assert m.file_count == 0
        assert m.modules == []
        assert m.key_files == []
        assert m.framework == ""
        assert m.trust_assumptions == []


class TestTrustAssumption:
    def test_valid(self) -> None:
        ta = TrustAssumption(assumption="Price from client", risk_category="input_tampering")
        assert ta.risk_category == "input_tampering"

    def test_default_risk_category(self) -> None:
        ta = TrustAssumption(assumption="No auth check")
        assert ta.risk_category == ""


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


class TestMappingTools:
    def test_has_expected_tools(self) -> None:
        names = {t["name"] for t in MAPPING_TOOLS}
        assert "list_directory" in names
        assert "read_file" in names
        assert "grep_search" in names

    def test_tool_count(self) -> None:
        assert len(MAPPING_TOOLS) == 3


# ---------------------------------------------------------------------------
# Agent instantiation
# ---------------------------------------------------------------------------


class TestAgentCreation:
    def test_defaults(self) -> None:
        agent = MappingAgent()
        assert agent.agent_id == "mapping"
        assert len(agent.tools) == 3
        assert agent.output_schema is MappingOutput

    def test_registry_has_all_tools(self) -> None:
        agent = MappingAgent()
        assert "list_directory" in agent._tool_registry
        assert "read_file" in agent._tool_registry
        assert "grep_search" in agent._tool_registry


# ---------------------------------------------------------------------------
# Mock LLM helpers for integration tests
# ---------------------------------------------------------------------------


@dataclass
class MockToolCall:
    name: str = ""
    arguments: str = ""
    id: str = ""


@dataclass
class MockLLMResponse:
    content: str | None = None
    tool_calls: list | None = None
    usage: Any = None


class MockLLMStepwise:
    """Mock that walks through a scripted conversation."""

    def __init__(self, responses: list[MockLLMResponse]) -> None:
        self.responses = responses
        self.call_count = 0
        self.all_messages: list[list[dict]] = []

    def chat_completion(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        **kwargs: Any,
    ) -> MockLLMResponse:
        self.all_messages.append(list(messages))
        idx = min(self.call_count, len(self.responses) - 1)
        self.call_count += 1
        return self.responses[idx]


# ---------------------------------------------------------------------------
# Integration: agent with mock LLM
# ---------------------------------------------------------------------------


class TestMappingAgentRun:
    """End-to-end agent.run() with scripted LLM responses."""

    VALID_MAPPING_JSON = json.dumps({
        "summary": "A sample project",
        "language": "Python",
        "framework": "Flask",
        "file_count": 10,
        "modules": [
            {"name": "app", "path": "/app", "description": "application logic"},
        ],
        "key_files": [
            {"path": "app.py", "role": "entry point"},
            {"path": "requirements.txt", "role": "dependencies"},
        ],
        "trust_assumptions": [
            {"assumption": "Price from client", "risk_category": "input_tampering"},
        ],
    })

    def test_llm_explores_then_outputs_json(self) -> None:
        """Agent: LLM calls list_directory, reads a file, then produces JSON."""
        llm = MockLLMStepwise([
            # Turn 1: explore root
            MockLLMResponse(
                content="Let me explore the project structure.",
                tool_calls=[
                    MockToolCall(name="list_directory", arguments='{"path": "/project"}', id="c1"),
                ],
            ),
            # Turn 2: tool result for list_directory, now read config
            MockLLMResponse(
                content="I see a Python project layout.",
                tool_calls=[
                    MockToolCall(name="read_file", arguments='{"path": "/project/requirements.txt"}', id="c2"),
                ],
            ),
            # Turn 3: produce final JSON
            MockLLMResponse(
                content=f"Final analysis:\n```json\n{self.VALID_MAPPING_JSON}\n```",
            ),
        ])
        agent = MappingAgent()
        response = agent.run({"project_path": "/project"}, llm)

        assert response.output["summary"] == "A sample project"
        assert response.output["language"] == "Python"
        assert response.output["framework"] == "Flask"
        assert len(response.output["modules"]) == 1
        assert len(response.output["key_files"]) == 2
        assert len(response.tool_calls) == 2
        assert len(response.tool_results) == 2

    def test_llm_directly_outputs_json_no_tools(self) -> None:
        """Agent gets final answer immediately, no tool calls needed."""
        llm = MockLLMStepwise([
            MockLLMResponse(
                content=f"```json\n{self.VALID_MAPPING_JSON}\n```",
            ),
        ])
        agent = MappingAgent()
        response = agent.run({"project_path": "/project"}, llm)

        assert response.output["language"] == "Python"
        assert len(response.tool_calls) == 0
        assert response.content == f"```json\n{self.VALID_MAPPING_JSON}\n```"

    def test_llm_produces_invalid_json(self) -> None:
        """Agent gracefully handles invalid JSON from LLM."""
        llm = MockLLMStepwise([
            MockLLMResponse(content="I'm not sure what this project is."),
        ])
        agent = MappingAgent()
        response = agent.run({}, llm)

        # No valid JSON found → empty output
        assert response.output == {}

    def test_exploration_with_grep(self) -> None:
        """Agent uses grep to find patterns."""
        llm = MockLLMStepwise([
            MockLLMResponse(
                content="Searching for entry points.",
                tool_calls=[
                    MockToolCall(
                        name="grep_search",
                        arguments='{"pattern": "@app.route", "path": "/project"}',
                        id="c1",
                    ),
                ],
            ),
            MockLLMResponse(
                content=f"```json\n{self.VALID_MAPPING_JSON}\n```",
            ),
        ])
        agent = MappingAgent()
        response = agent.run({"project_path": "/project"}, llm)

        assert response.output["language"] == "Python"
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].name == "grep_search"


# ---------------------------------------------------------------------------
# Brain integration — MappingAgent in the real pipeline
# ---------------------------------------------------------------------------


@dataclass
class MockLLMBrain:
    """Minimal LLM for brain integration — mapping agent uses tools then outputs JSON."""

    VALID_MAPPING = json.dumps({
        "summary": "Integrated test project",
        "language": "Python",
        "framework": "Flask",
        "file_count": 42,
        "modules": [{"name": "core", "path": "core/", "description": "core logic"}],
        "key_files": [{"path": "run.py", "role": "entry point"}],
        "trust_assumptions": [
            {"assumption": "Price from client", "risk_category": "input_tampering"},
        ],
    })

    def __init__(self) -> None:
        self.call_count = 0

    def chat_completion(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        **kwargs: Any,
    ) -> MockLLMResponse:
        self.call_count += 1
        if self.call_count == 1:
            # First call: explore
            return MockLLMResponse(
                content="Exploring...",
                tool_calls=[MockToolCall(
                    name="list_directory",
                    arguments='{"path": "/project"}',
                    id="c1",
                )],
            )
        # Second call: final JSON
        return MockLLMResponse(
            content=f"```json\n{self.VALID_MAPPING}\n```",
        )


class TestBrainWithMapping:
    """MappingAgent wired into the real Brain."""

    def test_brain_invokes_mapping_agent(self) -> None:
        llm = MockLLMBrain()
        runner = Runner(llm=llm)
        agent = MappingAgent()
        brain = Brain(runner=runner, agents={"mapping": agent})

        state = brain.run("/project")

        assert "mapping" in state.completed_agents
        assert state.project_summary == "Integrated test project"
        assert state.language == "Python"
        assert state.framework == "Flask"
        assert state.file_count == 42
        assert len(state.modules) == 1
        assert len(state.key_files) == 1
        assert len(state.trust_assumptions) == 1
        assert state.trust_assumptions[0]["risk_category"] == "input_tampering"

    def test_brain_stops_after_mapping_no_other_agents(self) -> None:
        llm = MockLLMBrain()
        runner = Runner(llm=llm)
        brain = Brain(runner=runner, agents={"mapping": MappingAgent()})

        state = brain.run("/project")

        assert "mapping" in state.completed_agents
        assert "attack_surface" not in state.completed_agents
        assert state.language == "Python"
