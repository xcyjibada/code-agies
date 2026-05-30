"""Tests for engine/agents/dataflow.py — DataFlowAgent.

Test categories:
1. _parse_output — JSON extraction from LLM text
2. _extract_json — edge cases for brace-depth counting
3. Schema validation — DataFlowOutput / DataFlowPath models
4. Tool definitions — correct tool set
5. Agent creation — defaults and registry
6. Mock LLM integration — scripted conversations
7. Brain integration — dataflow in the full pipeline
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

from agies.engine.v2.agents.base import AgentResponse, ToolResult
from agies.engine.v2.agents.dataflow import (
    DATAFLOW_TOOLS,
    DataFlowAgent,
    DataFlowPath,
    DataFlowOutput,
    DataFlowPathStep,
)
from agies.engine.v2.brain import Brain
from agies.engine.v2.runner import Runner, AgentResult, AgentCall
from agies.engine.v2.state import ProjectState


@dataclass
class _MockLLM:
    """Minimal LLM stub for Runner construction in Brain integration tests."""
    def chat_completion(self, messages, tools=None, **kwargs):
        from dataclasses import dataclass as _dc
        @_dc
        class _Resp:
            content: str | None = None
            tool_calls: list | None = None
            usage: Any = None
        return _Resp(content="ok")


SIMPLE_LLM = _MockLLM()


# ---------------------------------------------------------------------------
# _parse_output
# ---------------------------------------------------------------------------


class TestParseOutput:
    """DataFlowAgent._parse_output — JSON extraction from LLM text."""

    def make_agent(self) -> DataFlowAgent:
        return DataFlowAgent()

    def test_extracts_paths_from_code_block(self) -> None:
        agent = self.make_agent()
        content = """I traced the data flow.

```json
{
  "entry_point_id": "ep-001",
  "paths": [
    {
      "sink_type": "sql_injection",
      "sink_file": "repo/UserRepo.java",
      "sink_line": 85,
      "sink_function": "findUser",
      "description": "Username flows unsanitized into SQL",
      "path_steps": [
        {"file": "controller/AuthController.java", "line": 42, "detail": "Receives username"},
        {"file": "service/AuthService.java", "line": 30, "detail": "Passes to repo"}
      ],
      "has_validation": false,
      "confidence": "high"
    }
  ]
}
```"""
        result = agent._parse_output(content, [])
        assert result["entry_point_id"] == "ep-001"
        assert len(result["paths"]) == 1
        p = result["paths"][0]
        assert p["sink_type"] == "sql_injection"
        assert p["sink_file"] == "repo/UserRepo.java"
        assert p["sink_line"] == 85
        assert p["confidence"] == "high"
        assert len(p["path_steps"]) == 2

    def test_empty_paths_list(self) -> None:
        agent = self.make_agent()
        content = """```json
{"entry_point_id": "ep-001", "paths": []}
```"""
        result = agent._parse_output(content, [])
        assert result["paths"] == []
        assert result["entry_point_id"] == "ep-001"

    def test_empty_content_returns_empty(self) -> None:
        agent = self.make_agent()
        result = agent._parse_output("", [])
        assert result["paths"] == []
        assert result["entry_point_id"] == ""

    def test_no_json_in_content_returns_empty(self) -> None:
        agent = self.make_agent()
        result = agent._parse_output("Just some text without JSON", [])
        assert result["paths"] == []
        assert result["entry_point_id"] == ""

    def test_normalises_path_fields(self) -> None:
        agent = self.make_agent()
        content = """```json
{
  "entry_point_id": "ep-001",
  "paths": [
    {
      "sink_type": "command_injection",
      "sink_file": "util/Exec.java",
      "sink_line": 15,
      "sink_function": "runCommand",
      "description": "desc",
      "path_steps": [
        {"file": "a.java", "line": 1, "detail": "step 1"}
      ],
      "has_validation": false,
      "confidence": "high",
      "unknown_field": "should be dropped"
    }
  ]
}
```"""
        result = agent._parse_output(content, [])
        assert len(result["paths"]) == 1
        p = result["paths"][0]
        assert "unknown_field" not in p

    def test_invalid_json_returns_empty(self) -> None:
        agent = self.make_agent()
        content = "```json\n{broken json here\n```"
        result = agent._parse_output(content, [])
        assert result["paths"] == []

    def test_partial_path_gets_defaults(self) -> None:
        agent = self.make_agent()
        content = """```json
{
  "entry_point_id": "ep-001",
  "paths": [
    {
      "sink_type": "path_traversal",
      "sink_file": "io/FileService.java",
      "sink_line": 42,
      "sink_function": "readFile"
    }
  ]
}
```"""
        result = agent._parse_output(content, [])
        assert len(result["paths"]) == 1
        p = result["paths"][0]
        assert p["sink_type"] == "path_traversal"
        assert p["has_validation"] is False
        assert p["confidence"] == "medium"
        assert p["path_steps"] == []
        assert p["description"] == ""

    def test_multiple_paths(self) -> None:
        agent = self.make_agent()
        content = """```json
{
  "entry_point_id": "ep-001",
  "paths": [
    {"sink_type": "sqli", "sink_file": "a.py", "sink_line": 1, "sink_function": "q"},
    {"sink_type": "xss", "sink_file": "b.py", "sink_line": 2, "sink_function": "r"},
    {"sink_type": "cmd_injection", "sink_file": "c.py", "sink_line": 3, "sink_function": "s"}
  ]
}
```"""
        result = agent._parse_output(content, [])
        assert len(result["paths"]) == 3

    def test_cleans_path_steps(self) -> None:
        agent = self.make_agent()
        content = """```json
{
  "entry_point_id": "ep-001",
  "paths": [
    {
      "sink_type": "sqli",
      "sink_file": "a.py",
      "sink_line": 10,
      "sink_function": "q",
      "path_steps": [
        {"file": "x.py", "line": 1, "detail": "step A", "extra": "dropped"}
      ]
    }
  ]
}
```"""
        result = agent._parse_output(content, [])
        step = result["paths"][0]["path_steps"][0]
        assert step["file"] == "x.py"
        assert step["line"] == 1
        assert step["detail"] == "step A"
        assert "extra" not in step


# ---------------------------------------------------------------------------
# _extract_json
# ---------------------------------------------------------------------------


class TestExtractJson:
    """DataFlowAgent._extract_json."""

    def test_code_block(self) -> None:
        text = "Text\n```json\n{\"a\": 1}\n```\ntext"
        assert DataFlowAgent._extract_json(text) == '{"a": 1}'

    def test_code_block_no_lang(self) -> None:
        text = "```\n{\"a\": 1}\n```"
        assert DataFlowAgent._extract_json(text) == '{"a": 1}'

    def test_bare_braces(self) -> None:
        text = "prefix {\"paths\": []} suffix"
        assert DataFlowAgent._extract_json(text) == '{"paths": []}'

    def test_no_json(self) -> None:
        assert DataFlowAgent._extract_json("just text") is None

    def test_nested_braces(self) -> None:
        text = '{"a": {"b": [1, 2, {"c": 3}]}}'
        assert DataFlowAgent._extract_json(text) == text

    def test_only_opening_brace(self) -> None:
        assert DataFlowAgent._extract_json("{ no closing") is None


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


class TestDataFlowOutput:
    def test_valid(self) -> None:
        o = DataFlowOutput(
            entry_point_id="ep-001",
            paths=[
                DataFlowPath(
                    sink_type="sql_injection",
                    sink_file="repo/UserRepo.java",
                    sink_line=85,
                    sink_function="findUser",
                    description="desc",
                    path_steps=[
                        DataFlowPathStep(file="a.java", line=1, detail="step"),
                    ],
                    has_validation=False,
                    confidence="high",
                ),
            ],
        )
        assert o.entry_point_id == "ep-001"
        assert len(o.paths) == 1
        assert o.paths[0].sink_type == "sql_injection"

    def test_empty_default(self) -> None:
        o = DataFlowOutput()
        assert o.paths == []
        assert o.entry_point_id == ""

    def test_minimal_path(self) -> None:
        p = DataFlowPath(sink_type="sqli", sink_file="x.py", sink_line=1, sink_function="q")
        assert p.confidence == "medium"
        assert p.has_validation is False
        assert p.path_steps == []

    def test_path_step_defaults(self) -> None:
        s = DataFlowPathStep(file="a.py", line=1, detail="step")
        assert s.file == "a.py"
        assert s.line == 1
        assert s.detail == "step"


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


class TestDataFlowTools:
    def test_has_expected_tools(self) -> None:
        names = {t["name"] for t in DATAFLOW_TOOLS}
        assert "read_file" in names
        assert "grep_search" in names
        assert "lookup_function" in names
        assert "find_callers" in names
        assert "find_callees" in names
        assert "get_taint_flows" in names

    def test_tool_count(self) -> None:
        assert len(DATAFLOW_TOOLS) == 6


# ---------------------------------------------------------------------------
# Agent instantiation
# ---------------------------------------------------------------------------


class TestAgentCreation:
    def test_defaults(self) -> None:
        agent = DataFlowAgent()
        assert agent.agent_id == "dataflow"
        assert len(agent.tools) == 6
        assert agent.output_schema is DataFlowOutput

    def test_registry_has_all_tools(self) -> None:
        agent = DataFlowAgent()
        assert "read_file" in agent._tool_registry
        assert "grep_search" in agent._tool_registry
        assert "lookup_function" in agent._tool_registry
        assert "find_callers" in agent._tool_registry
        assert "find_callees" in agent._tool_registry
        assert "get_taint_flows" in agent._tool_registry


# ---------------------------------------------------------------------------
# Mock LLM helpers
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


class TestDataFlowAgentRun:
    """End-to-end agent.run() with scripted LLM responses."""

    VALID_DF_JSON = json.dumps({
        "entry_point_id": "ep-001",
        "paths": [
            {
                "sink_type": "sql_injection",
                "sink_file": "repo/UserRepo.java",
                "sink_line": 85,
                "sink_function": "findUser",
                "description": "Username flows unsanitized into SQL query",
                "path_steps": [
                    {"file": "controller/AuthController.java", "line": 42,
                     "detail": "Receives `username` from request body"},
                    {"file": "service/AuthService.java", "line": 30,
                     "detail": "Passed to userRepo.findUser(username)"},
                ],
                "has_validation": False,
                "confidence": "high",
            },
        ],
    })

    def make_agent(self) -> DataFlowAgent:
        return DataFlowAgent()

    def test_llm_explores_then_reports_paths(self) -> None:
        """LLM uses read_file tool, then outputs paths."""
        agent = self.make_agent()
        mock_llm = MockLLMStepwise([
            MockLLMResponse(
                content="Let me read the entry point code.",
                tool_calls=[MockToolCall(
                    name="read_file",
                    arguments=json.dumps({"path": "/project/controller/AuthController.java"}),
                    id="call1",
                )],
            ),
            MockLLMResponse(
                content=f"```json\n{self.VALID_DF_JSON}\n```",
                tool_calls=None,
            ),
        ])
        result = agent.run(
            params={
                "entry_point_id": "ep-001",
                "entry_point": {"type": "http_endpoint", "path": "/api/login", "method": "POST"},
                "project_path": "/project",
            },
            llm=mock_llm,
        )
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].name == "read_file"
        assert result.output["entry_point_id"] == "ep-001"
        assert len(result.output["paths"]) == 1

    def test_llm_directly_outputs_paths(self) -> None:
        """LLM directly outputs the result without tool calls."""
        agent = self.make_agent()
        mock_llm = MockLLMStepwise([
            MockLLMResponse(
                content=f"```json\n{self.VALID_DF_JSON}\n```",
                tool_calls=None,
            ),
        ])
        result = agent.run(
            params={
                "entry_point_id": "ep-001",
                "entry_point": {"type": "http_endpoint", "path": "/api/login"},
                "project_path": "/project",
            },
            llm=mock_llm,
        )
        assert len(result.tool_calls) == 0
        assert len(result.output["paths"]) == 1

    def test_no_paths_found(self) -> None:
        """LLM correctly reports no data flow paths."""
        agent = self.make_agent()
        mock_llm = MockLLMStepwise([
            MockLLMResponse(
                content='{"entry_point_id": "ep-001", "paths": []}',
                tool_calls=None,
            ),
        ])
        result = agent.run(
            params={
                "entry_point_id": "ep-001",
                "entry_point": {"type": "http_endpoint", "path": "/api/health"},
                "project_path": "/project",
            },
            llm=mock_llm,
        )
        assert result.output["paths"] == []

    def test_llm_produces_invalid_output(self) -> None:
        """Agent handles invalid JSON gracefully."""
        agent = self.make_agent()
        mock_llm = MockLLMStepwise([
            MockLLMResponse(
                content="I could not complete the analysis due to an error.",
                tool_calls=None,
            ),
        ])
        result = agent.run(
            params={
                "entry_point_id": "ep-001",
                "entry_point": {},
                "project_path": "/project",
            },
            llm=mock_llm,
        )
        assert result.output["paths"] == []

    def test_llm_uses_grep_and_then_reports(self) -> None:
        """LLM uses grep_search then outputs paths."""
        agent = self.make_agent()
        mock_llm = MockLLMStepwise([
            MockLLMResponse(
                content="Let me search for the sink.",
                tool_calls=[MockToolCall(
                    name="grep_search",
                    arguments=json.dumps({"pattern": "executeQuery", "path": "/project"}),
                    id="call1",
                )],
            ),
            MockLLMResponse(
                content=f"```json\n{self.VALID_DF_JSON}\n```",
                tool_calls=None,
            ),
        ])
        result = agent.run(
            params={
                "entry_point_id": "ep-001",
                "entry_point": {"type": "http_endpoint", "path": "/api/login"},
                "project_path": "/project",
            },
            llm=mock_llm,
        )
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].name == "grep_search"


# ---------------------------------------------------------------------------
# Brain integration
# ---------------------------------------------------------------------------


class TestBrainWithDataFlow:
    """DataFlow Agent in the Brain pipeline."""

    DF_RESULT = {
        "entry_point_id": "ep-001",
        "paths": [
            {
                "sink_type": "sql_injection",
                "sink_file": "repo/UserRepo.java",
                "sink_line": 85,
                "sink_function": "findUser",
                "description": "desc",
                "path_steps": [{"file": "a.java", "line": 1, "detail": "step"}],
                "has_validation": False,
                "confidence": "high",
            },
        ],
    }

    def test_dataflow_runs_after_attack_surface(self) -> None:
        """Brain dispatches DataFlow after AttackSurface populates entry_points."""
        state = ProjectState(project_path="/project")
        state.completed_agents = ["mapping", "attack_surface"]
        state.entry_points = [
            {"id": "ep-001", "type": "http_endpoint", "path": "/api/login"},
        ]

        agent = DataFlowAgent()
        available = state.get_available_agents()
        assert "dataflow" in available

    def test_dataflow_skipped_when_no_entry_points(self) -> None:
        """DataFlow is not available when there are no entry points."""
        state = ProjectState(project_path="/project")
        state.completed_agents = ["mapping"]
        state.entry_points = []

        available = state.get_available_agents()
        assert "dataflow" not in available

    def test_dataflow_skipped_when_all_done(self) -> None:
        """DataFlow is not available when all entry points have dataflow_done."""
        state = ProjectState(project_path="/project")
        state.completed_agents = ["mapping", "attack_surface"]
        state.entry_points = [
            {"id": "ep-001", "type": "http_endpoint", "dataflow_done": True},
        ]

        available = state.get_available_agents()
        assert "dataflow" not in available

    def test_brain_builds_dataflow_call_for_unanalyzed_ep(self) -> None:
        """Brain builds AgentCall for each unanalyzed entry point."""
        runner = Runner(llm=SIMPLE_LLM, max_workers=1)
        agent = DataFlowAgent()
        brain = Brain(runner=runner, agents={"dataflow": agent})

        state = ProjectState(project_path="/project")
        state.completed_agents = ["mapping", "attack_surface"]
        state.entry_points = [
            {"id": "ep-001", "type": "http_endpoint", "path": "/api/login"},
            {"id": "ep-002", "type": "http_endpoint", "path": "/api/register"},
        ]

        batch = brain._build_calls("dataflow", agent, state)
        assert len(batch) == 2
        assert batch[0].params["entry_point_id"] == "ep-001"
        assert batch[1].params["entry_point_id"] == "ep-002"

    def test_register_result_stores_paths(self) -> None:
        """State.register_result correctly stores dataflow paths."""
        state = ProjectState(project_path="/project")
        state.entry_points = [{"id": "ep-001", "type": "http_endpoint"}]

        state.register_result(
            agent_name="dataflow",
            params={"entry_point_id": "ep-001"},
            output=self.DF_RESULT,
        )

        assert len(state.dataflow_paths) == 1
        assert state.dataflow_paths[0]["dataflow_done"] is True
        # entry point should be marked done
        assert state.entry_points[0]["dataflow_done"] is True

    def test_register_result_multiple_eps(self) -> None:
        """Each entry point is independently marked done."""
        state = ProjectState(project_path="/project")
        state.entry_points = [
            {"id": "ep-001", "type": "http_endpoint"},
            {"id": "ep-002", "type": "http_endpoint"},
        ]

        # Only analyze ep-001
        state.register_result(
            agent_name="dataflow",
            params={"entry_point_id": "ep-001"},
            output={"entry_point_id": "ep-001", "paths": [
                {"sink_type": "sqli", "sink_file": "a.py", "sink_line": 1, "sink_function": "q"},
            ]},
        )

        assert state.entry_points[0]["dataflow_done"] is True
        assert "dataflow_done" not in state.entry_points[1]
        assert len(state.dataflow_paths) == 1

    def test_state_after_dataflow_vuln_mode2_available(self) -> None:
        """After dataflow paths exist, vulnerability Mode 2 becomes available."""
        state = ProjectState(project_path="/project")
        state.completed_agents = ["mapping", "attack_surface", "dataflow"]
        state.entry_points = [{"id": "ep-001", "type": "http_endpoint", "dataflow_done": True}]
        state.dataflow_paths = [
            {"id": "pf-001", "dataflow_done": True, "sink_type": "sqli"},
        ]

        available = state.get_available_agents()
        assert "vulnerability" in available


# ---------------------------------------------------------------------------
# State progression
# ---------------------------------------------------------------------------


class TestStateProgression:
    """DataFlow availability through the pipeline stages."""

    def test_after_attack_surface_dataflow_is_available(self) -> None:
        state = ProjectState(project_path="/project")
        state.completed_agents = ["mapping", "attack_surface"]
        state.entry_points = [{"id": "ep-001", "type": "http_endpoint"}]
        assert "dataflow" in state.get_available_agents()

    def test_after_all_entry_points_dataflow_unavailable(self) -> None:
        state = ProjectState(project_path="/project")
        state.completed_agents = ["mapping", "attack_surface"]
        state.entry_points = [{"id": "ep-001", "type": "http_endpoint", "dataflow_done": True}]
        assert "dataflow" not in state.get_available_agents()

    def test_no_entry_points_dataflow_not_available(self) -> None:
        state = ProjectState(project_path="/project")
        state.completed_agents = ["mapping", "attack_surface"]
        state.entry_points = []
        assert "dataflow" not in state.get_available_agents()

    def test_empty_entry_points_after_empty_register(self) -> None:
        state = ProjectState(project_path="/project")
        state.entry_points = []
        assert "dataflow" not in state.get_available_agents()


# ---------------------------------------------------------------------------
# Existing tests should still pass
# ---------------------------------------------------------------------------


class TestExistingBrainStillWorks:
    """Make sure adding DataFlow doesn't break existing Brain behavior."""

    def test_mapping_only_brain_stops(self) -> None:
        """Brain with only MappingAgent should still work."""
        from agies.engine.v2.agents.mapping import MappingAgent

        runner = Runner(llm=SIMPLE_LLM, max_workers=1)
        mapping_agent = MappingAgent()
        dataflow_agent = DataFlowAgent()
        brain = Brain(
            runner=runner,
            agents={"mapping": mapping_agent, "dataflow": dataflow_agent},
        )

        state = ProjectState(project_path="/project")
        state.completed_agents = ["mapping"]
        state.entry_points = []

        available = state.get_available_agents()
        assert "dataflow" not in available  # no entry points to feed it
