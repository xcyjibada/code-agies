"""Tests for engine/agents/verify.py — VerifyAgent.

Test categories:
1. _parse_output — JSON extraction from LLM text
2. _extract_json — edge cases for brace-depth counting
3. Schema validation — VerifyOutput / VerifiedFinding models
4. Tool definitions — correct tool set
5. Agent creation — defaults and registry
6. Mock LLM integration — scripted conversations
7. Brain integration — verify in the full pipeline
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

from agies.engine.agents.base import AgentResponse, ToolResult
from agies.engine.agents.verify import (
    VERIFY_TOOLS,
    VerifyAgent,
    VerifiedFinding,
    VerifyOutput,
)
from agies.engine.brain import Brain
from agies.engine.runner import Runner, AgentResult, AgentCall
from agies.engine.state import ProjectState


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
    """VerifyAgent._parse_output — JSON extraction from LLM text."""

    def make_agent(self) -> VerifyAgent:
        return VerifyAgent()

    def test_extracts_findings_from_code_block(self) -> None:
        agent = self.make_agent()
        content = """I verified the vulnerability.

```json
{
  "findings": [
    {
      "type": "sql_injection",
      "severity": "critical",
      "file_path": "src/db/query.py",
      "line_number": 42,
      "title": "Confirmed: SQL injection in UserDAO",
      "description": "User input flows directly into execute()",
      "reasoning": "No sanitization before the execute() call",
      "confidence": "high",
      "verified": true
    }
  ]
}
```"""
        result = agent._parse_output(content, [])
        assert "findings" in result
        assert len(result["findings"]) == 1
        f = result["findings"][0]
        assert f["type"] == "sql_injection"
        assert f["severity"] == "critical"
        assert f["file_path"] == "src/db/query.py"
        assert f["line_number"] == 42
        assert f["confidence"] == "high"
        assert f["verified"] is True

    def test_empty_findings_list(self) -> None:
        agent = self.make_agent()
        content = """```json
{"findings": []}
```"""
        result = agent._parse_output(content, [])
        assert result["findings"] == []

    def test_no_json_in_content(self) -> None:
        agent = self.make_agent()
        content = "No vulnerabilities were confirmed after analysis."
        result = agent._parse_output(content, [])
        assert result["findings"] == []

    def test_invalid_json(self) -> None:
        agent = self.make_agent()
        content = "Some text with ```json\n{invalid: json\n}``` after"
        result = agent._parse_output(content, [])
        assert result["findings"] == []

    def test_empty_content(self) -> None:
        agent = self.make_agent()
        result = agent._parse_output("", [])
        assert result["findings"] == []

    def test_partial_finding_defaults(self) -> None:
        """Fields not in the LLM output get default values."""
        agent = self.make_agent()
        content = """```json
{"findings": [{"type": "xss", "severity": "high"}]}
```"""
        result = agent._parse_output(content, [])
        assert len(result["findings"]) == 1
        f = result["findings"][0]
        assert f["type"] == "xss"
        assert f["severity"] == "high"
        # Defaults for missing fields
        assert f["file_path"] == ""
        assert f["line_number"] == 0
        assert f["title"] == ""
        assert f["verified"] is True
        assert f["confidence"] == "medium"

    def test_invalid_fields_stripped(self) -> None:
        """Extra fields from the LLM are pruned."""
        agent = self.make_agent()
        content = """```json
{"findings": [{"type": "xss", "severity": "high", "extra_field": "should_be_removed"}]}
```"""
        result = agent._parse_output(content, [])
        assert len(result["findings"]) == 1
        f = result["findings"][0]
        assert "extra_field" not in f


# ---------------------------------------------------------------------------
# _extract_json
# ---------------------------------------------------------------------------


class TestExtractJson:
    """VerifyAgent._extract_json — edge cases."""

    def test_code_block_with_lang(self) -> None:
        text = "some text\n```json\n{\"a\": 1}\n```"
        assert VerifyAgent._extract_json(text) == '{"a": 1}'

    def test_code_block_no_lang(self) -> None:
        text = "```\n{\"a\": 1}\n```"
        assert VerifyAgent._extract_json(text) == '{"a": 1}'

    def test_bare_braces(self) -> None:
        text = "some text {\"a\": 1} more text"
        assert VerifyAgent._extract_json(text) == '{"a": 1}'

    def test_no_json(self) -> None:
        text = "just plain text without braces"
        assert VerifyAgent._extract_json(text) is None

    def test_nested_braces(self) -> None:
        text = "```json\n{\"a\": {\"b\": [1, 2]}}\n```"
        assert VerifyAgent._extract_json(text) == '{"a": {"b": [1, 2]}}'

    def test_partial_brace(self) -> None:
        text = "```json\n{\"a\": 1\n```"
        # Unclosed brace should still be found by the fallback bare-brace path
        result = VerifyAgent._extract_json(text)
        # The fallback finds the open brace
        assert result is None or result == '{"a": 1'


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class TestVerifyOutput:
    """VerifyOutput and VerifiedFinding model validation."""

    def test_valid_full_output(self) -> None:
        out = VerifyOutput(
            findings=[
                VerifiedFinding(
                    type="sql_injection",
                    severity="critical",
                    file_path="src/db.py",
                    line_number=42,
                    title="SQL Injection",
                    description="User input in query",
                    reasoning="No sanitization",
                    confidence="high",
                    verified=True,
                ),
            ],
        )
        assert len(out.findings) == 1
        assert out.findings[0].verified is True

    def test_empty_output(self) -> None:
        out = VerifyOutput()
        assert out.findings == []

    def test_minimal_finding(self) -> None:
        """A VerifiedFinding with no fields uses all defaults."""
        f = VerifiedFinding()
        assert f.type == ""
        assert f.severity == "medium"
        assert f.file_path == ""
        assert f.line_number == 0
        assert f.title == ""
        assert f.description == ""
        assert f.reasoning == ""
        assert f.confidence == "medium"
        assert f.verified is True


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


class TestVerifyTools:
    """VerifyAgent tool definitions."""

    def test_expected_tools(self) -> None:
        names = {t["name"] for t in VERIFY_TOOLS}
        assert "read_file" in names
        assert "grep_search" in names
        assert "get_taint_flows" in names
        assert "lookup_function" in names
        assert "find_callers" in names
        assert "find_callees" in names
        assert "get_call_chain_logic" in names
        assert "record_knowledge" in names

    def test_tool_count(self) -> None:
        assert len(VERIFY_TOOLS) == 8


# ---------------------------------------------------------------------------
# Agent creation
# ---------------------------------------------------------------------------


class TestAgentCreation:
    """VerifyAgent construction and defaults."""

    def test_defaults(self) -> None:
        agent = VerifyAgent()
        assert agent.agent_id == "verify"
        assert len(agent.tools) == 8
        assert agent.output_schema == VerifyOutput

    def test_overrides(self) -> None:
        agent = VerifyAgent(agent_id="my_verify")
        assert agent.agent_id == "my_verify"


# ---------------------------------------------------------------------------
# Mock LLM integration
# ---------------------------------------------------------------------------


@dataclass
class MockLLMResponder:
    """Scriptable mock that returns pre-configured responses."""
    responses: list[Any]

    def __init__(self, responses: list[dict] | None = None) -> None:
        self.responses = responses or []
        self.call_count = 0

    def chat_completion(self, messages, tools=None, **kwargs):
        from dataclasses import dataclass as _dc
        self.call_count += 1
        resp_data = self.responses[self.call_count - 1] if self.call_count <= len(self.responses) else {"content": "ok"}
        @_dc
        class _Resp:
            content: str | None = None
            tool_calls: list | None = None
            usage: Any = None
        return _Resp(
            content=resp_data.get("content"),
            tool_calls=resp_data.get("tool_calls"),
            usage=resp_data.get("usage"),
        )


class TestVerifyAgentRun:
    """VerifyAgent.run() with a mock LLM."""

    def test_confirmed_finding(self) -> None:
        agent = VerifyAgent()
        llm = MockLLMResponder([
            {"content": "```json\n{\"findings\": [{\"type\": \"sqli\", \"severity\": \"critical\", \"file_path\": \"db.py\", \"line_number\": 10, \"title\": \"SQLI confirmed\", \"description\": \"Found it\", \"reasoning\": \"Evidence\", \"confidence\": \"high\"}]}\n```"}
        ])
        response = agent.run(
            {"vulnerability_id": "v_001", "vulnerability": {"type": "sqli"}, "project_path": "/p"},
            llm,
        )
        assert response.output is not None
        assert len(response.output.get("findings", [])) == 1
        assert response.output["findings"][0]["type"] == "sqli"
        assert response.output["findings"][0]["severity"] == "critical"
        assert response.output["findings"][0]["verified"] is True

    def test_false_positive_empty(self) -> None:
        agent = VerifyAgent()
        llm = MockLLMResponder([
            {"content": "```json\n{\"findings\": []}\n```"}
        ])
        response = agent.run(
            {"vulnerability_id": "v_002", "vulnerability": {"type": "xss"}, "project_path": "/p"},
            llm,
        )
        assert response.output is not None
        assert len(response.output.get("findings", [])) == 0

    def test_no_json_in_response(self) -> None:
        """When the LLM returns no JSON, return empty findings."""
        agent = VerifyAgent()
        llm = MockLLMResponder([
            {"content": "After analysis, this is a false positive."}
        ])
        response = agent.run(
            {"vulnerability_id": "v_003", "vulnerability": {"type": "sqli"}, "project_path": "/p"},
            llm,
        )
        assert response.output is not None
        assert response.output.get("findings") == []

    def test_invalid_llm_output(self) -> None:
        """Invalid JSON from LLM results in empty findings."""
        agent = VerifyAgent()
        llm = MockLLMResponder([
            {"content": "```json\n{invalid: json}\n```"}
        ])
        response = agent.run(
            {"vulnerability_id": "v_004", "vulnerability": {"type": "sqli"}, "project_path": "/p"},
            llm,
        )
        assert len(response.output.get("findings", [])) == 0

    def test_explore_then_report(self) -> None:
        """LLM uses tools first, then reports findings."""
        agent = VerifyAgent()
        tool_call = type("TC", (), {"id": "tc1", "name": "grep_search", "arguments": '{"pattern": "execute", "path": "/p"}'})()
        llm = MockLLMResponder([
            {"content": "Let me check the code.", "tool_calls": [tool_call]},
            {"content": "```json\n{\"findings\": [{\"type\": \"sqli\", \"severity\": \"high\", \"file_path\": \"db.py\", \"line_number\": 10, \"title\": \"Confirmed\", \"description\": \"Found\", \"reasoning\": \"Evidence\", \"confidence\": \"high\"}]}\n```"},
        ])
        response = agent.run(
            {"vulnerability_id": "v_005", "vulnerability": {"type": "sqli"}, "project_path": "/p"},
            llm,
        )
        assert response.output is not None
        assert len(response.output.get("findings", [])) == 1


# ---------------------------------------------------------------------------
# Brain integration
# ---------------------------------------------------------------------------


class TestBrainWithVerify:
    """VerifyAgent in the Brain / TaskQueue pipeline."""

    @dataclass
    class MappingStub:
        agent_id = "mapping"
        system_prompt = ""
        tools = []
        def run(self, params, llm=None, **kwargs) -> AgentResponse:
            return AgentResponse(content="mapped", output={
                "summary": "Web app", "modules": [], "key_files": [
                    {"path": "app/main.py", "role": "entry"},
                ],
                "language": "Python", "framework": "Flask", "file_count": 10,
            })

    @dataclass
    class AttackSurfaceStub:
        agent_id = "attack_surface"
        system_prompt = ""
        tools = []
        def run(self, params, llm=None, **kwargs) -> AgentResponse:
            return AgentResponse(content="surface", output={
                "entry_points": [{"id": "ep1", "path": "/login", "method": "POST"}],
            })

    @dataclass
    class DataFlowStub:
        agent_id = "dataflow"
        system_prompt = ""
        tools = []
        def __init__(self):
            self._counter = 0
        def run(self, params, llm=None, **kwargs) -> AgentResponse:
            self._counter += 1
            return AgentResponse(content="flow", output={
                "paths": [{"id": f"p_{self._counter}", "source": params.get("entry_point_id"), "sink": "exec()"}],
            })

    @dataclass
    class VulnStub:
        agent_id = "vulnerability"
        system_prompt = ""
        tools = []
        def __init__(self):
            self._counter = 0
        def run(self, params, llm=None, **kwargs) -> AgentResponse:
            self._counter += 1
            return AgentResponse(content="vuln", output={
                "vulnerabilities": [{"id": f"v_{self._counter}", "type": "sqli", "severity": "critical"}],
            })

    @dataclass
    class ReportStub:
        agent_id = "report"
        system_prompt = ""
        tools = []
        def run(self, params, llm=None, **kwargs) -> AgentResponse:
            return AgentResponse(content="report", output={"report": "Done"})

    def test_verify_available_after_vuln(self) -> None:
        """Verify agent becomes available after vulnerability has candidates."""
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={
            "mapping": self.MappingStub(),
            "attack_surface": self.AttackSurfaceStub(),
            "dataflow": self.DataFlowStub(),
            "vulnerability": self.VulnStub(),
            "verify": VerifyAgent(),
            "report": self.ReportStub(),
        })
        state = brain.run("/project")

        assert "mapping" in state.completed_agents
        assert "attack_surface" in state.completed_agents
        assert "dataflow" in state.completed_agents
        assert "vulnerability" in state.completed_agents
        assert "verify" in state.completed_agents

    def test_verify_marks_vuln_verified(self) -> None:
        """After verify runs, candidate vulnerabilities are marked verified."""
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={
            "mapping": self.MappingStub(),
            "attack_surface": self.AttackSurfaceStub(),
            "dataflow": self.DataFlowStub(),
            "vulnerability": self.VulnStub(),
            "verify": VerifyAgent(),
            "report": self.ReportStub(),
        })
        state = brain.run("/project")

        assert len(state.candidate_vulnerabilities) > 0
        for v in state.candidate_vulnerabilities:
            assert v.get("verified"), f"Vulnerability {v.get('id')} should be verified"

    def test_verify_not_available_without_vulns(self) -> None:
        """Without candidate vulnerabilities, verify should not be available."""
        state = ProjectState(project_path="/p")
        state.completed_agents = ["mapping", "attack_surface", "dataflow", "vulnerability"]
        available = state.get_available_agents()
        assert "verify" not in available

    def test_verify_available_after_report(self) -> None:
        """After all vulns verified, report becomes available."""
        state = ProjectState(project_path="/p")
        state.completed_agents = ["mapping", "attack_surface", "dataflow", "vulnerability", "verify"]
        state.candidate_vulnerabilities = [
            {"id": "v_1", "type": "sqli", "verified": True},
        ]
        state.entry_points = [{"id": "ep1", "dataflow_done": True}]
        available = state.get_available_agents()
        assert "report" in available

    def test_verify_creates_correct_params(self) -> None:
        """Brain._build_calls('verify', ...) creates per-vulnerability calls."""
        state = ProjectState(project_path="/p")
        state.candidate_vulnerabilities = [
            {"id": "v_1", "type": "sqli", "verified": False},
            {"id": "v_2", "type": "xss", "verified": False},
            {"id": "v_3", "type": "sqli", "verified": True},  # already verified
        ]
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={"verify": VerifyAgent()})
        calls = brain._build_calls("verify", VerifyAgent(), state)
        # Only unverified vulns create calls
        vuln_ids = [c.params.get("vulnerability_id") for c in calls]
        assert "v_1" in vuln_ids
        assert "v_2" in vuln_ids
        assert "v_3" not in vuln_ids  # already verified
        assert len(calls) == 2


# ---------------------------------------------------------------------------
# State progression
# ---------------------------------------------------------------------------


class TestStateProgression:
    """ProjectState availability of 'verify' through pipeline stages."""

    def test_not_available_before_vuln(self) -> None:
        state = ProjectState(project_path="/p")
        state.completed_agents = ["mapping", "attack_surface", "dataflow"]
        assert "verify" not in state.get_available_agents()

    def test_available_after_vuln(self) -> None:
        state = ProjectState(project_path="/p")
        state.completed_agents = ["mapping", "attack_surface", "dataflow", "vulnerability"]
        state.candidate_vulnerabilities = [{"id": "v_1", "type": "sqli", "verified": False}]
        state.entry_points = [{"id": "ep1", "dataflow_done": True}]
        available = state.get_available_agents()
        assert "verify" in available

    def test_not_available_when_all_verified(self) -> None:
        state = ProjectState(project_path="/p")
        state.completed_agents = ["mapping", "attack_surface", "dataflow", "vulnerability", "verify"]
        state.candidate_vulnerabilities = [{"id": "v_1", "type": "sqli", "verified": True}]
        available = state.get_available_agents()
        assert "verify" not in available

    def test_verify_registers_findings(self) -> None:
        """register_result('verify', ...) extends verified_findings."""
        state = ProjectState(project_path="/p")
        state.candidate_vulnerabilities = [
            {"id": "v_1", "type": "sqli", "verified": False},
        ]
        state.register_result("verify", {"vulnerability_id": "v_1"}, {
            "findings": [{"type": "sqli", "severity": "critical", "file_path": "db.py"}],
        })
        # Candidate should be marked verified
        assert state.candidate_vulnerabilities[0]["verified"] is True
        # Should be in verified_findings
        assert len(state.verified_findings) == 1
        assert state.verified_findings[0]["verified"] is True

    def test_verify_empty_findings_still_marks_verified(self) -> None:
        """Empty findings from verify should still mark vuln as processed."""
        state = ProjectState(project_path="/p")
        state.candidate_vulnerabilities = [
            {"id": "v_1", "type": "sqli", "verified": False},
        ]
        state.register_result("verify", {"vulnerability_id": "v_1"}, {"findings": []})
        # Still marked as verified (processed)
        assert state.candidate_vulnerabilities[0]["verified"] is True


# ---------------------------------------------------------------------------
# Existing brain still works (regression)
# ---------------------------------------------------------------------------


class TestExistingBrainStillWorks:
    """Verify that existing brain tests still pass with verify agent."""

    def test_mapping_only_still_works(self) -> None:
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={
            "mapping": TestBrainWithVerify.MappingStub(),
        })
        state = brain.run("/project")
        assert "mapping" in state.completed_agents
