"""Integration tests for SAST pattern matching in verification agents.

Tests that _apply_sast correctly tags evidence and boosts confidence
in both VerifyAgent (legacy) and VerificationAgent (new pipeline).
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agies.engine.agents.base import AgentResponse
from agies.engine.agents.verify import VerifyAgent
from agies.engine.sast.matcher import SASTMatcher, get_matcher

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_py(tmpdir: str, name: str, code: str) -> str:
    p = Path(tmpdir) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code)
    return str(p)


# ---------------------------------------------------------------------------
# VerifyAgent SAST integration
# ---------------------------------------------------------------------------


class TestVerifyAgentSast:
    """_apply_sast on VerifyAgent — works per-finding on findings list."""

    def make_agent(self) -> VerifyAgent:
        return VerifyAgent()

    def test_tags_finding_with_sast_evidence(self) -> None:
        agent = self.make_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = _write_py(tmpdir, "app.py", 'eval(user_input)')
            response = AgentResponse(
                content="verified",
                output={
                    "findings": [
                        {
                            "type": "code_injection",
                            "severity": "high",
                            "file_path": file_path,
                            "line_number": 1,
                            "title": "Code injection",
                            "description": "eval on user input",
                            "reasoning": "found it",
                            "confidence": "medium",
                            "verified": True,
                        },
                    ],
                },
            )
            agent._apply_sast(response, {"project_path": ""})
            findings = response.output["findings"]
            assert len(findings) == 1
            f = findings[0]
            assert "SAST:" in f["evidence"]
            assert "py-eval-exec" in f["evidence"] or "eval" in f["evidence"]

    def test_boosts_confidence(self) -> None:
        """SAST match should boost confidence from medium to high."""
        agent = self.make_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = _write_py(tmpdir, "app.py", 'eval(user_input)')
            response = AgentResponse(
                content="verified",
                output={
                    "findings": [
                        {
                            "type": "code_injection",
                            "severity": "high",
                            "file_path": file_path,
                            "line_number": 1,
                            "title": "Code injection",
                            "description": "eval on user input",
                            "reasoning": "found it",
                            "confidence": "medium",
                            "verified": True,
                        },
                    ],
                },
            )
            agent._apply_sast(response, {"project_path": ""})
            f = response.output["findings"][0]
            # eval is critical severity → confidence should be "high"
            assert f["confidence"] == "high"

    def test_no_match_does_not_change_finding(self) -> None:
        """Clean code should leave finding unchanged."""
        agent = self.make_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = _write_py(tmpdir, "safe.py", "x = 1 + 1")
            response = AgentResponse(
                content="verified",
                output={
                    "findings": [
                        {
                            "type": "sqli",
                            "severity": "high",
                            "file_path": file_path,
                            "line_number": 1,
                            "title": "SQLI?",
                            "description": "maybe",
                            "reasoning": "checking",
                            "confidence": "low",
                            "verified": False,
                        },
                    ],
                },
            )
            agent._apply_sast(response, {"project_path": ""})
            f = response.output["findings"][0]
            # Confidence unchanged
            assert f["confidence"] == "low"
            # No evidence added
            assert "evidence" not in f or not f["evidence"]

    def test_relative_path_resolved_via_project_path(self) -> None:
        agent = self.make_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = _write_py(tmpdir, "sub/app.py", 'eval(user_input)')
            relative = "sub/app.py"
            response = AgentResponse(
                content="verified",
                output={
                    "findings": [
                        {
                            "type": "code_injection",
                            "severity": "high",
                            "file_path": relative,
                            "line_number": 1,
                            "title": "CI",
                            "description": "eval",
                            "reasoning": "found",
                            "confidence": "medium",
                            "verified": True,
                        },
                    ],
                },
            )
            agent._apply_sast(response, {"project_path": tmpdir})
            f = response.output["findings"][0]
            assert "SAST:" in f["evidence"]

    def test_empty_findings_noop(self) -> None:
        agent = self.make_agent()
        response = AgentResponse(content="verified", output={"findings": []})
        agent._apply_sast(response, {"project_path": "/p"})
        assert response.output["findings"] == []

    def test_empty_output_noop(self) -> None:
        agent = self.make_agent()
        response = AgentResponse(content="verified", output={})
        agent._apply_sast(response, {"project_path": "/p"})
        assert response.output == {}

    def test_multiple_findings_tagged_independently(self) -> None:
        """Multiple findings in same file should each get evidence."""
        agent = self.make_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = _write_py(tmpdir, "vuln.py", 'eval(user_input)\n')
            response = AgentResponse(
                content="verified",
                output={
                    "findings": [
                        {
                            "type": "code_injection",
                            "severity": "high",
                            "file_path": file_path,
                            "line_number": 1,
                            "title": "Finding 1",
                            "description": "eval",
                            "reasoning": "x",
                            "confidence": "low",
                            "verified": True,
                        },
                        {
                            "type": "code_injection",
                            "severity": "high",
                            "file_path": file_path,
                            "line_number": 1,
                            "title": "Finding 2",
                            "description": "also eval",
                            "reasoning": "y",
                            "confidence": "low",
                            "verified": True,
                        },
                    ],
                },
            )
            agent._apply_sast(response, {"project_path": ""})
            for f in response.output["findings"]:
                assert "SAST:" in f["evidence"]

    def test_file_not_found_skips_gracefully(self) -> None:
        agent = self.make_agent()
        response = AgentResponse(
            content="verified",
            output={
                "findings": [
                    {
                        "type": "code_injection",
                        "severity": "high",
                        "file_path": "/nonexistent/path.py",
                        "line_number": 1,
                        "title": "Test",
                        "description": "test",
                        "reasoning": "test",
                        "confidence": "medium",
                        "verified": True,
                    },
                ],
            },
        )
        # Should not raise
        agent._apply_sast(response, {"project_path": ""})
        f = response.output["findings"][0]
        assert "evidence" not in f or not f["evidence"]

    def test_existing_evidence_not_overwritten(self) -> None:
        """SAST evidence should be appended to existing evidence."""
        agent = self.make_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = _write_py(tmpdir, "app.py", 'eval(user_input)')
            response = AgentResponse(
                content="verified",
                output={
                    "findings": [
                        {
                            "type": "code_injection",
                            "severity": "high",
                            "file_path": file_path,
                            "line_number": 1,
                            "title": "CI",
                            "description": "eval",
                            "reasoning": "found",
                            "confidence": "medium",
                            "verified": True,
                            "evidence": "Manual analysis confirms",
                        },
                    ],
                },
            )
            agent._apply_sast(response, {"project_path": ""})
            f = response.output["findings"][0]
            assert "Manual analysis confirms" in f["evidence"]
            assert "SAST:" in f["evidence"]


# ---------------------------------------------------------------------------
# VerificationAgent SAST integration
# ---------------------------------------------------------------------------


class TestVerificationAgentSast:
    """_apply_sast on VerificationAgent — works on top-level output fields."""

    def test_tags_evidence_on_triggerable(self) -> None:
        from agies.engine.agents.verification_agent import VerificationAgent

        agent = VerificationAgent()
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = _write_py(tmpdir, "app.py", 'eval(user_input)')
            response = AgentResponse(
                content="verified",
                output={
                    "triggerable": True,
                    "conditions": "User input reaches eval()",
                    "false_positive_reason": "",
                    "confidence": "medium",
                    "evidence": [],
                },
            )
            agent._apply_sast(response, {"candidate": type("C", (), {"file_path": file_path})()})
            assert len(response.output["evidence"]) > 0
            assert any("SAST:" in e for e in response.output["evidence"])

    def test_boosts_confidence_on_match(self) -> None:
        from agies.engine.agents.verification_agent import VerificationAgent

        agent = VerificationAgent()
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = _write_py(tmpdir, "app.py", 'eval(user_input)')
            response = AgentResponse(
                content="verified",
                output={
                    "triggerable": True,
                    "conditions": "",
                    "false_positive_reason": "",
                    "confidence": "medium",
                    "evidence": [],
                },
            )
            agent._apply_sast(response, {"candidate": type("C", (), {"file_path": file_path})()})
            assert response.output["confidence"] == "high"

    def test_no_candidate_noop(self) -> None:
        from agies.engine.agents.verification_agent import VerificationAgent

        agent = VerificationAgent()
        response = AgentResponse(
            content="verified",
            output={
                "triggerable": False,
                "conditions": "",
                "false_positive_reason": "No candidate",
                "confidence": "low",
                "evidence": [],
            },
        )
        agent._apply_sast(response, {})
        assert response.output["evidence"] == []

    def test_no_match_unchanged(self) -> None:
        from agies.engine.agents.verification_agent import VerificationAgent

        agent = VerificationAgent()
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = _write_py(tmpdir, "safe.py", "x = 1")
            response = AgentResponse(
                content="verified",
                output={
                    "triggerable": False,
                    "conditions": "",
                    "false_positive_reason": "Safe code",
                    "confidence": "low",
                    "evidence": [],
                },
            )
            agent._apply_sast(response, {"candidate": type("C", (), {"file_path": file_path})()})
            assert response.output["evidence"] == []
            assert response.output["confidence"] == "low"

    def test_relative_path_resolved(self) -> None:
        from agies.engine.agents.verification_agent import VerificationAgent

        agent = VerificationAgent()
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = _write_py(tmpdir, "sub/vuln.py", 'eval(user_input)')
            candidate = type("C", (), {"file_path": "sub/vuln.py"})()
            response = AgentResponse(
                content="verified",
                output={
                    "triggerable": True,
                    "conditions": "",
                    "false_positive_reason": "",
                    "confidence": "medium",
                    "evidence": [],
                },
            )
            agent._apply_sast(response, {"candidate": candidate, "project_path": tmpdir})
            assert any("SAST:" in e for e in response.output["evidence"])

    def test_file_not_found_skips(self) -> None:
        from agies.engine.agents.verification_agent import VerificationAgent

        agent = VerificationAgent()
        candidate = type("C", (), {"file_path": "/nonexistent/vuln.py"})()
        response = AgentResponse(
            content="verified",
            output={
                "triggerable": True,
                "conditions": "",
                "false_positive_reason": "",
                "confidence": "medium",
                "evidence": [],
            },
        )
        agent._apply_sast(response, {"candidate": candidate})
        assert response.output["evidence"] == []


# ---------------------------------------------------------------------------
# Standalone SAST matcher integration
# ---------------------------------------------------------------------------


class TestSastMatcherIntegration:
    """End-to-end SAST matching with real YAML rules."""

    def test_py_subprocess_shell_matches(self) -> None:
        matcher = get_matcher()
        source = 'import subprocess\nsubprocess.Popen("ls", shell=True)'
        results = matcher.match_source(source, "python")
        rule_ids = {r.rule_id for r in results}
        assert "py-subprocess-shell" in rule_ids

    def test_py_eval_exec_matches(self) -> None:
        matcher = get_matcher()
        results = matcher.match_source('eval(user_input)', "python")
        rule_ids = {r.rule_id for r in results}
        assert "py-eval-exec" in rule_ids

    def test_py_eval_exec_with_exec(self) -> None:
        matcher = get_matcher()
        results = matcher.match_source('exec(code_string)', "python")
        rule_ids = {r.rule_id for r in results}
        assert "py-eval-exec" in rule_ids

    def test_clean_code_no_matches(self) -> None:
        matcher = get_matcher()
        results = matcher.match_source('x = 1 + 1\nprint(x)', "python")
        assert len(results) == 0

    def test_pickle_unsafe_matches(self) -> None:
        matcher = get_matcher()
        results = matcher.match_source('pickle.loads(data)', "python")
        rule_ids = {r.rule_id for r in results}
        assert "py-pickle-unsafe" in rule_ids

    def test_yaml_unsafe_matches(self) -> None:
        matcher = get_matcher()
        results = matcher.match_source('yaml.load(data)', "python")
        rule_ids = {r.rule_id for r in results}
        assert "py-yaml-unsafe" in rule_ids

    def test_file_matching_returns_correct_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = _write_py(tmpdir, "vuln.py", 'eval(user_input)')
            matcher = get_matcher()
            results = matcher.match_file(file_path)
            assert len(results) > 0
            assert results[0].file_path == file_path
