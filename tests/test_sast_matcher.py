"""Tests for agies.engine.sast — SAST pattern matching engine."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from agies.engine.sast import MatchResult, SASTRule, confidence_from_severity
from agies.engine.sast.matcher import (
    SASTMatcher,
    load_rules_from_dir,
    _ext_to_lang,
)

# ---------------------------------------------------------------------------
# Helper: rule factory
# ---------------------------------------------------------------------------


def _rule(**overrides: object) -> SASTRule:
    defaults: dict = {
        "id": "test-rule",
        "name": "Test Rule",
        "language": "python",
        "severity": "high",
        "query": "(call function: (identifier) @match)",
        "capture_group": "match",
    }
    defaults.update(overrides)
    return SASTRule(**defaults)


def _write_py(tmpdir: str, name: str, code: str) -> str:
    p = Path(tmpdir) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code)
    return str(p)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestExtToLang:
    def test_python(self) -> None:
        assert _ext_to_lang("app.py") == "python"
        assert _ext_to_lang("/path/to/module.py") == "python"

    def test_java(self) -> None:
        assert _ext_to_lang("Main.java") == "java"

    def test_javascript(self) -> None:
        assert _ext_to_lang("app.js") == "javascript"

    def test_typescript(self) -> None:
        assert _ext_to_lang("component.ts") == "typescript"

    def test_unknown_returns_empty(self) -> None:
        assert _ext_to_lang("file.rb") == ""


class TestSASTRule:
    def test_mutual_cwe_invalid(self) -> None:
        rule = SASTRule(id="r1", name="", language="python", query="() @match")
        assert rule.cwe == []


class TestConfidenceFromSeverity:
    def test_critical_to_high(self) -> None:
        assert confidence_from_severity("critical") == "high"

    def test_high_to_high(self) -> None:
        assert confidence_from_severity("high") == "high"

    def test_medium_to_medium(self) -> None:
        assert confidence_from_severity("medium") == "medium"

    def test_unknown_fallback(self) -> None:
        assert confidence_from_severity("unknown") == "medium"


class TestMatchFunctionCall:
    """Match function calls by name."""

    def test_eval_match(self) -> None:
        matcher = SASTMatcher(rules=[
            _rule(
                id="py-eval-test",
                name="eval test",
                query="(call function: (identifier) @match)",
                match_any=["eval"],
            ),
        ])
        results = matcher.match_source('eval(user_input)', "python")
        assert len(results) == 1
        assert results[0].rule_id == "py-eval-test"
        assert results[0].matched_text == "eval"

    def test_exec_match(self) -> None:
        matcher = SASTMatcher(rules=[
            _rule(
                id="py-eval-test",
                query="(call function: (identifier) @match)",
                match_any=["eval", "exec"],
            ),
        ])
        results = matcher.match_source('exec("dangerous")', "python")
        assert len(results) == 1
        assert results[0].matched_text == "exec"

    def test_no_match_when_safe(self) -> None:
        matcher = SASTMatcher(rules=[
            _rule(
                id="py-eval-test",
                query="(call function: (identifier) @match)",
                match_any=["eval"],
            ),
        ])
        results = matcher.match_source('safe_function(x)', "python")
        assert len(results) == 0

    def test_capture_group_filters(self) -> None:
        """Only the named capture group is used for match."""
        matcher = SASTMatcher(rules=[
            _rule(
                id="py-exec-call",
                query="""
                (call
                  function: (identifier) @match
                  arguments: (argument_list) @args
                )
                """,
                capture_group="match",
                match_any=["exec"],
            ),
        ])
        results = matcher.match_source('exec(code)', "python")
        assert len(results) == 1
        assert results[0].rule_id == "py-exec-call"

    def test_multiple_matches_in_one_file(self) -> None:
        matcher = SASTMatcher(rules=[
            _rule(
                id="py-eval-test",
                query="(call function: (identifier) @match)",
                match_any=["eval"],
            ),
        ])
        results = matcher.match_source(
            'a = eval(x)\nb = eval(y)', "python"
        )
        assert len(results) == 2


class TestMatchFile:
    def test_match_python_file(self) -> None:
        matcher = SASTMatcher(rules=[
            _rule(
                id="py-eval-test",
                query="(call function: (identifier) @match)",
                match_any=["eval"],
            ),
        ])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_py(tmpdir, "test.py", "eval(x)")
            results = matcher.match_file(path)
            assert len(results) == 1
            assert results[0].file_path == path

    def test_unsupported_language_returns_empty(self) -> None:
        matcher = SASTMatcher()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_py(tmpdir, "test.rb", "eval(x)")
            results = matcher.match_file(path)
            assert results == []


class TestMatchSource:
    def test_empty_source(self) -> None:
        matcher = SASTMatcher(rules=[
            _rule(id="py-eval", query="(call function: (identifier) @match)", match_any=["eval"]),
        ])
        results = matcher.match_source("", "python")
        assert results == []

    def test_wrong_language(self) -> None:
        matcher = SASTMatcher(rules=[
            _rule(id="py-eval", query="(call function: (identifier) @match)", match_any=["eval"]),
        ])
        results = matcher.match_source("eval(x)", "java")
        assert results == []


class TestLoadRulesFromDir:
    def test_load_yaml_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = Path(tmpdir) / "python"
            rules_dir.mkdir()
            (rules_dir / "test-rule.yaml").write_text(
                'id: test-rule\nname: "Test"\nlanguage: python\nquery: "() @match"\n'
            )
            rules = load_rules_from_dir(tmpdir)
            assert len(rules) == 1
            assert rules[0].id == "test-rule"

    def test_nonexistent_dir_returns_empty(self) -> None:
        rules = load_rules_from_dir("/nonexistent/path")
        assert rules == []

    def test_skip_invalid_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "bad.yaml").write_text("{invalid: yaml: unclosed")
            rules = load_rules_from_dir(tmpdir)
            assert rules == []


class TestSubprocessShellRule:
    """Specific test for the shell=True rule."""

    def test_shell_true_detected(self) -> None:
        query = """
        (call
          function: (attribute
            object: (identifier) @module
            attribute: (identifier) @func
          )
          arguments: (argument_list
            (keyword_argument
              name: (identifier) @kw
              (#eq? @kw "shell")
              value: (true) @shell_value
            )
          )
        )
        """
        matcher = SASTMatcher(rules=[
            _rule(
                id="py-subprocess-shell",
                query=query,
                capture_group="func",
                match_any=["Popen", "call", "run"],
            ),
        ])
        source = 'subprocess.Popen("ls", shell=True)'
        results = matcher.match_source(source, "python")
        assert len(results) == 1
        assert results[0].rule_id == "py-subprocess-shell"

    def test_no_shell_false(self) -> None:
        query = """
        (call
          function: (attribute
            object: (identifier) @module
            attribute: (identifier) @func
          )
          arguments: (argument_list
            (keyword_argument
              name: (identifier) @kw
              (#eq? @kw "shell")
              value: (true) @shell_value
            )
          )
        )
        """
        matcher = SASTMatcher(rules=[
            _rule(
                id="py-subprocess-shell",
                query=query,
                capture_group="module",
                match_any=["Popen", "call", "run"],
            ),
        ])
        # No shell=True → no match
        results = matcher.match_source(
            'subprocess.run(["ls"], shell=False)', "python"
        )
        assert len(results) == 0


class TestConfidenceScoring:
    """Tag format for verification integration."""

    def test_tag_format(self) -> None:
        result = MatchResult(
            rule_id="py-eval",
            rule_name="eval test",
            severity="critical",
            language="python",
            file_path="test.py",
            line_number=1,
        )
        tag = f"[SAST:{result.rule_id}]"
        assert tag == "[SAST:py-eval]"

    def test_evidence_line(self) -> None:
        result = MatchResult(
            rule_id="py-eval",
            rule_name="eval test",
            severity="high",
            language="python",
            file_path="src/app.py",
            line_number=42,
            matched_text="eval",
            message="eval is dangerous",
        )
        line = (
            f"SAST pattern matched: {result.rule_name} "
            f"(severity={result.severity}, line={result.line_number})"
        )
        assert "SAST pattern matched" in line
        assert "high" in line
