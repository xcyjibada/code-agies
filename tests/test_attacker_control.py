"""Tests for Phase 2: attacker control verification pipeline."""

from __future__ import annotations

import os
import tempfile

from agies.verification.attacker_control import (
    AttackerControlVerifier,
    ExecutionContextValidator,
    ExternalReachabilityValidator,
    SemanticPatternValidator,
    ThreadModelValidator,
    TrustBoundaryValidator,
    ValidationChainValidator,
)
from agies.verification.exploitability import assess_exploitability
from agies.verification.language_patterns import get_language_patterns
from agies.verification.language_patterns_java import JavaPatterns
from agies.verification.language_patterns_js import JavaScriptPatterns


# ── LanguagePatterns Tests ───────────────────────────────────────────────────


class TestPythonPatterns:
    def test_is_test_code_by_path(self):
        patterns = get_language_patterns("python", "/tmp")
        assert patterns.is_test_code("/tmp/tests/test_foo.py", "")
        assert patterns.is_test_code("/tmp/test_foo.py", "")
        assert patterns.is_test_code("/tmp/foo_test.py", "")

    def test_is_test_code_by_import(self):
        patterns = get_language_patterns("python", "/tmp")
        content = "import pytest\n\ndef test_foo():\n    pass\n"
        assert patterns.is_test_code("/tmp/foo.py", content)

    def test_is_not_test_code(self):
        patterns = get_language_patterns("python", "/tmp")
        content = "def foo():\n    return 42\n"
        assert not patterns.is_test_code("/tmp/prod/foo.py", content)

    def test_is_compiler_code(self):
        patterns = get_language_patterns("python", "/tmp")
        assert patterns.is_compiler_code("/tmp/setup.py", "")

    def test_user_input_apis(self):
        patterns = get_language_patterns("python", "/tmp")
        apis = patterns.get_user_input_entry_points()
        assert "sys.argv" in apis
        assert "flask.request" in apis
        assert "os.environ" in apis

    def test_external_entry_points(self):
        patterns = get_language_patterns("python", "/tmp")
        eps = patterns.get_external_entry_points()
        assert "@app.route" in eps
        assert "def main(" in eps

    def test_validation_functions(self):
        patterns = get_language_patterns("python", "/tmp")
        vfns = patterns.get_validation_functions()
        assert "validate" in vfns
        assert "sanitize" in vfns
        assert "bleach.clean" in vfns


class TestJavaPatterns:
    def test_is_test_code_by_path(self):
        patterns = JavaPatterns("/tmp")
        assert patterns.is_test_code("/tmp/src/test/java/com/example/UserTest.java", "")
        assert patterns.is_test_code("/tmp/UserServiceTest.java", "")

    def test_is_test_code_by_annotation(self):
        patterns = JavaPatterns("/tmp")
        content = 'import org.junit.jupiter.api.Test;\n\nclass Foo {\n    @Test\n    void testBar() {}\n}'
        assert patterns.is_test_code("/tmp/Foo.java", content)

    def test_is_not_test_code(self):
        patterns = JavaPatterns("/tmp")
        content = "package com.example;\n\npublic class UserService {}\n"
        assert not patterns.is_test_code("/tmp/src/main/java/UserService.java", content)

    def test_is_startup_code(self):
        patterns = JavaPatterns("/tmp")
        assert patterns.is_startup_code("/tmp/Application.java", "")

    def test_user_input_apis(self):
        patterns = JavaPatterns("/tmp")
        apis = patterns.get_user_input_entry_points()
        assert "@RequestParam" in apis
        assert "@RequestBody" in apis
        assert "HttpServletRequest" in apis
        assert "request.getParameter" in apis

    def test_external_entry_points(self):
        patterns = JavaPatterns("/tmp")
        eps = patterns.get_external_entry_points()
        assert "@RequestMapping" in eps
        assert "@GetMapping" in eps
        assert "@PostMapping" in eps

    def test_validation_functions(self):
        patterns = JavaPatterns("/tmp")
        vfns = patterns.get_validation_functions()
        assert "@Valid" in vfns
        assert "@NotNull" in vfns
        assert "ESAPI.validator" in vfns


class TestJavaScriptPatterns:
    def test_is_test_code_by_path(self):
        patterns = JavaScriptPatterns("/tmp")
        assert patterns.is_test_code("/tmp/app.test.js", "")
        assert patterns.is_test_code("/tmp/app.spec.ts", "")

    def test_is_test_code_by_function(self):
        patterns = JavaScriptPatterns("/tmp")
        content = 'describe("foo", () => {\n  it("should work", () => {\n    expect(1).toBe(1)\n  })\n})'
        assert patterns.is_test_code("/tmp/app.js", content)

    def test_is_not_test_code(self):
        patterns = JavaScriptPatterns("/tmp")
        content = "const express = require('express');\nconst app = express();\n"
        assert not patterns.is_test_code("/tmp/server.js", content)

    def test_is_startup_code(self):
        patterns = JavaScriptPatterns("/tmp")
        assert patterns.is_startup_code("/tmp/server.js", "app.listen(3000)")
        assert patterns.is_startup_code("/tmp/index.js", "")

    def test_user_input_apis(self):
        patterns = JavaScriptPatterns("/tmp")
        apis = patterns.get_user_input_entry_points()
        assert "req.query" in apis
        assert "req.body" in apis
        assert "process.argv" in apis

    def test_external_entry_points(self):
        patterns = JavaScriptPatterns("/tmp")
        eps = patterns.get_external_entry_points()
        assert "app.get(" in eps
        assert "app.post(" in eps
        assert "router.get(" in eps

    def test_validation_functions(self):
        patterns = JavaScriptPatterns("/tmp")
        vfns = patterns.get_validation_functions()
        assert "Joi.object(" in vfns
        assert "z.object(" in vfns
        assert "sanitizeHtml" in vfns


# ── Validator Tests ──────────────────────────────────────────────────────────


class TestExecutionContextValidator:
    def setup_method(self):
        self.patterns = get_language_patterns("python", "/tmp")
        self.validator = ExecutionContextValidator(self.patterns)

    def test_no_file_path(self):
        result = self.validator.check({"file_path": ""})
        assert not result.passed
        assert result.blocking

    def test_test_code_blocks(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import pytest\n\ndef test_foo():\n    pass\n")
            fpath = f.name
        try:
            result = self.validator.check({"file_path": fpath})
            assert not result.passed
            assert result.blocking
            assert "test" in result.detail.lower()
        finally:
            os.unlink(fpath)

    def test_normal_code_passes(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("def handle(request):\n    return do_stuff(request)\n")
            fpath = f.name
        try:
            result = self.validator.check({"file_path": fpath})
            assert result.passed
        finally:
            os.unlink(fpath)


class TestTrustBoundaryValidator:
    def setup_method(self):
        self.patterns = get_language_patterns("python", "/tmp")
        self.validator = TrustBoundaryValidator(self.patterns)

    def test_detects_source_name(self):
        result = self.validator.check({
            "source_rule_name": "flask.request",
            "file_path": "",
        })
        assert result.passed

    def test_detects_source_info(self):
        result = self.validator.check({
            "source_info": "request.GET",
            "file_path": "",
        })
        assert result.passed

    def test_detects_taint_path(self):
        result = self.validator.check({
            "file_path": "",
            "taint_path": {"source": "request.GET['id']", "sink": "execute()"},
        })
        assert result.passed

    def test_no_boundary(self):
        result = self.validator.check({
            "source_rule_name": "",
            "source_info": "",
            "detail": "",
            "file_path": "",
        })
        assert not result.passed

    def test_detects_entry_point_in_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("@app.route('/api/users')\ndef get_users():\n    pass\n")
            fpath = f.name
        try:
            result = self.validator.check({
                "source_info": "",
                "source_rule_name": "",
                "file_path": fpath,
                "detail": "",
            })
            assert result.passed
        finally:
            os.unlink(fpath)


class TestExternalReachabilityValidator:
    def setup_method(self):
        self.patterns = get_language_patterns("python", "/tmp")
        self.validator = ExternalReachabilityValidator(self.patterns)

    def test_taint_path_indicates_reachability(self):
        result = self.validator.check({
            "taint_path": {"source": "x", "sink": "y"},
            "description": "",
        })
        assert result.passed

    def test_description_with_entry_point(self):
        result = self.validator.check({
            "description": "Found in @app.route('/api/users') handler",
            "taint_path": {},
        })
        assert result.passed

    def test_no_reachability(self):
        result = self.validator.check({
            "description": "Internal utility function",
            "taint_path": {},
            "file_path": "",
        })
        assert not result.passed

    def test_call_chain_indicates_reachability(self):
        result = self.validator.check({
            "description": "",
            "taint_path": {},
            "file_path": "",
            "call_chain": ["handler()", "process()", "sink()"],
        })
        assert result.passed


class TestValidationChainValidator:
    def setup_method(self):
        self.patterns = get_language_patterns("python", "/tmp")
        self.validator = ValidationChainValidator(self.patterns)

    def test_detects_validation_near_line(self):
        content = "\n" * 18 + "def validate_input(data):\n    return data\n" + "\n" * 5 + "result = execute(query)\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            fpath = f.name
        try:
            result = self.validator.check({
                "file_path": fpath,
                "line_number": 25,
                "description": "",
            })
            assert result.passed
        finally:
            os.unlink(fpath)

    def test_no_validation_detected(self):
        result = self.validator.check({
            "file_path": "",
            "line_number": 0,
            "description": "plain sql injection",
            "suggestion": "",
        })
        assert not result.passed

    def test_validation_in_description(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("x = 1\n")
            fpath = f.name
        try:
            result = self.validator.check({
                "file_path": fpath,
                "line_number": 1,
                "description": "Input not sanitized by bleach.clean",
                "suggestion": "",
            })
            assert result.passed
        finally:
            os.unlink(fpath)


class TestThreadModelValidator:
    def setup_method(self):
        self.patterns = get_language_patterns("python", "/tmp")
        self.validator = ThreadModelValidator(self.patterns)

    def test_authenticated_precondition(self):
        result = self.validator.check({
            "description": "Authenticated users can trigger XSS",
        })
        assert not result.passed  # precondition = less exploitable
        assert "authenticated" in result.detail

    def test_unauthenticated_access(self):
        result = self.validator.check({
            "description": "Unauthenticated public endpoint",
        })
        assert result.passed

    def test_no_preconditions(self):
        result = self.validator.check({
            "description": "Arbitrary command injection",
        })
        assert result.passed

    def test_admin_required(self):
        result = self.validator.check({
            "description": "Admin users only",
        })
        assert not result.passed
        assert "admin" in result.detail


class TestSemanticPatternValidator:
    def setup_method(self):
        self.patterns = get_language_patterns("python", "/tmp")
        self.validator = SemanticPatternValidator(self.patterns)

    def test_sql_injection_matches(self):
        result = self.validator.check({
            "rule_id": "sql-injection",
            "description": "SELECT * FROM users WHERE id = ?",
        })
        assert result.passed

    def test_xss_matches(self):
        result = self.validator.check({
            "rule_id": "reflective-xss",
            "description": "Unescaped innerHTML assignment",
        })
        assert result.passed

    def test_no_match(self):
        result = self.validator.check({
            "rule_id": "sql-injection",
            "description": "Just some random code",
        })
        assert not result.passed

    def test_unknown_rule_passes_gracefully(self):
        result = self.validator.check({
            "rule_id": "custom-injection",
            "description": "Some description",
        })
        assert result.passed  # No semantic check defined = pass


# ── End-to-End Verifier Tests ────────────────────────────────────────────────


class TestAttackerControlVerifier:
    def test_controllable_finding(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("def handle(request):\n    return execute(request.GET['id'])\n")
            fpath = f.name
        try:
            verifier = AttackerControlVerifier("/tmp")
            result = verifier.verify({
                "file_path": fpath,
                "source_info": "request.GET",
                "language": "python",
                "rule_id": "sql-injection",
                "description": "SELECT * FROM users",
            })
            assert result.is_controlled, f"Expected controllable, got: {result.blocking_reason}"
            assert result.exploitability_score > 0.5
            assert len(result.dimension_results) == 6
        finally:
            os.unlink(fpath)

    def test_blocked_test_code(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import pytest\n\ndef test_sql():\n    execute('SELECT * FROM users')\n")
            fpath = f.name
        try:
            verifier = AttackerControlVerifier("/tmp")
            result = verifier.verify({
                "file_path": fpath,
                "language": "python",
                "rule_id": "sql-injection",
                "description": "SELECT in test",
                "source_info": "",
            })
            assert not result.is_controlled
            assert "test" in result.blocking_reason.lower()
            # Score should be low due to P0 block
            assert result.exploitability_score < 0.6
        finally:
            os.unlink(fpath)

    def test_all_dimensions_recorded(self):
        verifier = AttackerControlVerifier("/tmp")
        result = verifier.verify({
            "file_path": "",
            "language": "python",
            "rule_id": "unknown-rule",
            "description": "test",
            "source_info": "",
        })
        assert len(result.dimension_results) == 6
        names = [r.name for r in result.dimension_results]
        assert "execution_context" in names
        assert "trust_boundary" in names
        assert "external_reachability" in names
        assert "validation_chain" in names
        assert "thread_model" in names
        assert "semantic_pattern" in names


# ── Exploitability Assessment Tests ──────────────────────────────────────────


class TestExploitability:
    def test_high_exploitability(self):
        from agies.verification.attacker_control import AttackerControlResult, ValidatorResult

        ac_result = AttackerControlResult(
            is_controlled=True,
            exploitability_score=0.85,
            dimension_results=[
                ValidatorResult(name="execution_context", passed=True, priority="P0"),
                ValidatorResult(name="trust_boundary", passed=True, priority="P0"),
                ValidatorResult(name="external_reachability", passed=True, priority="P0"),
                ValidatorResult(name="validation_chain", passed=False, priority="P1"),
                ValidatorResult(name="thread_model", passed=True, priority="P1"),
                ValidatorResult(name="semantic_pattern", passed=True, priority="P1"),
            ],
        )
        assessment = assess_exploitability(ac_result, {"severity": "critical"})
        assert assessment.rating in ("critical", "high")

    def test_low_exploitability(self):
        from agies.verification.attacker_control import AttackerControlResult, ValidatorResult

        ac_result = AttackerControlResult(
            is_controlled=False,
            blocking_reason="finding is in test code",
            exploitability_score=0.2,
            dimension_results=[
                ValidatorResult(name="execution_context", passed=False, priority="P0", detail="test code"),
                ValidatorResult(name="trust_boundary", passed=False, priority="P0"),
                ValidatorResult(name="external_reachability", passed=False, priority="P0"),
                ValidatorResult(name="validation_chain", passed=False, priority="P1"),
                ValidatorResult(name="thread_model", passed=True, priority="P1"),
                ValidatorResult(name="semantic_pattern", passed=False, priority="P1"),
            ],
        )
        assessment = assess_exploitability(ac_result, {"severity": "info"})
        assert assessment.p0_blocked
        assert assessment.rating in ("none", "low")

    def test_severity_adjustment(self):
        from agies.verification.attacker_control import AttackerControlResult, ValidatorResult

        base_dims = [
            ValidatorResult(name="execution_context", passed=True, priority="P0"),
            ValidatorResult(name="trust_boundary", passed=True, priority="P0"),
            ValidatorResult(name="external_reachability", passed=True, priority="P0"),
            ValidatorResult(name="validation_chain", passed=False, priority="P1"),
            ValidatorResult(name="thread_model", passed=False, priority="P1"),
            ValidatorResult(name="semantic_pattern", passed=True, priority="P1"),
        ]
        ac = AttackerControlResult(is_controlled=True, exploitability_score=0.7, dimension_results=base_dims)

        critical = assess_exploitability(ac, {"severity": "critical"})
        low = assess_exploitability(ac, {"severity": "low"})
        assert critical.severity_adjusted_score >= low.severity_adjusted_score
