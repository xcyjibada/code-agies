"""Attacker control verification — language-agnostic 6-dimension pipeline.

Validates whether a vulnerability is attacker-controllable by checking:
  P0 (blocking): execution_context, trust_boundary, external_reachability
  P1 (scoring):  validation_chain, thread_model, semantic_pattern

Each validator uses LanguagePatterns for language-specific queries,
making the pipeline cross-language without per-language branching.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from agies.verification.language_patterns import LanguagePatterns, get_language_patterns


@dataclass
class ValidatorResult:
    """Result from a single validator dimension."""
    name: str
    passed: bool
    priority: str  # "P0" or "P1"
    detail: str = ""
    blocking: bool = True  # P0 = blocking, P1 = non-blocking

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "passed": self.passed,
            "priority": self.priority,
            "detail": self.detail,
        }


@dataclass
class AttackerControlResult:
    """Overall result from the attacker control verification."""
    is_controlled: bool = True
    blocking_reason: str = ""
    dimension_results: list[ValidatorResult] = field(default_factory=list)
    exploitability_score: float = 1.0

    def to_dict(self) -> dict:
        return {
            "is_controlled": self.is_controlled,
            "blocking_reason": self.blocking_reason,
            "exploitability_score": self.exploitability_score,
            "dimension_results": [
                {"name": r.name, "passed": r.passed, "priority": r.priority, "detail": r.detail}
                for r in self.dimension_results
            ],
        }


# ── P0 Validators ────────────────────────────────────────────────────────


class ExecutionContextValidator:
    """P0: Is the code in a runtime-executable context?

    Checks if the finding's file is:
    - Test code       → blocked
    - Compiler code   → blocked
    - Startup-only    → downgraded (P1)
    """

    def __init__(self, patterns: LanguagePatterns) -> None:
        self.patterns = patterns

    def check(self, finding: dict) -> ValidatorResult:
        file_path = finding.get("file_path", "")
        if not file_path:
            return ValidatorResult(name="execution_context", passed=False, priority="P0",
                                   detail="no file path to check", blocking=True)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except (OSError, PermissionError):
            return ValidatorResult(name="execution_context", passed=False, priority="P0",
                                   detail=f"cannot read file: {file_path}", blocking=False)

        # P0-blocking checks
        if self.patterns.is_test_code(file_path, content):
            return ValidatorResult(name="execution_context", passed=False, priority="P0",
                                   detail="finding is in test code — not exploitable in production",
                                   blocking=True)

        if self.patterns.is_compiler_code(file_path, content):
            return ValidatorResult(name="execution_context", passed=False, priority="P0",
                                   detail="finding is in compiler/build code — not runtime executable",
                                   blocking=True)

        # P1-scoring check
        if self.patterns.is_startup_code(file_path, content):
            return ValidatorResult(name="execution_context", passed=False, priority="P1",
                                   detail="finding is in startup code — limited runtime exposure",
                                   blocking=False)

        return ValidatorResult(name="execution_context", passed=True, priority="P0",
                               detail="code is in runtime-executable context", blocking=True)


class TrustBoundaryValidator:
    """P0: Does data cross a trust boundary?

    Checks if the finding's data source is user-controllable
    (HTTP request, file upload, environment, etc.)
    """

    def __init__(self, patterns: LanguagePatterns) -> None:
        self.patterns = patterns

    def check(self, finding: dict) -> ValidatorResult:
        source_info = finding.get("source_info", "")
        source_name = finding.get("source_rule_name", "")
        detail = finding.get("detail", "") or finding.get("description", "")

        input_apis = self.patterns.get_user_input_entry_points()
        entry_points = self.patterns.get_external_entry_points()

        # Check if the source name matches an input API
        for api in input_apis:
            if api in source_name or api in source_info or api in detail:
                return ValidatorResult(name="trust_boundary", passed=True, priority="P0",
                                       detail=f"data originates from user input API: {api}",
                                       blocking=True)

        # Check if it's behind an external entry point
        for ep in entry_points:
            if ep in source_info or ep in detail:
                return ValidatorResult(name="trust_boundary", passed=True, priority="P0",
                                       detail=f"data flows from external entry point: {ep}",
                                       blocking=True)

        # Try to read the file and detect entry points
        file_path = finding.get("file_path", "")
        if file_path and os.path.isfile(file_path):
            try:
                with open(file_path, "r") as f:
                    content = f.read()
                for ep in entry_points:
                    if ep in content:
                        return ValidatorResult(name="trust_boundary", passed=True, priority="P0",
                                               detail=f"file contains external entry point: {ep}",
                                               blocking=True)
            except (OSError, PermissionError):
                pass

        # If it's a taint-based finding with a trace, it already crossed a boundary
        taint_path = finding.get("taint_path", {}) or {}
        if taint_path.get("source"):
            return ValidatorResult(name="trust_boundary", passed=True, priority="P0",
                                   detail="taint analysis confirms data crosses trust boundary",
                                   blocking=True)

        return ValidatorResult(name="trust_boundary", passed=False, priority="P0",
                               detail="no clear trust boundary crossing detected — may not be user-controllable",
                               blocking=True)


class ExternalReachabilityValidator:
    """P0: Is the vulnerable code path externally reachable?

    Checks if the vulnerability can be triggered from outside
    (HTTP endpoint, message queue, CLI, etc.)
    """

    def __init__(self, patterns: LanguagePatterns) -> None:
        self.patterns = patterns

    def check(self, finding: dict) -> ValidatorResult:
        file_path = finding.get("file_path", "")
        description = finding.get("description", "") or ""
        detail = finding.get("detail", "") or ""

        # If finding has a taint path, it's reachable by definition
        taint_path = finding.get("taint_path", {}) or {}
        if taint_path.get("sink") and taint_path.get("source"):
            return ValidatorResult(name="external_reachability", passed=True, priority="P0",
                                   detail="taint path confirms external reachability",
                                   blocking=True)

        entry_points = self.patterns.get_external_entry_points()

        # Check description for entry point mentions
        combined = description + " " + detail
        for ep in entry_points:
            if ep in combined:
                return ValidatorResult(name="external_reachability", passed=True, priority="P0",
                                       detail=f"external entry point identified: {ep}",
                                       blocking=True)

        # Check the actual file
        if file_path and os.path.isfile(file_path):
            try:
                with open(file_path, "r") as f:
                    content = f.read()
                for ep in entry_points:
                    if ep in content:
                        return ValidatorResult(name="external_reachability", passed=True, priority="P0",
                                               detail=f"file declares external handler: {ep}",
                                               blocking=True)
            except (OSError, PermissionError):
                pass

        # Check call chain
        call_chain = finding.get("call_chain", [])
        if call_chain:
            return ValidatorResult(name="external_reachability", passed=True, priority="P0",
                                   detail=f"call chain ({len(call_chain)} steps) indicates reachable path",
                                   blocking=True)

        return ValidatorResult(name="external_reachability", passed=False, priority="P0",
                               detail="no external reachability path identified",
                               blocking=True)


# ── P1 Validators ────────────────────────────────────────────────────────


class ValidationChainValidator:
    """P1: Is there input validation before the sink?

    Checks if user input passes through validation/sanitization
    before reaching the vulnerable code path.
    """

    def __init__(self, patterns: LanguagePatterns) -> None:
        self.patterns = patterns

    def check(self, finding: dict, code_context: str = "") -> ValidatorResult:
        validation_fns = self.patterns.get_validation_functions()
        description = finding.get("description", "") or ""
        detail = finding.get("detail", "") or ""
        suggestion = finding.get("suggestion", "") or ""
        content = code_context or ""

        # Read the file if no context provided
        if not content:
            file_path = finding.get("file_path", "")
            if file_path and os.path.isfile(file_path):
                try:
                    with open(file_path, "r") as f:
                        content = f.read()
                except (OSError, PermissionError):
                    pass

        # Check if finding suggests validation already exists
        if "validate" in suggestion.lower() or "sanitize" in suggestion.lower():
            pass  # The suggestion is recommending adding validation, meaning it's absent

        # Check for validation functions in the code context
        found_validations: list[str] = []
        for vfn in validation_fns:
            if vfn in content:
                # Check if it's used near the finding's line
                line = finding.get("line_number", 0)
                if isinstance(line, int) and line > 0:
                    lines = content.split("\n")
                    start = max(0, line - 20)
                    end = min(len(lines), line + 5)
                    nearby = "\n".join(lines[start:end])
                    if vfn in nearby:
                        found_validations.append(vfn)

        if found_validations:
            return ValidatorResult(name="validation_chain", passed=True, priority="P1",
                                   detail=f"input validation detected nearby: {', '.join(found_validations[:3])}",
                                   blocking=False)

        combined = description + detail
        for vfn in validation_fns:
            if vfn in combined:
                return ValidatorResult(name="validation_chain", passed=True, priority="P1",
                                       detail=f"known validation function referenced: {vfn}",
                                       blocking=False)

        return ValidatorResult(name="validation_chain", passed=False, priority="P1",
                               detail="no input validation detected in code path",
                               blocking=False)


class ThreadModelValidator:
    """P1: Does the vulnerability require preconditions?

    Checks if the exploit requires authentication, specific headers,
    user interaction, or other preconditions.
    """

    def __init__(self, patterns: LanguagePatterns) -> None:
        self.patterns = patterns

    def check(self, finding: dict) -> ValidatorResult:
        description = finding.get("description", "") or ""
        detail = finding.get("detail", "") or ""

        combined = description + " " + detail
        combined_lower = combined.lower()

        # Indicators that no preconditions are needed (raises exploitability)
        # Check these FIRST to avoid false positives (e.g. "unauthenticated" containing "authenticated")
        unauthenticated_signals = [
            "unauthenticated", "no auth", "public endpoint",
            "anonymous", "guest",
        ]
        for signal in unauthenticated_signals:
            if signal in combined_lower:
                return ValidatorResult(name="thread_model", passed=True, priority="P1",
                                       detail=f"no authentication precondition: {signal}",
                                       blocking=False)

        # Indicators that preconditions are required (lowers exploitability)
        precondition_signals = [
            "authenticated", "authentication required", "logged in",
            "admin", "administrator", "authorization",
            "csrf token", "xsrf token",
            "rate limited", "rate_limit",
            "user interaction", "user clicks",
        ]

        found_preconditions = [s for s in precondition_signals if s in combined_lower]
        if found_preconditions:
            return ValidatorResult(name="thread_model", passed=False, priority="P1",
                                   detail=f"preconditions required: {', '.join(found_preconditions[:3])}",
                                   blocking=False)

        return ValidatorResult(name="thread_model", passed=True, priority="P1",
                               detail="no preconditions identified (assumes unauthenticated access)",
                               blocking=False)


class SemanticPatternValidator:
    """P1: Does the code context match the vulnerability semantics?

    Validates that the code pattern actually matches the expected
    vulnerability type (e.g., SQL injection in a SQL context).
    """

    def __init__(self, patterns: LanguagePatterns) -> None:
        self.patterns = patterns

    def check(self, finding: dict) -> ValidatorResult:
        rule_id = finding.get("rule_id", "")
        description = finding.get("description", "") or ""

        # Rule-to-context mapping: each rule type expects certain code patterns
        rule_contexts = {
            "sql-injection": ["select", "insert", "update", "delete", "from", "where", "execute"],
            "os-command-injection": ["exec", "system", "popen", "subprocess", "shell", "cmd"],
            "xss": ["html", "innerhtml", "outerhtml", "append", "write", "render", "template"],
            "path-traversal": ["open", "read", "write", "file", "path", "directory"],
            "ssrf": ["url", "fetch", "request", "http", "connection", "open"],
            "code-injection": ["eval", "exec", "compile", "function", "invoke"],
            "unsafe-deserialization": ["pickle", "unserialize", "deserialize", "yaml", "xml"],
            "jndi-injection": ["lookup", "jndi", "ldap", "rmi"],
            "xxe": ["xml", "documentbuilder", "saxparser", "saxbuilder"],
        }

        # Normalize rule_id to look up context keywords
        normalized = rule_id.lower().replace("taint-to-", "").replace("python-", "").replace("reflective-", "")
        expected_keywords = rule_contexts.get(normalized, [])

        if not expected_keywords:
            return ValidatorResult(name="semantic_pattern", passed=True, priority="P1",
                                   detail=f"no semantic check defined for rule: {rule_id}",
                                   blocking=False)

        # Check description for context keywords
        desc_lower = description.lower()
        matches = [kw for kw in expected_keywords if kw in desc_lower]

        if matches:
            return ValidatorResult(name="semantic_pattern", passed=True, priority="P1",
                                   detail=f"code context matches vulnerability type: {', '.join(matches[:3])}",
                                   blocking=False)

        return ValidatorResult(name="semantic_pattern", passed=False, priority="P1",
                               detail=f"no context keywords ({', '.join(expected_keywords)}) found in description",
                               blocking=False)


# ── AttackerControlVerifier ──────────────────────────────────────────────


class AttackerControlVerifier:
    """Language-agnostic attacker control verification pipeline.

    Runs all 6 dimension validators and determines overall exploitability.
    P0 failures are blocking; P1 failures lower the confidence score.
    """

    VALIDATORS = [
        ("execution_context", ExecutionContextValidator),
        ("trust_boundary", TrustBoundaryValidator),
        ("external_reachability", ExternalReachabilityValidator),
        ("validation_chain", ValidationChainValidator),
        ("thread_model", ThreadModelValidator),
        ("semantic_pattern", SemanticPatternValidator),
    ]

    def __init__(self, target_root: str) -> None:
        self.target_root = target_root

    def verify(self, finding: dict, code_context: str = "") -> AttackerControlResult:
        """Run all validators on a single finding.

        Returns AttackerControlResult with is_controlled and dimension results.
        """
        lang = finding.get("language", "python")
        patterns = get_language_patterns(lang, self.target_root)

        result = AttackerControlResult()
        p0_passed = True
        p1_passed = 0
        p1_total = 0

        for name, validator_cls in self.VALIDATORS:
            validator = validator_cls(patterns)

            # validation_chain needs code context; others don't
            if name == "validation_chain":
                vr = validator.check(finding, code_context)
            else:
                vr = validator.check(finding)

            result.dimension_results.append(vr)

            if vr.priority == "P0":
                if not vr.passed:
                    if p0_passed:  # first P0 failure
                        result.blocking_reason = vr.detail
                    p0_passed = False
                    result.is_controlled = False
                    # Continue running remaining validators for full diagnostics
            else:  # P1
                p1_total += 1
                if vr.passed:
                    p1_passed += 1

        # Calculate exploitability score
        p0_weight = 0.6
        p1_ratio = p1_passed / max(p1_total, 1)
        score = p0_weight * (1.0 if p0_passed else 0.0) + 0.4 * p1_ratio
        result.exploitability_score = round(score, 2)

        return result
