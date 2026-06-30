"""Semantic Leaks — sensitive variable flow tracking across trust boundaries.

Detects cases where a sensitive-named variable (password, api_key, secret, token)
flows to an output/log context without dangerous API calls.  Traditional sink-based
analysis misses these because the "sink" is a legitimate API (jsonify, print, log).

Design
------
Phase 1: Scan function AST for sensitive variable definitions and usage.
Phase 2: Trace variable flow through assignments and transformations.
Phase 3: Flag boundary crossings (output, log, network, serialization).

This is NOT a full data-flow analysis — it's a heuristic scan that flags
likely-sensitive variables used in output contexts.  The LLM (Logic Agent)
validates the findings.
"""

from __future__ import annotations

import ast
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sensitive variable naming patterns
# ---------------------------------------------------------------------------

_LB = r"(?:\b|(?<=_)|(?<=(?-i:[a-z])))"  # leading: word boundary, underscore (snake_case), or CamelCase transition
_TB = r"(?=\b|(?-i:[A-Z_0-9]))"  # trailing: word boundary, uppercase (CamelCase), underscore, or digit

_SENSITIVE_VAR_PATTERNS: list[re.Pattern] = [
    re.compile(rf"(?i){_LB}(password|passwd|pwd|passwd_hash){_TB}"),
    re.compile(rf"(?i){_LB}(api_key|apikey|api_secret|api_token){_TB}"),
    re.compile(rf"(?i){_LB}(secret|secret_key|secret_access_key){_TB}"),
    re.compile(rf"(?i){_LB}(token|access_token|refresh_token|id_token|auth_token){_TB}"),
    re.compile(rf"(?i){_LB}(private_key|public_key|ssh_key|rsa_key|ssh_private_key){_TB}"),
    re.compile(rf"(?i){_LB}(session_id|session_key|csrf_token|nonce){_TB}"),
    re.compile(rf"(?i){_LB}(credential|ciphertext|encrypted|plaintext){_TB}"),
]

# Output/log context function calls that flag a boundary crossing
_OUTPUT_CONTEXTS: list[str] = [
    # Logging
    "logging.debug", "logging.info", "logging.warning", "logging.error",
    "logger.debug", "logger.info", "logger.warning", "logger.error",
    "print", "pprint",
    # HTTP response
    "jsonify", "json.dumps", "JsonResponse", "Response",
    "make_response", "HttpResponse", "JSONResponse",
    "return",  # special: track return statements with sensitive vars
    # Serialization / external
    "requests.post", "requests.get", "requests.put", "requests.patch",
    "urllib.request.urlopen", "urllib3",
    # Format strings
    "str.format", "%", "fstring",
]

_EXCLUDED_DIRS = ["/test", "/tests", "/__pycache__", "/.git", "/node_modules", "/venv"]


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class SensitiveVar:
    """A sensitive variable instance detected in source code."""

    name: str
    """Variable name (may include attribute chain, e.g. ``self.password``)."""

    file_path: str
    """Absolute file path."""

    line_number: int
    """Line where the variable is defined or first referenced."""

    match_pattern: str
    """Which sensitive pattern matched (e.g. ``password``, ``api_key``)."""

    context_hint: str = ""
    """How the variable is used — assignment, attribute, parameter, return, log."""


@dataclass
class LeakEvent:
    """A probable semantic leak — sensitive data crossing a trust boundary."""

    var: SensitiveVar
    """The sensitive variable involved."""

    function_name: str
    """Function where the leak occurs."""

    file_path: str
    """Source file."""

    line_number: int
    """Line of the leak."""

    context_code: str
    """Surrounding source code snippet (3 lines around)."""

    severity: str = "medium"
    """Estimated severity: high/medium/low."""

    leak_channel: str = ""
    """How the leak occurs: log, return, http_response, format_string, etc."""


@dataclass
class LeakScanResult:
    """Aggregated scan results for a file or project."""

    file_path: str
    sensitive_vars: list[SensitiveVar] = field(default_factory=list)
    """All sensitive variables found in the file."""

    leaks: list[LeakEvent] = field(default_factory=list)
    """Confirmed/probable leak events."""

    total_vars: int = 0
    total_leaks: int = 0


# ---------------------------------------------------------------------------
# Semantic Leak Detector
# ---------------------------------------------------------------------------


class SemanticLeakDetector:
    """Scans code for sensitive variable boundary crossings.

    Usage::

        detector = SemanticLeakDetector()
        results = detector.scan_file("src/auth.py")
        # or
        results = detector.scan_project("/path/to/project")
    """

    def __init__(self) -> None:
        self._results: list[LeakScanResult] = []

    def scan_project(self, project_path: str) -> list[LeakScanResult]:
        """Scan all Python files in a project for semantic leaks."""
        self._results = []
        project_path = os.path.abspath(project_path)
        for root, _dirs, files in os.walk(project_path):
            if any(excl in root for excl in _EXCLUDED_DIRS):
                continue
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    result = self.scan_file(fpath)
                    if result.sensitive_vars or result.leaks:
                        self._results.append(result)
                except Exception:
                    logger.debug("Error scanning %s", fpath, exc_info=True)
        return self._results

    def scan_file(self, file_path: str) -> LeakScanResult:
        """Scan a single Python file for semantic leaks."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except OSError:
            return LeakScanResult(file_path=file_path)

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return LeakScanResult(file_path=file_path)

        scanner = _FunctionScanner(source, os.path.abspath(file_path))
        scanner.visit(tree)

        return LeakScanResult(
            file_path=os.path.abspath(file_path),
            sensitive_vars=scanner.sensitive_vars,
            leaks=scanner.leaks,
            total_vars=len(scanner.sensitive_vars),
            total_leaks=len(scanner.leaks),
        )

    @property
    def results(self) -> list[LeakScanResult]:
        return self._results

    def summary(self) -> str:
        """Human-readable summary of all scan results."""
        total_vars = sum(r.total_vars for r in self._results)
        total_leaks = sum(r.total_leaks for r in self._results)
        return (
            f"SemanticLeakDetector: {len(self._results)} files, "
            f"{total_vars} sensitive vars, {total_leaks} probable leaks"
        )


class _FunctionScanner(ast.NodeVisitor):
    """Internal AST visitor that collects sensitive vars and leak events."""

    def __init__(self, source: str, file_path: str) -> None:
        self._source = source
        self._source_lines = source.splitlines()
        self._file_path = file_path
        self.sensitive_vars: list[SensitiveVar] = []
        self.leaks: list[LeakEvent] = []
        self._current_function: str = ""

    def _match_sensitive(self, name: str) -> str | None:
        """Check if a variable name matches a sensitive pattern."""
        for pat in _SENSITIVE_VAR_PATTERNS:
            m = pat.search(name)
            if m:
                return m.group(1)
        return None

    def _get_context(self, lineno: int) -> str:
        """Get surrounding source lines for context."""
        start = max(0, lineno - 2)
        end = min(len(self._source_lines), lineno + 1)
        return "\n".join(
            f"{i + 1}:{self._source_lines[i]}"
            for i in range(start, end)
        )

    @staticmethod
    def _extract_name_from_expr(expr: ast.AST) -> list[str]:
        """Extract Name node values from an expression (handles f-strings)."""
        names: list[str] = []
        if isinstance(expr, ast.Name):
            names.append(expr.id)
        elif isinstance(expr, ast.Attribute):
            names.append(f"{expr.attr}")
            if isinstance(expr.value, ast.Name):
                names.append(f"{expr.value.id}.{expr.attr}")
        elif isinstance(expr, ast.Call):
            # Recurse into call args (handle nested calls)
            for arg in expr.args:
                names.extend(_FunctionScanner._extract_name_from_expr(arg))
        elif isinstance(expr, ast.JoinedStr):
            for part in expr.values:
                if isinstance(part, ast.FormattedValue):
                    names.extend(_FunctionScanner._extract_name_from_expr(part.value))
        elif isinstance(expr, ast.BinOp):
            names.extend(_FunctionScanner._extract_name_from_expr(expr.left))
            names.extend(_FunctionScanner._extract_name_from_expr(expr.right))
        return names

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old_fn = self._current_function
        self._current_function = node.name
        self.generic_visit(node)
        self._current_function = old_fn

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track assignments with sensitive variable names."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                match = self._match_sensitive(target.id)
                if match:
                    self.sensitive_vars.append(SensitiveVar(
                        name=target.id,
                        file_path=self._file_path,
                        line_number=node.lineno,
                        match_pattern=match,
                        context_hint="assignment",
                    ))

            elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                # self.password, obj.secret, etc.
                full_name = f"{target.value.id}.{target.attr}"
                match = self._match_sensitive(full_name)
                if match:
                    self.sensitive_vars.append(SensitiveVar(
                        name=full_name,
                        file_path=self._file_path,
                        line_number=node.lineno,
                        match_pattern=match,
                        context_hint="attribute_assignment",
                    ))

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        """Check if a return value is a sensitive variable."""
        names = self._extract_name_from_expr(node.value) if node.value else []
        for name in names:
            match = self._match_sensitive(name)
            if match:
                self.leaks.append(LeakEvent(
                    var=SensitiveVar(
                        name=name,
                        file_path=self._file_path,
                        line_number=node.lineno,
                        match_pattern=match,
                        context_hint="return",
                    ),
                    function_name=self._current_function,
                    file_path=self._file_path,
                    line_number=node.lineno,
                    context_code=self._get_context(node.lineno),
                    severity="high",
                    leak_channel="return",
                ))

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check if sensitive vars are passed to output/log functions."""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            call_name = f"{node.func.value.id}.{node.func.attr}"
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Attribute):
            # logger.info, self.logger.info
            call_name = f"{node.func.value.attr}.{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            call_name = node.func.id
        else:
            call_name = ""

        # Check if this is an output/log context
        is_output = any(ctx in call_name for ctx in _OUTPUT_CONTEXTS)

        # Check args for sensitive variables (handles Name, Attribute, f-strings)
        for arg in node.args:
            for var_name in self._extract_name_from_expr(arg):
                match = self._match_sensitive(var_name)
                if match:
                    if is_output:
                        self._record_leak(var_name, match, node.lineno, call_name)

        # Check keyword arguments too
        for kw in node.keywords:
            if kw.arg is None:  # **kwargs
                continue
            for var_name in self._extract_name_from_expr(kw.value):
                match = self._match_sensitive(var_name)
                if match and is_output:
                    self._record_leak(var_name, match, node.lineno, call_name)

        self.generic_visit(node)

    def _record_leak(self, var_name: str, match: str, lineno: int, channel: str) -> None:
        """Record a leak event for a sensitive variable in an output context."""
        self.leaks.append(LeakEvent(
            var=SensitiveVar(
                name=var_name,
                file_path=self._file_path,
                line_number=lineno,
                match_pattern=match,
                context_hint=f"passed_to_{channel}",
            ),
            function_name=self._current_function,
            file_path=self._file_path,
            line_number=lineno,
            context_code=self._get_context(lineno),
            severity="high" if channel in ("return",) else "medium",
            leak_channel=channel,
        ))


# ---------------------------------------------------------------------------
# Bridge: Build semantic leak prompt for Logic Agent
# ---------------------------------------------------------------------------


def build_leak_prompt(leaks: list[LeakEvent], max_leaks: int = 10) -> str:
    """Build a prompt block about semantic leaks for the Logic Agent.

    Injected into the code_block when semantic leaks are detected,
    so the Logic Agent can verify and classify them.
    """
    if not leaks:
        return ""

    seen = set()
    blocks: list[str] = []
    for leak in leaks[:max_leaks]:
        key = (leak.function_name, leak.var.name, leak.line_number)
        if key in seen:
            continue
        seen.add(key)
        blocks.append(
            f"### Leak {len(blocks) + 1}: {leak.var.name} → {leak.leak_channel}\n"
            f"- **Variable**: `{leak.var.name}` (`{leak.var.match_pattern}`)\n"
            f"- **Function**: `{leak.function_name}` ({leak.file_path}:{leak.line_number})\n"
            f"- **Channel**: `{leak.leak_channel}`\n"
            f"- **Severity**: {leak.severity}\n"
            f"```\n{leak.context_code}\n```"
        )

    return (
        "\n\n"
        "[SEMANTIC LEAK DETECTIONS]\n"
        "The static scanner found sensitive variables flowing to output/log contexts. "
        "These are deterministic signals — validate whether each constitutes a real "
        "information disclosure.\n\n"
        + "\n\n".join(blocks) +
        "\n\n[/SEMANTIC LEAK DETECTIONS]"
    )
