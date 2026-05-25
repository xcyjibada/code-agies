"""Language-specific code pattern detection for attacker control verification.

Each language implements the LanguagePatterns ABC, providing structured
queries (not regex) for determining whether a vulnerability is exploitable.

Validators in attacker_control.py use these patterns to check:
  - Is the code in production runtime? (vs test, compiler, startup)
  - Does data cross a trust boundary? (user input entry points)
  - Is there input validation in the path?
  - Is there an external reachability path?
"""

from __future__ import annotations

import ast
import os
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional


class LanguagePatterns(ABC):
    """Abstract interface for language-specific pattern queries.

    All methods use structured code analysis (AST/tree-sitter) rather than
    regex, making them testable, composable, and cross-language.
    """

    def __init__(self, target_root: str) -> None:
        self.target_root = target_root

    # ── P0: Execution Context ────────────────────────────────────────────

    @abstractmethod
    def is_test_code(self, path: str, content: str) -> bool:
        """Is this file test code (not production)?"""

    @abstractmethod
    def is_compiler_code(self, path: str, content: str) -> bool:
        """Is this compile-time / build-time code (not runtime)?"""

    @abstractmethod
    def is_startup_code(self, path: str, content: str) -> bool:
        """Is this code only executed at startup/init (not request-time)?"""

    # ── P0: Trust Boundary ───────────────────────────────────────────────

    @abstractmethod
    def get_user_input_entry_points(self) -> list[str]:
        """Return patterns for user input APIs (HTTP params, env, CLI args)."""

    @abstractmethod
    def get_external_entry_points(self) -> list[str]:
        """Return patterns for external entry points (route handlers, message consumers)."""

    # ── P1: Validation Chain ─────────────────────────────────────────────

    @abstractmethod
    def get_validation_functions(self) -> list[str]:
        """Return names of known validation/sanitization functions."""

    # ── Helpers ──────────────────────────────────────────────────────────

    @abstractmethod
    def is_production_code(self, path: str, content: str) -> bool:
        """Is this code deployed and runtime-accessible?"""

    def _path_matches(self, path: str, patterns: list[str]) -> bool:
        """Check if a file path matches any glob/regex pattern."""
        p = Path(path)
        for pattern in patterns:
            if p.match(pattern) or pattern in str(p):
                return True
        return False


# ── Python Implementation ────────────────────────────────────────────────


class PythonPatterns(LanguagePatterns):
    """Python-specific pattern detection using AST."""

    TEST_PATTERNS = [
        "test_*.py",
        "*_test.py",
        "*_test_*.py",
        "conftest.py",
        "*/tests/*.py",
        "*/test_*.py",
        "*/test/*.py",
    ]

    COMPILER_PATTERNS = [
        "setup.py",
        "setup.cfg",
        "*/setup.py",
        "conftest.py",
        "*/migrations/*.py",
        "*/management/commands/*.py",
    ]

    STARTUP_PATTERNS = [
        "manage.py",
        "app.py",
        "wsgi.py",
        "asgi.py",
        "*/settings.py",
        "*/urls.py",
        "*/apps.py",
    ]

    def __init__(self, target_root: str) -> None:
        super().__init__(target_root)
        # Cache compiled patterns
        self._validation_fns: list[str] | None = None
        self._input_apis: list[str] | None = None
        self._entry_points: list[str] | None = None

    def is_test_code(self, path: str, content: str) -> bool:
        """Detect test code by path patterns and code structure."""
        if self._path_matches(path, self.TEST_PATTERNS):
            return True

        # Check for pytest imports or test function patterns
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in ("pytest", "unittest"):
                            return True
                elif isinstance(node, ast.ImportFrom):
                    if node.module in ("pytest",) or (node.module and node.module.startswith("pytest.")):
                        return True
        except SyntaxError:
            pass

        return False

    def is_compiler_code(self, path: str, content: str) -> bool:
        """Detect build/compile-time code."""
        if self._path_matches(path, self.COMPILER_PATTERNS):
            return True

        # Check for decorators/markers that indicate non-runtime code
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    for deco in node.decorator_list:
                        if isinstance(deco, ast.Name):
                            if deco.id in ("requires_debug",):
                                return True
        except SyntaxError:
            pass

        return False

    def is_startup_code(self, path: str, content: str) -> bool:
        """Detect startup/initialization code."""
        if self._path_matches(path, self.STARTUP_PATTERNS):
            return True

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return False

        has_startup_marker = False
        for node in ast.iter_child_nodes(tree):
            # Function/method definitions are okay
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            # Module-level call to app.run, app.start, etc.
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Attribute):
                    if call.func.attr in ("run", "start", "main", "serve"):
                        has_startup_marker = True

        return has_startup_marker

    def is_production_code(self, path: str, content: str) -> bool:
        """A file is production code if it's not test, compiler, or exclusively startup."""
        if self.is_test_code(path, content) or self.is_compiler_code(path, content):
            return False
        # Startup code can also be production code if functions are importable
        # Only exclude if it's ONLY startup (no other code)
        return True

    def get_user_input_entry_points(self) -> list[str]:
        """Common Python user input APIs."""
        if self._input_apis is None:
            self._input_apis = [
                "sys.argv",
                "input",
                "os.environ",
                "os.getenv",
                "flask.request",
                "request.GET",
                "request.POST",
                "request.data",
                "request.json",
                "request.args",
                "request.form",
                "request.headers",
                "request.cookies",
                "request.files",
                "fastapi.Request",
                "fastapi.Request.query_params",
                "fastapi.Request.body",
                "django.http.HttpRequest",
                "django.http.request.HttpRequest",
                "starlette.requests.Request",
                "argparse",
                "click.argument",
                "click.option",
                "typer.Argument",
                "typer.Option",
            ]
        return self._input_apis

    def get_external_entry_points(self) -> list[str]:
        """Common Python external handler registration patterns."""
        if self._entry_points is None:
            self._entry_points = [
                "@app.route",
                "@app.get",
                "@app.post",
                "@app.put",
                "@app.delete",
                "@app.patch",
                "@blueprint.route",
                "@blueprint.get",
                "@blueprint.post",
                "@router.get",
                "@router.post",
                "@router.put",
                "@router.delete",
                "@router.patch",
                "def main(",
                "asgi_app",
                "wsgi_app",
                "def handle(",
                "def handler(",
                "def on_message(",
                "def on_event(",
            ]
        return self._entry_points

    def get_validation_functions(self) -> list[str]:
        """Known Python validation/sanitization function names."""
        if self._validation_fns is None:
            self._validation_fns = [
                "isinstance",
                "issubclass",
                "hasattr",
                "getattr",
                "validate",
                "validator",
                "validate_input",
                "validate_request",
                "sanitize",
                "sanitize_input",
                "clean",
                "clean_input",
                "escape",
                "shlex.quote",
                "shlex.escape",
                "html.escape",
                "re.escape",
                "django.utils.html.escape",
                "flask.escape",
                "markupsafe.escape",
                "bleach.clean",
                "bleach.linkify",
                "pydantic.BaseModel",
                "pydantic.validate_call",
                "marshmallow.Schema",
                "cerberus.Validator",
                "schema.Schema",
            ]
        return self._validation_fns


# ── Factory ──────────────────────────────────────────────────────────────


def get_language_patterns(language: str, target_root: str) -> LanguagePatterns:
    """Factory: get LanguagePatterns instance for the given language."""
    from agies.verification.language_patterns_java import JavaPatterns
    from agies.verification.language_patterns_js import JavaScriptPatterns

    mapping = {
        "python": PythonPatterns,
        "java": JavaPatterns,
        "javascript": JavaScriptPatterns,
    }
    cls = mapping.get(language)
    if cls is None:
        # Fallback to a generic implementation
        return PythonPatterns(target_root)
    return cls(target_root)
