"""Source classification for CodeQlPath — distinguish HTTP-controllable from
env/config-driven or constant paths.

Purpose
-------
The tree-sitter pathfinder flags any function that calls a known sink
(e.g. ``importlib.import_module``, ``open``, ``exec``) regardless of whether
the argument is attacker-controlled.  This results in 80-95% false positives
on frameworks like LangGraph where sinks are called with env-var or config
values at startup.

The classifier closes that gap by examining the **source of the data flowing
into the sink** at the AST level (no LLM needed):

- **HTTP_INPUT** — entry function is an HTTP route handler (``@app.get``,
  ``request`` param)
- **CONFIG_DRIVEN** — sink arguments reference environment variables, config
  objects, or module-level ALL_CAPS constants
- **CONSTANT** — sink arguments are all string literals (hardcoded paths/keys)
- **UNKNOWN** — can't determine (pass through for LLM analysis)

Correctness justification
-------------------------
- HTTP_INPUT:  detecting route decorators and ``request`` params has negligible
  FP rate (tree-sitter level, no heuristics needed).
- CONFIG_DRIVEN: ``env(...)`` and ``os.environ[...]`` can only appear in config-
  loading code.  False positives are possible if a test controller also reads
  ``os.environ``, but those are rare in practice.
- CONSTANT: a string literal argument to ``open("fixed_path")`` or
  ``importlib.import_module("fixed_module")`` can never be attacker-controlled.
- UNKNOWN: anything that doesn't match the above patterns is deferred to the
  LLM pipeline for deeper analysis.

Scoring asymmetry
-----------------
- CONSTANT → **filtered out entirely** (no path to exploit)
- CONFIG_DRIVEN → **filtered by default** (marked in stats), admittable via
  ``--keep-config-paths`` flag for codebases where config injection is in scope
- HTTP_INPUT → kept (highest priority)
- UNKNOWN → kept (deferred to LLM)
"""

from __future__ import annotations

import logging
import re
from enum import Enum
from typing import Any

from agies.engine.v3.codeql.models import CodeQlPath, Reachability

logger = logging.getLogger(__name__)


class SourceClass(str, Enum):
    """Origin classification for data flowing into a sink."""

    HTTP_INPUT = "http_input"
    """Entry function is an HTTP route handler — input is attacker-controllable."""

    CONFIG_DRIVEN = "config"
    """Sink argument originates from an env var, config object, or settings."""

    CONSTANT = "constant"
    """Sink argument is a hardcoded string literal — never attacker-controllable."""

    UNKNOWN = "unknown"
    """Can't determine from static analysis — pass through for LLM."""


# ── Config/env reference patterns ──────────────────────────────────────

_ENV_PATTERNS: list[re.Pattern] = [
    re.compile(r"os\.environ\s*\["),       # os.environ["KEY"]
    re.compile(r"os\.environ\.get\s*\("),   # os.environ.get("KEY")
    re.compile(r"os\.getenv\s*\("),         # os.getenv("KEY")
    re.compile(r"\benv\s*\(\s*['\"]"),       # env("KEY") — pydantic-settings
    re.compile(r"\bsettings\.[A-Z]"),        # settings.KEY
    re.compile(r"\bconfig\.[A-Z]"),          # config.KEY
    re.compile(r"\bLANGGRAPH_[A-Z_]+\b"),    # LANGGRAPH_STORE, etc.
    re.compile(r"\bPYTHON_[A-Z_]+\b"),       # PYTHON_GRPC_BIND_HOST, etc.
]

_ALL_CAPS_REF = re.compile(r"\b[A-Z][A-Z_]{2,}\b")
"""Matches ``LANGGRAPH_STORE``, ``MAX_RETRIES`` — potential config constants."""

_ROUTE_DECORATOR = re.compile(
    r"@\w+\.(?:get|post|put|delete|patch|route|api_route)\b"
)

# Common names that are never user input
_SAFE_ARG_NAMES = frozenset({
    "self", "cls", "None", "True", "False",
})


# ── Public API ─────────────────────────────────────────────────────────


def classify_source(path: CodeQlPath) -> SourceClass:
    """Classify the source of data flowing through *path*.

    Examines the entry function, intermediate call chain snippets, and
    the sink call arguments to determine whether the data source is
    attacker-controllable.

    Parameters
    ----------
    path : CodeQlPath
        A source→sink path from tree-sitter or CodeQL discovery.

    Returns
    -------
    SourceClass
        The classification of the data source for this path.
    """
    # ── 1. HTTP controller detection (highest confidence) ──
    if _is_http_controller(path):
        return SourceClass.HTTP_INPUT

    # ── 2. Body-only / external-api paths — the source is unknown,
    #    pass through.  These are typically library functions where
    #    we can't see the callers, so defer to LLM.
    if _is_body_only(path):
        return SourceClass.UNKNOWN

    # ── 3. Check the sink-caller function's and entry function's
    #    code for config/env patterns.
    caller_text = _get_caller_snippet(path)
    if caller_text and _has_config_pattern(caller_text):
        return SourceClass.CONFIG_DRIVEN

    # ── 4. Check whether the sink function's body (for body-detected
    #    cases) contains config patterns.
    sink_text = _get_sink_snippet(path)
    if sink_text and _has_config_pattern(sink_text):
        return SourceClass.CONFIG_DRIVEN

    # -- 5. Check ALL_CAPS variable name usage in caller
    if caller_text and _sink_call_has_all_caps_arg(caller_text, path.sink):
        return SourceClass.CONFIG_DRIVEN

    # ── 6. Constant detection — all arguments are string literals ──
    if caller_text and _sink_args_all_literal(caller_text, path.sink):
        return SourceClass.CONSTANT

    return SourceClass.UNKNOWN


def should_filter(path: CodeQlPath) -> bool:
    """Return ``True`` if *path* should be filtered from the pipeline.

    Currently filters CONSTANT and CONFIG_DRIVEN paths.  HTTP_INPUT and
    UNKNOWN paths pass through for normal LLM analysis.
    """
    cls = classify_source(path)
    return cls in (SourceClass.CONSTANT, SourceClass.CONFIG_DRIVEN)


def filter_paths(
    paths: list[CodeQlPath],
    keep_config: bool = False,
) -> tuple[list[CodeQlPath], dict[str, int]]:
    """Filter a list of CodeQlPath objects by source classification.

    Parameters
    ----------
    paths : list[CodeQlPath]
        All discovered paths from one vulnerability type query.
    keep_config : bool
        When True, keep CONFIG_DRIVEN paths instead of filtering them.

    Returns
    -------
    kept : list[CodeQlPath]
        Paths that pass the filter.
    stats : dict[str, int]
        ``{"http_input": N, "config": N, "constant": N, "unknown": N, "filtered": N}``
    """
    kept: list[CodeQlPath] = []
    stats: dict[str, int] = {
        "http_input": 0, "config": 0, "constant": 0,
        "unknown": 0, "filtered": 0,
    }

    for p in paths:
        cls = classify_source(p)
        stats[cls.value] = stats.get(cls.value, 0) + 1

        if cls == SourceClass.CONSTANT:
            stats["filtered"] += 1
            continue  # always filter constants

        if cls == SourceClass.CONFIG_DRIVEN and not keep_config:
            stats["filtered"] += 1
            continue  # filter config unless --keep-config-paths

        kept.append(p)

    return kept, stats


# ── Implementation details ─────────────────────────────────────────────


def _is_http_controller(path: CodeQlPath) -> bool:
    """Check whether the path's entry function is an HTTP controller.

    Uses both the existing ``source_controllability_proof`` field and
    direct route decorator detection.
    """
    # Already classified by TreeSitterPathFinder
    if path.source_controllability_proof:
        return True

    # Check entry function snippet for route decorators
    if path.nodes and path.nodes[0].snippet:
        if _ROUTE_DECORATOR.search(path.nodes[0].snippet):
            return True

    # Check entry function snippet for web framework parameter names
    if path.nodes and path.nodes[0].snippet:
        if _has_web_param(path.nodes[0].snippet):
            return True

    return False


def _is_body_only(path: CodeQlPath) -> bool:
    """Check whether the path has no call chain (body-detected or external API).

    These have no caller context to analyze, so we can't classify the source
    type reliably — pass through as UNKNOWN.
    """
    reach = getattr(path, "reachability", Reachability.CHAIN)
    return reach in (Reachability.BODY_ONLY, Reachability.EXTERNAL_API)


def _get_caller_snippet(path: CodeQlPath) -> str:
    """Get the source code of the function that calls the sink.

    For paths with a full call chain, this is the second-to-last node
    (the function immediately before the sink).  For single-node paths,
    returns the sink function's own body.
    """
    if not path.nodes:
        return ""

    if len(path.nodes) >= 2:
        # The last node is the sink; the one before it is the caller
        return path.nodes[-2].snippet or ""

    return path.nodes[-1].snippet or ""


def _get_sink_snippet(path: CodeQlPath) -> str:
    """Get the sink function's source code."""
    if not path.nodes:
        return ""
    return path.nodes[-1].snippet or ""


def _has_config_pattern(text: str) -> bool:
    """Check if *text* contains references to env vars or config objects."""
    for pat in _ENV_PATTERNS:
        if pat.search(text):
            return True
    return False


_WEB_PARAMS = frozenset({
    "request", "response", "payload", "data", "body",
    "query", "form", "files", "json", "incoming",
})


def _has_web_param(snippet: str) -> bool:
    """Check if a function signature contains a web-framework parameter."""
    m = re.search(r"def\s+\w+\s*\(([^)]*)\)", snippet)
    if not m:
        return False
    params_text = m.group(1)
    for p in params_text.split(","):
        name = p.strip().split("=")[0].split(":")[0].strip()
        if name in _WEB_PARAMS:
            return True
    return False


def _sink_call_has_all_caps_arg(body_text: str, sink_name: str) -> bool:
    """Check if any argument to the sink call is an ALL_CAPS name.

    ALL_CAPS names (e.g. ``LANGGRAPH_STORE``, ``DEFAULT_PATH``) are
    conventionally module-level config constants, not user input.
    """
    m = re.search(rf"\b{re.escape(sink_name)}\s*\(([^)]*)\)", body_text)
    if not m or not m.group(1).strip():
        return False

    args_str = m.group(1)
    args = _split_args(args_str)
    for arg in args:
        arg = arg.strip()
        if not arg:
            continue
        # Skip keyword names, check values
        if "=" in arg:
            _kw = arg.split("=", 1)
            value = _kw[1].strip()
        else:
            value = arg
        if _ALL_CAPS_REF.fullmatch(value):
            return True
    return False


def _sink_args_all_literal(body_text: str, sink_name: str) -> bool:
    """Check if ALL arguments to the sink call are string literals.

    Examples that match::

        open("/etc/passwd")
        importlib.import_module("some.module")
        "/hardcoded/path"

    Examples that don't match::

        open(user_input_filename)
        importlib.import_module(config_path)
        open(self.path)
    """
    m = re.search(rf"\b{re.escape(sink_name)}\s*\(([^)]*)\)", body_text)
    if not m or not m.group(1).strip():
        return False

    args_str = m.group(1)
    args = _split_args(args_str)
    if not args:
        return False

    for arg in args:
        arg = arg.strip()
        if not arg:
            continue

        # Handle keyword arguments: check value side
        value = arg
        if "=" in arg:
            parts = arg.split("=", 1)
            value = parts[1].strip()

        # Skip safe builtins
        if value in _SAFE_ARG_NAMES:
            continue

        # Accept string literals (single or double quoted)
        if _is_string_literal(value):
            continue

        # Accept simple numeric literals
        if _is_numeric_literal(value):
            continue

        # Anything else is non-constant
        return False

    return bool(args)


def _is_string_literal(text: str) -> bool:
    """Check if *text* is a Python string literal (single, double, triple)."""
    return (
        text.startswith("'") and text.endswith("'")
        or text.startswith('"') and text.endswith('"')
        or text.startswith("'''") and text.endswith("'''")
        or text.startswith('"""') and text.endswith('"""')
    )


def _is_numeric_literal(text: str) -> bool:
    """Check if *text* is a numeric literal (int or float)."""
    try:
        float(text)
        return True
    except ValueError:
        return False


def _split_args(args_text: str) -> list[str]:
    """Split argument text by comma, respecting nested parentheses."""
    args: list[str] = []
    depth = 0
    current = ""
    for ch in args_text:
        if ch in ("(", "[", "{"):
            depth += 1
        elif ch in (")", "]", "}"):
            depth -= 1
        if ch == "," and depth == 0:
            args.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        args.append(current.strip())
    return args


# ── Summary helpers ────────────────────────────────────────────────────


def format_stats(stats: dict[str, int]) -> str:
    """Format filter stats for console output."""
    parts = []
    if stats.get("http_input"):
        parts.append(f"{stats['http_input']} http")
    if stats.get("config"):
        parts.append(f"{stats['config']} config")
    if stats.get("constant"):
        parts.append(f"{stats['constant']} constant")
    if stats.get("unknown"):
        parts.append(f"{stats['unknown']} unk")
    filtered = stats.get("filtered", 0)
    kept = sum(stats.get(k, 0) for k in ("http_input", "unknown"))
    tag = "[red]filtered[/red]" if filtered else "[dim]none filtered[/dim]"
    return f"Source: {', '.join(parts)} | {tag} ({filtered} removed, {kept} kept)"
