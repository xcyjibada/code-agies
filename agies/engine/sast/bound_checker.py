"""Deterministic scanner for missing depth/bound guards in recursive functions.

Scans recursive function bodies for common depth/bound/limit guard patterns
and flags functions that lack them — a key detector for type 4 (DoS/stack
overflow via uncontrolled recursion).

Usage::

    from agies.engine.sast.bound_checker import check_depth_guard

    is_safe = check_depth_guard(function_body_text, function_name)
    # → True if depth guard found, False if missing
"""

from __future__ import annotations

import re

# ── Depth guard patterns ───────────────────────────────────────────────

# Patterns that indicate a function limits its recursion depth.
# Each entry is a compiled regex targeting a common form of depth check.

_DEPTH_GUARD_PATTERNS: list[re.Pattern] = [
    # if depth > N / >= N / == N
    re.compile(r"\b(depth|level|n|nesting|count|limit)\s*(>=?|==)\s*\d"),
    # if depth > MAX_DEPTH / >= MAX_LEVEL (named constant)
    re.compile(r"\b(depth|level|n|nesting|count|limit)\s*(>=?|==?)\s*[A-Z_]{2,}"),
    # if len(stack/list/queue) > MAX
    re.compile(r"\blen\s*\(\s*\w+\s*\)\s*[>:=]+\s*\d"),
    # if stack_depth >= max_depth (attribute pattern)
    re.compile(r"\b(self\.|this\.)?\w*(depth|limit|level|bound)\s*(>=?|==)\s*\d"),
    # if limit <= 0 / max_depth <= 0 (early return on invalid input)
    re.compile(r"\b(max_depth|limit|max_nesting|max_level)\s*(<=|<|=)\s*\d"),
    # recursion limit check exception: if depth > sys.getrecursionlimit()
    re.compile(r"\b(getrecursionlimit|get_limit|max_depth)\s*\("),
    # while stack / while queue (bounded loops that prevent full recursion)
    re.compile(r"\bwhile\s+(stack|queue|q)\s*(:|\bnot\b)"),
    # try/except recursion depth exceeded
    re.compile(r"\bRecursionError\b"),
    # Guard clause at function entry: if not x: return / if x is None: return
    re.compile(r"\bif\s+(not\s+)?(\w+\s+is\s+None|\w+\s*(==|is)\s*None|len\(.*\)\s*==\s*0)\s*:"),
]


def check_depth_guard(
    source_text: str,
    func_name: str | None = None,
) -> bool:
    """Check if *source_text* contains a depth/bound guard pattern.

    Returns ``True`` if at least one plausible depth guard is found,
    ``False`` if the function appears unbounded.

    Parameters
    ----------
    source_text : str
        The full body of the function (including signature).
    func_name : str or None
        Optional function name (used for heuristic exclusions).
    """
    # If it's a known "split/merge" or "trivial recursion" pattern that
    # is inherently bounded by the data, still flag it unless a guard exists.
    for pattern in _DEPTH_GUARD_PATTERNS:
        if pattern.search(source_text):
            return True
    return False


def find_missing_bounds(
    function_bodies: dict[str, str],
) -> list[str]:
    """Filter *function_bodies* to only names that lack depth guards.

    Parameters
    ----------
    function_bodies : dict[str, str]
        Mapping of ``function_name → source_body`` (the full function
        source including signature).

    Returns
    -------
    list[str]
        Function names that are missing depth/bound guards.
    """
    missing: list[str] = []
    for fname, body in function_bodies.items():
        if not check_depth_guard(body, func_name=fname):
            missing.append(fname)
    return missing
