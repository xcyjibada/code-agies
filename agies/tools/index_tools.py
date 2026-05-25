"""FunctionIndex-aware tools for the Verification Agent.

These tools require a FunctionIndex to be passed in at registration time
so they can query the index during Phase 2 verification.

Tools:
- ``lookup_function(name)`` — find functions by name
- ``find_callers(name)`` — find functions that call a given function
- ``find_callees(name)`` — find functions called by a given function
"""

from __future__ import annotations

from typing import Any

# Global index reference — set during tool registration in the VerificationAgent
_index: FunctionIndex | None = None

# Global state reference — set by Brain for knowledge-recording tools
_state: Any = None


def set_index(idx: FunctionIndex | None) -> None:
    """Set the FunctionIndex for index-aware tools."""
    global _index
    _index = idx


def set_state(st: Any | None) -> None:
    """Set the ProjectState for knowledge-recording tools."""
    global _state
    _state = st


def record_knowledge(key: str, value: str, **kwargs: Any) -> str:
    """Record a discovered fact for cross-agent knowledge sharing.

    Call this after you discover something meaningful (a call chain,
    an auth bypass, a sanitizer presence) so that subsequent agents
    working on the same function/file benefit from your analysis.

    Parameters
    ----------
    key:
        Function name or file path the knowledge relates to.
    value:
        Free-text summary of what was discovered (1-3 sentences).
    """
    if not key or not value:
        return "Error: key and value are required"
    from agies.engine.router import validate_tool_call
    err = validate_tool_call("record_knowledge", {"key": key, "value": value})
    if err:
        return f"Error: {err}"
    if _state is None:
        return "Error: ProjectState not available (record_knowledge only works during an active audit)"
    _state.record_knowledge(key, value)
    return f"Knowledge recorded for '{key}'"


def lookup_function(name: str, file_glob: str = "", **kwargs: Any) -> str:
    """Find functions matching *name*. Optionally filter by file_glob."""
    from agies.engine.router import validate_tool_call
    err = validate_tool_call("lookup_function", {"name": name})
    if err:
        return f"Error: {err}"
    if _index is None:
        return "FunctionIndex not available"
    results = _index.lookup(name)
    if file_glob:
        results = [fn for fn in results if file_glob in fn.file_path]
    if not results:
        return f"No functions found matching '{name}'"
    lines = [f"Found {len(results)} function(s):"]
    for fn in results[:20]:
        lines.append(
            f"  {fn.fullname} ({fn.file_path}:{fn.line_start}) — "
            f"{fn.signature[:80]}"
        )
    if len(results) > 20:
        lines.append(f"  ... and {len(results) - 20} more")
    return "\n".join(lines)


def find_callers(name: str, **kwargs: Any) -> str:
    """Find functions that directly call *name*."""
    from agies.engine.router import validate_tool_call
    err = validate_tool_call("find_callers", {"name": name})
    if err:
        return f"Error: {err}"
    if _index is None:
        return "FunctionIndex not available"
    callers = _index.find_callers(name)
    if not callers:
        return f"No callers found for '{name}'"
    lines = [f"Callers of '{name}' ({len(callers)}):"]
    for fn in callers[:20]:
        lines.append(f"  {fn.fullname} ({fn.file_path}:{fn.line_start})")
    if len(callers) > 20:
        lines.append(f"  ... and {len(callers) - 20} more")
    return "\n".join(lines)


def find_callees(name: str, **kwargs: Any) -> str:
    """Find functions called by *name*."""
    from agies.engine.router import validate_tool_call
    err = validate_tool_call("find_callees", {"name": name})
    if err:
        return f"Error: {err}"
    if _index is None:
        return "FunctionIndex not available"
    callees = _index.find_callees(name)
    if not callees:
        return f"No callees found for '{name}'"
    lines = [f"Callees of '{name}' ({len(callees)}):"]
    for fn in callees[:20]:
        lines.append(f"  {fn.fullname} ({fn.file_path}:{fn.line_start})")
    if len(callees) > 20:
        lines.append(f"  ... and {len(callees) - 20} more")
    return "\n".join(lines)


def get_call_chain_logic(
    sink_function: str,
    entry_function: str = "",
    max_depth: int = 12,
    **kwargs: Any,
) -> str:
    """Return a compact logic dossier for the call chain from *entry_function*
    to *sink_function*.

    Uses the FunctionIndex call graph + tree-sitter logic extraction to
    produce a one-page summary of all paths, including key if-conditions,
    important calls, and sanitizer/auth-gate annotations.  Noise functions
    like logging.info() and print() are automatically filtered out.

    Parameters
    ----------
    sink_function:
        The function name at the end of the call chain (the vulnerable sink).
    entry_function:
        Optional entry-point function.  If empty, finds all paths to *sink_function*.
    max_depth:
        Maximum call-chain depth.  Default 12.

    Returns
    -------
    str
        Human-readable "logic dossier" with paths and extracted logic.
    """
    if _index is None:
        return "FunctionIndex not available"
    from agies.engine.sast.pathfinder import CallChainAnalyzer
    finder = CallChainAnalyzer(_index)
    return finder.analyze(
        sink=sink_function,
        entry=entry_function,
        max_depth=min(max_depth, 24),
    )
