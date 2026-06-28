"""Cross-file parameter-level data flow annotation for v3 paths.

Walks existing ``CodeQlPath`` chains (from ``TreeSitterPathFinder``) and
annotates each hop with *which argument carries the taint*.

Unlike full taint tracking, this operates on the already-discovered
function-level call chains, adding parameter-level detail by inspecting
call sites in function bodies.

Usage::

    from agies.engine.v3.pathfinder.dataflow import enrich_paths

    # After paths are discovered by TreeSitterPathFinder
    enrich_paths(index, all_paths)
    # Each path now has .cross_file_flow populated with param-level trace.
"""

from __future__ import annotations

import logging
import os
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from agies.engine.v2.sourcer.models import FunctionIndex, SourceFunction
from agies.engine.v3.codeql.models import CodeQlPath, PathNode

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Parameter extraction from function signatures
# ──────────────────────────────────────────────────────────────────────

_PARAM_SIG = re.compile(r"def\s+\w+\s*\(([^)]*)\)", re.DOTALL)
_PARAM_CLEAN = re.compile(r"(\*{0,2}\w+)\s*(?::\s*[^=,)]+)?")


def extract_params(signature: str) -> list[str]:
    """Extract parameter names from a Python function signature.

    Returns ordered list, excluding ``self`` and ``cls``.
    """
    m = _PARAM_SIG.search(signature)
    if not m:
        return []
    return _parse_param_list(m.group(1))


def _parse_param_list(raw: str) -> list[str]:
    """Parse comma-separated parameter declarations into names.

    Handles nested brackets in type annotations (e.g. ``dict[str, Any]``).
    Excludes ``self``, ``cls``, and positional-only marker ``/``.
    """
    names: list[str] = []
    depth = 0
    buf: list[str] = []
    for ch in raw:
        if ch in "([{":
            depth += 1
            buf.append(ch)
        elif ch in ")]}":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            part = "".join(buf).strip()
            if part and part not in ("self", "cls", "/"):
                if part.startswith("*"):
                    names.append(part)
                else:
                    cm = _PARAM_CLEAN.match(part)
                    if cm:
                        names.append(cm.group(1))
            buf = []
        else:
            buf.append(ch)
    remaining = "".join(buf).strip()
    if remaining and remaining not in ("self", "cls", "/"):
        if remaining.startswith("*"):
            names.append(remaining)
        else:
            cm = _PARAM_CLEAN.match(remaining)
            if cm:
                names.append(cm.group(1))
    return names


# ──────────────────────────────────────────────────────────────────────
# Call-site analysis: match arguments to parameters
# ──────────────────────────────────────────────────────────────────────

_CALL_PATTERN = re.compile(
    r"\b([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*\(((?:[^()]*(?:\([^()]*\))?)*)\)"
)


def _get_call_arg_exprs(call_body: str) -> list[str]:
    """Split call arguments, handling nested parens.

    ``func(a, b(c, d), e)`` → ``["a", "b(c, d)", "e"]``
    """
    args: list[str] = []
    depth = 0
    buf: list[str] = []
    for ch in call_body:
        if ch == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
        else:
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            buf.append(ch)
    remaining = "".join(buf).strip()
    if remaining:
        args.append(remaining)
    return args


def _extract_call_body(body: str, open_paren_idx: int) -> str | None:
    """Extract everything between matching parentheses starting at *open_paren_idx*.

    Handles nested parens correctly. Returns None on unbalanced parens
    or if the call body is unreasonably long (>100K chars).
    """
    depth = 0
    for i in range(open_paren_idx, min(open_paren_idx + 100_000, len(body))):
        ch = body[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return body[open_paren_idx + 1 : i]
    return None  # unbalanced or too long


def _extract_arg_idents(expr: str) -> str | None:
    """Extract a simple identifier from an expression, or None.

    Handles: ``x``, ``self.x``, ``obj.attr``.
    Returns the outermost identifier (e.g. ``x`` from ``x.foo.bar``).
    """
    expr = expr.strip()
    m = re.match(r"([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)", expr)
    if m:
        return m.group(1)
    return None


def match_call_to_params(
    body: str,
    callee_name: str,
    callee_params: list[str],
) -> list[str | None]:
    """Find *callee_name*(...) in *body* and match args to params.

    Returns a list the same length as *callee_params*, where each entry
    is the caller-side expression passed to that parameter (or None if
    we can't determine it).

    Handles positionals and some keyword arguments.
    Only returns simple identifier expressions, not full expressions.
    """
    if not body or not callee_params:
        return []

    # Skip huge function bodies — regex backtracking on >80K char bodies
    # (e.g. Gradio's create_app factory) can hang for minutes.
    if len(body) > 5_000:
        return []

    result: list[str | None] = [None] * len(callee_params)

    # Use str.find() instead of regex to avoid pathological backtracking on
    # function bodies with deeply nested calls.  This is O(len(body)) per
    # callee_name match — fast even on large bodies.
    search_from = 0
    while True:
        idx = body.find(callee_name, search_from)
        if idx == -1:
            break

        # Check that the match is a function call: preceded by a word boundary
        # and followed by '(' (possibly with whitespace).
        if idx > 0:
            prev = body[idx - 1]
            if prev.isalnum() or prev == "_" or prev == ".":
                search_from = idx + 1
                continue

        call_start = len(callee_name) + idx
        # Skip whitespace between name and '('
        while call_start < len(body) and body[call_start] in " \t\n\r":
            call_start += 1
        if call_start >= len(body) or body[call_start] != "(":
            search_from = idx + 1
            continue

        call_body = _extract_call_body(body, call_start)
        if call_body is None:
            search_from = idx + 1
            continue

        raw_args = _get_call_arg_exprs(call_body)

        # Separate positional and keyword args
        positional: list[str] = []
        kwargs: dict[str, str] = {}
        for arg in raw_args:
            if "=" in arg and not arg.startswith("**"):
                # keyword arg: key=value
                parts = arg.split("=", 1)
                k = parts[0].strip()
                v = parts[1].strip()
                kwargs[k] = v
            else:
                positional.append(arg)

        # Map positionals to params
        for i, arg_expr in enumerate(positional):
            if i < len(callee_params):
                ident = _extract_arg_idents(arg_expr)
                if ident:
                    result[i] = ident

        # Map kwargs to params
        for i, pname in enumerate(callee_params):
            if pname in kwargs:
                ident = _extract_arg_idents(kwargs[pname])
                if ident:
                    result[i] = ident

        # Only analyze first matching call site
        break

    return result


# ──────────────────────────────────────────────────────────────────────
# Path enrichment
# ──────────────────────────────────────────────────────────────────────


def _build_cross_file_flow(
    index: FunctionIndex,
    path: CodeQlPath,
    all_nodes: list[tuple[str, SourceFunction | None]],
) -> str:
    """Build a param-level flow string for a path.

    Walks the node chain from source → sink and annotates which
    parameter carries the data at each hop.
    """
    steps: list[str] = []

    # We walk the nodes from source (index 0) to sink (last).
    # At each step (caller, callee), we look at the caller's body
    # to find the call site and determine the arguments passed.

    for i in range(len(all_nodes) - 1):
        caller_name, caller_fn = all_nodes[i]
        callee_name, callee_fn = all_nodes[i + 1]

        if caller_fn is None or callee_fn is None:
            steps.append(f"{caller_name} → {callee_name}")
            continue

        callee_params = extract_params(callee_fn.signature)
        if not callee_params:
            steps.append(f"{caller_name} → {callee_name}")
            continue

        arg_map = match_call_to_params(caller_fn.body, callee_name, callee_params)

        # Build param mapping string like "request.path → path"
        param_info: list[str] = []
        for idx, pname in enumerate(callee_params):
            src = arg_map[idx] if idx < len(arg_map) else None
            if src:
                param_info.append(f"{src} → {pname}")
            else:
                param_info.append(f"? → {pname}")

        if param_info:
            joined = ", ".join(param_info)
            steps.append(f"{caller_name}({joined}) → {callee_name}")
        else:
            steps.append(f"{caller_name} → {callee_name}")

    if steps:
        return " :: ".join(steps)
    return ""


def enrich_paths(index: FunctionIndex, paths: list[CodeQlPath]) -> None:
    """Enrich each ``CodeQlPath`` with cross-file parameter flow info.

    Modifies paths in-place, setting ``cross_file_flow`` on each one.

    Parameters
    ----------
    index : FunctionIndex
        The project's function index (bodies must be available, i.e.
        ``slim()`` not yet called).
    paths : list[CodeQlPath]
        Paths discovered by ``TreeSitterPathFinder``.
    """
    if not index or not paths:
        return

    # Build a lookup: function_name → SourceFunction
    # (prefer the one with the file path matching the path node)
    fn_by_name: dict[str, SourceFunction] = {}
    for fn in index.funcs:
        # Don't overwrite — first occurrence is fine for param extraction
        if fn.name not in fn_by_name:
            fn_by_name[fn.name] = fn

    def _enrich_one(path: CodeQlPath) -> None:
        """Process a single path — thread-safe, in-place."""
        node_names = [path.source]
        node_names += [n.function_name for n in path.nodes]
        node_names.append(path.sink)

        deduped_names: list[str] = []
        for name in node_names:
            if not deduped_names or deduped_names[-1] != name:
                deduped_names.append(name)

        all_nodes: list[tuple[str, SourceFunction | None]] = [
            (name, fn_by_name.get(name)) for name in deduped_names
        ]

        flow = _build_cross_file_flow(index, path, all_nodes)
        if flow:
            path.cross_file_flow = flow

    workers = min(8, (os.cpu_count() or 1) + 4)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_enrich_one, p) for p in paths]
        for future in as_completed(futures):
            future.result()  # re-raise exceptions

    enriched = sum(1 for p in paths if p.cross_file_flow)
    if enriched:
        logger.info(
            "Cross-file flow: enriched %d/%d paths",
            enriched, len(paths),
        )


# ──────────────────────────────────────────────────────────────────────
# CPG-based intra-procedural data flow queries
# ──────────────────────────────────────────────────────────────────────


def query_param_to_sink(
    cpg_builder: Any,
    func_name: str,
    body: str,
    param_names: list[str],
    sink_call_pattern: str,
) -> list[dict[str, Any]]:
    """Trace from a sink call's argument backward through WRITES_TO edges
    to find if any function parameter's value reaches it.

    Uses the CPG (if available) for precise within-function data flow.

    Returns a list of flow chains, each being::

        {"param": "path", "chain": ["path → normalized (L42)", ...], "reachable": True}

    If CPG is not available, falls back to a simple heuristic:
    check if the param name appears before the sink call in the function body.
    """
    from agies.engine.v3.graph.models import (
        WRITES_TO, READS, ATTR_TEXT, ATTR_LINE, ATTR_KIND, KIND_VAR, KIND_VAL,
    )

    results: list[dict[str, Any]] = []
    G = cpg_builder.graph if cpg_builder and cpg_builder.built else None

    for param_name in param_names:
        chain: list[str] = []

        if G is not None:
            # CPG-based: find the sink argument node, trace backward
            # 1. Find all nodes matching the sink call in this function
            sink_nodes = []
            for n, d in G.nodes(data=True):
                text = d.get(ATTR_TEXT, "")
                if sink_call_pattern in text and d.get(ATTR_KIND) in (KIND_VAR, KIND_VAL):
                    sink_nodes.append(n)

            # 2. For each sink argument, trace backward through WRITES_TO
            for sink_n in sink_nodes:
                current = sink_n
                visited: set[str] = set()
                steps: list[str] = []
                for _ in range(20):  # max depth
                    if current in visited:
                        break
                    visited.add(current)
                    node_data = G.nodes.get(current)
                    if node_data:
                        text = node_data.get(ATTR_TEXT, "")
                        line = node_data.get(ATTR_LINE, 0)
                        if text == param_name:
                            steps.append(f"param:{param_name} (L{line})")
                            break
                        elif text:
                            steps.append(f"{text} (L{line})")
                    # Follow WRITES_TO backward (predecessor)
                    found_pred = False
                    for pred in G.predecessors(current):
                        edge_data = G.get_edge_data(pred, current)
                        if edge_data and edge_data.get("relationship") in (WRITES_TO, READS):
                            current = pred
                            found_pred = True
                            break
                    if not found_pred:
                        break

                if steps:
                    chain = steps

        # Fallback: simple text-based heuristic if CPG not available or
        # didn't find a chain
        if not chain and body:
            # Look for the pattern: param_name appears before the sink call
            # This is a crude heuristic but better than nothing
            lines = body.split("\n")
            sink_line = -1
            for i, line in enumerate(lines):
                if sink_call_pattern in line:
                    sink_line = i
                    break
            if sink_line >= 0:
                # Check if param_name appears in any preceding line
                for i in range(min(sink_line, sink_line)):
                    if param_name in lines[i]:
                        chain = [
                            f"param:{param_name} (text heuristic)",
                            f"... → {sink_call_pattern} (L{sink_line})",
                        ]
                        break

        results.append({
            "param": param_name,
            "chain": chain,
            "reachable": len(chain) > 0,
        })

    return results


def format_cpg_evidence(flows: list[dict[str, Any]]) -> str:
    """Format ``query_param_to_sink()`` results into a readable trace string.

    Input::

        [{"param": "path", "chain": ["path (L15)", "normalized (L20)",
                                      "open(filename) (L42)"], "reachable": True}]

    Output::

        "param:path -> path (L15) -> normalized (L20) -> open(filename) (L42)"
    """
    if not flows:
        return ""
    trace_parts: list[str] = []
    for flow in flows:
        if flow.get("reachable") and flow.get("chain"):
            chain = flow["chain"]
            trace_parts.append(" -> ".join(chain))
    if trace_parts:
        return " | ".join(trace_parts)
    return ""

