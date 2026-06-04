"""Tree-sitter based path discovery — replaces CodeQL Phase A.

Uses the existing ``agies.engine.v2.sourcer`` (extractor + loader) to
build a project-wide call graph, then discovers source→sink paths by:

1. Building a ``FunctionIndex`` with full call graph
2. Searching all function names for sink patterns (exec, eval, open, …)
3. For each sink, BFS backwards through the call graph to build call chains
4. Packaging each chain as a ``CodeQlPath`` object

The output is identical to what ``CodeQLQueryRunner`` would produce, so
downstream modules (slicer → prompts → agents) work unchanged.
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict, deque
from typing import Any

from agies.engine.v2.sourcer.loader import build_index
from agies.engine.v2.sourcer.models import FunctionIndex, SourceFunction

from agies.engine.v3.codeql.models import (
    CodeQlPath,
    PathNode,
    QueryResult,
    VulnType,
    VULN_LABELS,
)
from agies.engine.v3.pathfinder.sink_patterns import (
    classify_sink,
    classify_sensitive_body,
    KNOWN_SINK_NAMES,
)

logger = logging.getLogger(__name__)

# How many caller-hops to trace back from a sink (max path depth).
_MAX_BACKTRACK_DEPTH = 8


class TreeSitterPathFinder:
    """Phase A path discovery using tree-sitter (no CodeQL needed).

    Usage::

        finder = TreeSitterPathFinder(project_path)
        results = finder.run_all()
        for r in results:
            print(f"{r.label}: {r.total_sinks} sinks")

    The output ``list[QueryResult]`` matches what ``CodeQLQueryRunner.run_all()``
    returns, so it can be plugged directly into the existing v3 pipeline.
    """

    def __init__(
        self,
        project_path: str,
        *,
        max_depth: int = _MAX_BACKTRACK_DEPTH,
        excluded_dirs: set[str] | None = None,
    ) -> None:
        self._project_path = os.path.abspath(project_path)
        self._max_depth = max_depth
        self._excluded_dirs = excluded_dirs or {
            ".git", "__pycache__", "node_modules", "venv", ".venv",
            "dist", "build", ".tox", ".eggs", "egg-info",
            ".mypy_cache", ".pytest_cache",
        }
        self._index: FunctionIndex | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_index(self) -> FunctionIndex:
        """Build the function index with call graph.

        Can be called separately to inspect the index before running queries.
        """
        if self._index is None:
            logger.info("TreeSitterPathFinder: building index for %s", self._project_path)
            self._index = build_index(
                project_path=self._project_path,
            )
            logger.info(
                "TreeSitterPathFinder: %d functions, %d files",
                len(self._index.funcs),
                len(self._index.sources),
            )
        return self._index

    def run_all(self) -> list[QueryResult]:
        """Run all sink queries against the project.

        Returns one ``QueryResult`` per vulnerability type with the
        discovered paths.
        """
        start = time.time()
        index = self.build_index()

        if not index.funcs:
            logger.warning("TreeSitterPathFinder: no functions found in %s", self._project_path)
            return []

        # Discover sinks grouped by VulnType
        sinks_by_type: dict[VulnType, list[SourceFunction]] = defaultdict(list)
        for fn in index.funcs:
            vtype = classify_sink(fn.name)
            if vtype is not None:
                sinks_by_type[vtype].append(fn)

        # Build results per VulnType
        results: list[QueryResult] = []
        for vtype in VulnType:
            if vtype == VulnType.UNKNOWN:
                continue
            sinks = sinks_by_type.get(vtype, [])
            label = VULN_LABELS.get(vtype, str(vtype))

            if not sinks:
                results.append(QueryResult(
                    vuln_type=vtype,
                    label=label,
                    total_sinks=0,
                    paths=[],
                    duration_seconds=time.time() - start,
                ))
                continue

            paths: list[CodeQlPath] = []
            for sink_fn in sinks[:20]:  # cap per type to avoid explosion
                path = self._build_path(index, sink_fn, vtype)
                if path is not None:
                    paths.append(path)

            results.append(QueryResult(
                vuln_type=vtype,
                label=label,
                total_sinks=len(paths),
                paths=paths,
                duration_seconds=time.time() - start,
            ))

        elapsed = time.time() - start
        total = sum(r.total_sinks for r in results)
        logger.info(
            "TreeSitterPathFinder: %d queries, %d sinks total (%.1fs)",
            len(results), total, elapsed,
        )

        # Second pass: sensitive body detection
        sensitive_count = 0
        for fn in index.funcs:
            if classify_sink(fn.name) is not None:
                continue
            if not fn.body:
                continue
            vtype = classify_sensitive_body(fn.body)
            if vtype is None:
                continue
            path = self._build_path(index, fn, vtype)
            if path is None:
                continue
            sensitive_count += 1
            found = False
            for r in results:
                if r.vuln_type == vtype:
                    r.paths.append(path)
                    r.total_sinks = len(r.paths)
                    found = True
                    break
            if not found:
                results.append(QueryResult(
                    vuln_type=vtype,
                    label=VULN_LABELS.get(vtype, str(vtype)),
                    total_sinks=1,
                    paths=[path],
                    duration_seconds=time.time() - start,
                ))

        if sensitive_count:
            logger.info(
                "TreeSitterPathFinder: +%d sensitive-body paths (Explore candidates)",
                sensitive_count,
            )
        return results

    def run_one(self, vuln_type: VulnType) -> QueryResult:
        """Run a single sink query for one vulnerability type."""
        index = self.build_index()
        label = VULN_LABELS.get(vuln_type, str(vuln_type))

        sinks = [
            fn for fn in index.funcs
            if classify_sink(fn.name) == vuln_type
        ]

        if not sinks:
            return QueryResult(
                vuln_type=vuln_type, label=label,
                total_sinks=0,
            )

        start = time.time()
        paths = []
        for sink_fn in sinks[:20]:
            path = self._build_path(index, sink_fn, vuln_type)
            if path is not None:
                paths.append(path)

        return QueryResult(
            vuln_type=vuln_type, label=label,
            total_sinks=len(paths), paths=paths,
            duration_seconds=time.time() - start,
        )

    # ------------------------------------------------------------------
    # Path building
    # ------------------------------------------------------------------

    def _build_path(
        self,
        index: FunctionIndex,
        sink_fn: SourceFunction,
        vuln_type: VulnType,
    ) -> CodeQlPath | None:
        """Build a CodeQlPath for one sink function.

        Traces backwards through ``index.call_graph`` to find callers.
        Creates a path from the deepest reachable caller to the sink.

        Returns ``None`` if no path can be built (isolated function).
        """
        # Walk backwards to find the call chain
        chain = self._backtrack(index, sink_fn.name)
        if not chain:
            return None

        # The chain is ordered [deepest_caller, ..., intermediate, sink]
        entry_fn_name = chain[0]
        entry_fns = index.lookup(entry_fn_name)
        source_file = entry_fns[0].file_path if entry_fns else sink_fn.file_path

        # Build path nodes
        nodes: list[PathNode] = []
        for fname in chain:
            matching = index.lookup(fname)
            if matching:
                m = matching[0]
                nodes.append(PathNode(
                    function_name=m.name,
                    file_path=m.file_path,
                    line_number=m.line_start,
                    snippet=m.body or "",
                ))

        path = CodeQlPath(
            vuln_type=vuln_type,
            source=entry_fn_name,
            source_file=source_file,
            source_line=chain_node_line(index, entry_fn_name),
            sink=sink_fn.name,
            sink_file=sink_fn.file_path,
            sink_line=sink_fn.line_start,
            message=f"{vuln_type.value.upper()}: {sink_fn.name} at {sink_fn.file_path}:{sink_fn.line_start}",
            is_full_path=False,  # tree-sitter can't guarantee completeness
            confidence=0.5,
            nodes=nodes,
        )
        return path

    def _backtrack(
        self,
        index: FunctionIndex,
        sink_name: str,
    ) -> list[str] | None:
        """BFS backward through the call graph from a sink.

        Returns a list ``[caller, ..., sink]`` — the longest discovered
        chain (fewest hops with most callers).

        Returns ``None`` if the sink is not in the call graph at all.
        """
        # call_graph is {callee_name: {caller_names}}
        if sink_name not in index.call_graph or not index.call_graph[sink_name]:
            return None

        # BFS backwards
        queue: deque[tuple[str, list[str]]] = deque()
        queue.append((sink_name, [sink_name]))
        best_chain: list[str] = [sink_name]

        while queue:
            current, chain = queue.popleft()
            if len(chain) > self._max_depth:
                continue

            callers = index.call_graph.get(current, set())
            if not callers:
                if len(chain) > len(best_chain):
                    best_chain = chain
                continue

            for caller in callers:
                # Avoid cycles — caller already in chain
                if caller in chain:
                    continue
                new_chain = [caller] + chain
                queue.append((caller, new_chain))
                if len(new_chain) > len(best_chain):
                    best_chain = new_chain

        return best_chain

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary_text(self, results: list[QueryResult]) -> str:
        """Human-readable summary."""
        lines: list[str] = []
        total = 0
        for r in results:
            tag = "  SNK"
            total += r.total_sinks

            if r.total_sinks == 0:
                lines.append(f"{tag}  {r.label}: 0 sinks")
            else:
                lines.append(f"{tag}  {r.label}: {r.total_sinks} sinks")
                for path in r.paths[:5]:
                    lines.append(f"       ↳ {path.sink} at {path.sink_file}:{path.sink_line}")

        lines.insert(0, f"TreeSitterPathFinder: {len(results)} queries, {total} sinks")
        return "\n".join(lines)

    @property
    def index(self) -> FunctionIndex | None:
        """The built function index (None before build_index() is called)."""
        return self._index


def chain_node_line(index: FunctionIndex, func_name: str) -> int:
    """Get the line number of a function in the call chain."""
    fns = index.lookup(func_name)
    return fns[0].line_start if fns else 0
