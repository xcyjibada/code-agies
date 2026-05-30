"""Function-level data structures for the sourcer/indexer layer.

Inspired by Xint's ``analysis/data.py`` (theori-io/aixcc-afc-archive).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SourceFunction:
    """A single function (or method) extracted from source code."""

    name: str
    """Short function name, e.g. ``validate_user``."""

    fullname: str
    """Qualified name, e.g. ``UserController::validateUser``."""

    file_path: str
    """Relative or absolute path to the source file."""

    line_start: int
    """1-based start line of the function (including signature)."""

    line_end: int
    """1-based end line of the function body."""

    signature: str
    """Function signature text (return type + name + params)."""

    body: str
    """Full function body as source text."""


@dataclass(frozen=True)
class SourceFile:
    """A source file with its content and line index."""

    path: str
    source: str
    language: str = ""

    def __post_init__(self) -> None:
        if not self.language:
            ext = self.path.rsplit(".", 1)[-1].lower()
            lang_map = {
                "py": "python",
                "java": "java",
                "js": "javascript",
                "ts": "typescript",
                "tsx": "typescript",
                "jsx": "javascript",
                "go": "go",
                "rs": "rust",
                "c": "c",
                "cpp": "cpp",
                "h": "c",
                "hpp": "cpp",
            }
            object.__setattr__(self, "language", lang_map.get(ext, "unknown"))


@dataclass
class FunctionIndex:
    """Index of all functions extracted from a project.

    Provides lookup and query methods used by both the bulk analyser
    (Phase 1) and the verification agent (Phase 2).
    """

    sources: dict[str, SourceFile] = field(default_factory=dict)
    """All source files keyed by path."""

    funcs: list[SourceFunction] = field(default_factory=list)
    """All extracted functions."""

    name_index: dict[str, list[SourceFunction]] = field(
        default_factory=dict
    )
    """Functions grouped by short name (may have overloads)."""

    file_index: dict[str, list[SourceFunction]] = field(
        default_factory=dict
    )
    """Functions grouped by file path."""

    call_graph: dict[str, set[str]] = field(default_factory=dict)
    """caller_name → set[callee_name] (filled by build_call_graph)."""

    # ------------------------------------------------------------------
    # Building
    # ------------------------------------------------------------------

    def add(self, sf: SourceFile, funcs: list[SourceFunction]) -> None:
        self.sources[sf.path] = sf
        for fn in funcs:
            self.funcs.append(fn)
            self.name_index.setdefault(fn.name, []).append(fn)
            self.file_index.setdefault(fn.file_path, []).append(fn)

    def build_lut(self) -> None:
        """Rebuild lookup tables (call after bulk-add)."""
        self.name_index.clear()
        self.file_index.clear()
        for fn in self.funcs:
            self.name_index.setdefault(fn.name, []).append(fn)
            self.file_index.setdefault(fn.file_path, []).append(fn)

    # ------------------------------------------------------------------
    # Queries (used by Verification Agent tools)
    # ------------------------------------------------------------------

    def lookup(self, name: str) -> list[SourceFunction]:
        """Find all functions matching *name*."""
        return self.name_index.get(name, [])

    def find_callers(self, func_name: str) -> list[SourceFunction]:
        """Return functions that directly call *func_name*."""
        caller_names = self.call_graph.get(func_name, set())
        results: list[SourceFunction] = []
        for name in caller_names:
            results.extend(self.name_index.get(name, []))
        return results

    def find_callees(self, func_name: str) -> list[SourceFunction]:
        """Return functions called by *func_name*."""
        results: list[SourceFunction] = []
        for fn in self.name_index.get(func_name, []):
            callees = self._get_direct_callees(fn.name)
            for cname in callees:
                results.extend(self.name_index.get(cname, []))
        return results

    def _get_direct_callees(self, name: str) -> set[str]:
        """Find callees by inverting the call_graph (caller→callee)."""
        if not self.call_graph:
            return set()
        # call_graph is callee → set[caller]; invert to get caller → set[callee]
        callee_set: set[str] = set()
        for callee, callers in self.call_graph.items():
            if name in callers:
                callee_set.add(callee)
        return callee_set

    def build_call_graph_from_calls(
        self, calls: dict[str, set[str]]
    ) -> None:
        """Build reverse call graph: callee_name → set[caller_name].

        *calls* should map caller_name → set[callee_name].
        """
        for caller, callees in calls.items():
            for callee in callees:
                self.call_graph.setdefault(callee, set()).add(caller)

    def replace_call_graph(
        self, calls: dict[str, set[str]]
    ) -> None:
        """Replace the entire call graph with *calls*.

        Builds reverse call graph: caller→callee becomes callee→{callers}.
        Previous graph data is discarded.
        """
        self.call_graph.clear()
        for caller, callees in calls.items():
            for callee in callees:
                self.call_graph.setdefault(callee, set()).add(caller)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    @property
    def total_files(self) -> int:
        return len(self.sources)

    @property
    def total_functions(self) -> int:
        return len(self.funcs)

    def summary(self) -> dict[str, Any]:
        return {
            "files": self.total_files,
            "functions": self.total_functions,
            "languages": list(
                {s.language for s in self.sources.values()}
            ),
        }


# -----------------------------------------------------------------------
# Phase 1 output structures
# -----------------------------------------------------------------------


@dataclass
class CandidateFinding:
    """A candidate vulnerability produced by Phase 1 bulk analysis."""

    type: str
    """Vulnerability type: OutOfBoundsAccess, UseAfterFree, sqli, xss, etc."""

    severity: str = "medium"
    """critical / high / medium / low / info."""

    file_path: str = ""
    function_name: str = ""
    line_number: int = 0
    source_line: str = ""

    reason: str = ""
    """Why this is suspicious — the LLM's reasoning."""

    sink_type: str = ""
    """The sink category that triggered this finding."""

    invariant: str = ""
    """The assumption that must hold for this not to be a vulnerability."""

    confidence: str = "medium"
    """high / medium / low."""


@dataclass
class BulkAnalysisOutput:
    """Aggregated output from a Phase 1 bulk analysis run."""

    candidates: list[CandidateFinding] = field(default_factory=list)
    total_functions_analyzed: int = 0
    total_llm_calls: int = 0
    total_cost: float = 0.0
    elapsed_seconds: float = 0.0
