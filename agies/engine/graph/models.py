"""Unified graph data models for the pluggable GraphGenerator layer.

Provides ``ProgramGraph`` (function-level call graph with signals and scores),
``GraphNode``, ``GraphEdge``, and ``ProgramSlice`` as a replacement for the
scattered ``FunctionIndex.call_graph`` + ``EntryAnalysisCard`` + ``Tag`` pattern.

Two concrete ``GraphGenerator`` implementations exist:
  - ``TreeSitterGraphGenerator`` — wraps existing tree-sitter extraction
  - ``CodeQLGraphGenerator`` — parses CodeQL SARIF/CSV output (stub)

Usage::

    from agies.engine.graph.models import ProgramGraph, GraphNode

    pg = ProgramGraph()
    pg.add_node(node)
    pg.add_edge("caller_id", "callee_id")
    nx_g = pg.to_networkx()
    chain = pg.bfs_expand("entry_func")
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# GraphNode — one function in the program graph
# ---------------------------------------------------------------------------


@dataclass
class GraphNode:
    """A single function or method in the program graph.

    Maps from ``SourceFunction`` (function metadata) + ``Tag`` signals +
    PageRank/attack-path scores from the Director layer.
    """

    id: str
    """Globally unique identifier, e.g. ``utils/http.py::parse_request``."""

    name: str
    """Short function name, e.g. ``parse_request``."""

    qualified_name: str
    """Fully qualified name, e.g. ``utils.http.parse_request``."""

    file_path: str
    """Path to the source file (absolute or project-relative)."""

    line_start: int = 0
    """1-based start line of the function (including signature)."""

    line_end: int = 0
    """1-based end line of the function body."""

    signature: str = ""
    """Function signature text."""

    source_code: str | None = None
    """Full function body as source text (lazy-loaded)."""

    language: str = ""
    """Programming language (python, java, javascript, …)."""

    signals: dict[str, float] = field(default_factory=dict)
    """SAST signal types → accumulated multiplier, e.g. ``{"sql_sink": 80}``."""

    pagerank_score: float = 0.0
    """PageRank score from the file-level or function-level PageRank."""

    attack_path_score: float = 0.0
    """Attack-path contribution from ``compute_attack_path_scores``."""

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------

    @property
    def final_score(self) -> float:
        """Combined score (matching ``EntryAnalysisCard.final_score`` formula)."""
        return self.pagerank_score * 0.3 + self.attack_path_score * 0.7

    def __repr__(self) -> str:
        return f"<GraphNode {self.id} signals={list(self.signals)}>"


# ---------------------------------------------------------------------------
# GraphEdge — directed call edge
# ---------------------------------------------------------------------------


@dataclass
class GraphEdge:
    """A directed call edge from one function to another."""

    caller_id: str
    """Node ID of the calling function."""

    callee_id: str
    """Node ID of the called function."""

    call_sites: list[tuple[str, int]] = field(default_factory=list)
    """Locations where this call happens: ``[(file_path, line), …]``."""


# ---------------------------------------------------------------------------
# ProgramGraph — unified function-level call graph
# ---------------------------------------------------------------------------


class ProgramGraph:
    """Unified program graph combining call relationships, signals, and scores.

    Stores both forward (caller → callees) and reverse (callee → callers)
    edge maps for O(1) bidirectional lookup.  Also maintains file-level
    aggregates for backward compatibility with the Director's file-level
    PageRank and attack-path scoring.

    Key methods
    -----------
    - ``add_node`` / ``add_edge`` — mutation
    - ``get_callers`` / ``get_callees`` — O(1) bidirectional lookup
    - ``lookup`` / ``file_lookup`` — name-based and file-based queries
    - ``bfs_expand`` — forward BFS from an entry function (replaces
      ``aggregator.expand_call_chain``)
    - ``to_networkx`` — bridge to ``nx.DiGraph`` for ``has_path`` /
      ``descendants`` / ``ancestors``
    - ``call_graph`` — property returning ``{callee: {callers}}``, matching
      the shape of ``FunctionIndex.call_graph`` for backward compatibility
    """

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        """Node ID → GraphNode."""

        self._forward: dict[str, list[str]] = defaultdict(list)
        """caller_id → [callee_ids]."""

        self._reverse: dict[str, list[str]] = defaultdict(list)
        """callee_id → [caller_ids]."""

        self.file_nodes: dict[str, list[str]] = defaultdict(list)
        """file_path → [node_ids]."""

        self.name_index: dict[str, list[str]] = defaultdict(list)
        """short_name → [node_ids]."""

        self.file_signals: dict[str, dict[str, float]] = {}
        """file_path → {signal_type: total_mul} (file-level aggregate)."""

        self.file_scores: dict[str, float] = {}
        """file_path → PageRank score (file-level)."""

        self._nx_graph: Any = None
        """Cached ``nx.DiGraph`` (invalidated on mutation)."""

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add_node(self, node: GraphNode) -> None:
        """Insert a node into the graph."""
        self.nodes[node.id] = node
        self.file_nodes[node.file_path].append(node.id)
        self.name_index[node.name].append(node.id)
        self._nx_graph = None  # invalidate cache

    def add_edge(
        self,
        caller_id: str,
        callee_id: str,
        call_site: tuple[str, int] | None = None,
    ) -> None:
        """Add a directed call edge.

        Parameters
        ----------
        caller_id : str
            Node ID of the calling function (must already be in the graph).
        callee_id : str
            Node ID of the called function (must already be in the graph).
        call_site : (str, int) or None
            Optional ``(file_path, line)`` of the call site.
        """
        self._forward[caller_id].append(callee_id)
        self._reverse[callee_id].append(caller_id)
        self._nx_graph = None  # invalidate cache

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_callers(self, node_id: str) -> list[GraphNode]:
        """Return nodes that directly call *node_id*."""
        return [self.nodes[cid] for cid in self._reverse.get(node_id, [])
                if cid in self.nodes]

    def get_callees(self, node_id: str) -> list[GraphNode]:
        """Return nodes that *node_id* directly calls."""
        return [self.nodes[cid] for cid in self._forward.get(node_id, [])
                if cid in self.nodes]

    def lookup(self, name: str) -> list[GraphNode]:
        """Find all functions matching *name* (short name)."""
        return [self.nodes[nid] for nid in self.name_index.get(name, [])
                if nid in self.nodes]

    def file_lookup(self, file_path: str) -> list[GraphNode]:
        """Find all functions in a given file."""
        return [self.nodes[nid] for nid in self.file_nodes.get(file_path, [])
                if nid in self.nodes]

    # ------------------------------------------------------------------
    # BFS expansion (replaces aggregator.expand_call_chain)
    # ------------------------------------------------------------------

    def bfs_expand(
        self,
        entry: str,
        max_depth: int = 8,
        max_nodes: int = 30,
    ) -> list[tuple[str, GraphNode, int]]:
        """BFS-expand the call chain from *entry* (forward direction).

        Returns ordered ``[(function_name, GraphNode, depth), …]`` where
        depth=0 is the entry function itself.  Replaces
        ``aggregator.expand_call_chain``.
        """
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque()
        queue.append((entry, 0))
        chain: list[tuple[str, GraphNode, int]] = []

        while queue and len(chain) < max_nodes:
            name, depth = queue.popleft()
            if name in visited or depth > max_depth:
                continue
            visited.add(name)

            # Find nodes matching this name
            nodes = self.lookup(name)
            if nodes:
                chain.append((name, nodes[0], depth))

            # BFS forward: what does this function call?
            for nid in self.name_index.get(name, []):
                for callee_id in self._forward.get(nid, []):
                    callee_node = self.nodes.get(callee_id)
                    if callee_node and callee_node.name not in visited:
                        queue.append((callee_node.name, depth + 1))

        return chain

    # ------------------------------------------------------------------
    # NetworkX bridge
    # ------------------------------------------------------------------

    def to_networkx(self) -> Any:
        """Build or return a cached ``nx.DiGraph``.

        Edge weights default to 1.0.  This is used for ``has_path``,
        ``ancestors``, ``descendants`` in attack-path scoring.
        """
        if self._nx_graph is not None:
            return self._nx_graph

        try:
            import networkx as nx
        except ImportError:
            logger.warning("networkx not available; to_networkx() disabled")
            return None

        G = nx.DiGraph()

        for nid, node in self.nodes.items():
            G.add_node(nid, name=node.name, file=node.file_path)

        for caller_id, callee_ids in self._forward.items():
            for callee_id in callee_ids:
                G.add_edge(caller_id, callee_id, weight=1.0)

        self._nx_graph = G
        return G

    # ------------------------------------------------------------------
    # Backward-compat call_graph property
    # ------------------------------------------------------------------

    @property
    def call_graph(self) -> dict[str, set[str]]:
        """Return ``{callee_name: {caller_names}}`` — matches
        ``FunctionIndex.call_graph`` shape.

        This is used by legacy consumers like ``CallChainAnalyzer`` and
        ``expand_call_chain`` that expect the reverse-map format.
        """
        cg: dict[str, set[str]] = {}
        for caller_id, callee_ids in self._forward.items():
            caller_node = self.nodes.get(caller_id)
            if caller_node is None:
                continue
            for callee_id in callee_ids:
                callee_node = self.nodes.get(callee_id)
                if callee_node is None:
                    continue
                cg.setdefault(callee_node.name, set()).add(caller_node.name)
        return cg

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    @property
    def total_nodes(self) -> int:
        return len(self.nodes)

    @property
    def total_edges(self) -> int:
        return sum(len(v) for v in self._forward.values())

    def summary(self) -> dict[str, Any]:
        return {
            "nodes": self.total_nodes,
            "edges": self.total_edges,
            "files": len(self.file_nodes),
            "unique_names": len(self.name_index),
        }

    # ------------------------------------------------------------------
    # Factory: from existing FunctionIndex + Director data
    # ------------------------------------------------------------------

    @classmethod
    def from_components(
        cls,
        funcs: list,
        forward_calls: dict[str, set[str]],
        signals_map: dict[str, dict[str, float]],
        scores_map: dict[str, float],
    ) -> ProgramGraph:
        """Build a ProgramGraph from existing extraction results.

        Parameters
        ----------
        funcs : list[SourceFunction]
            Extracted functions from ``FunctionIndex.funcs``.
        forward_calls : dict[str, set[str]]
            Forward call graph: ``{caller_name: {callee_names}}``.  This is
            the output of ``extract_call_graph()`` / ``build_call_graph``.
        signals_map : dict[str, dict[str, float]]
            Node ID → {signal_type: multiplier}.  Can be built from
            ``file_tags`` by mapping file-level signal tags to functions.
        scores_map : dict[str, float]
            Node ID → PageRank score (file-level PageRank mapped to
            function nodes).
        """
        pg = cls()

        for fn in funcs:
            node_id = _make_node_id(fn.file_path, fn.fullname or fn.name)
            node = GraphNode(
                id=node_id,
                name=fn.name,
                qualified_name=fn.fullname or fn.name,
                file_path=fn.file_path,
                line_start=fn.line_start,
                line_end=fn.line_end,
                signature=fn.signature,
                source_code=fn.body,
                signals=signals_map.get(node_id, {}),
                pagerank_score=scores_map.get(node_id, 0.0),
            )
            pg.add_node(node)

        # Build edges from forward call graph
        for caller_name, callee_names in forward_calls.items():
            caller_ids = pg.name_index.get(caller_name, [])
            for callee_name in callee_names:
                callee_ids = pg.name_index.get(callee_name, [])
                for cid in caller_ids:
                    for cal in callee_ids:
                        pg.add_edge(cid, cal)

        return pg


# ---------------------------------------------------------------------------
# ProgramSlice — an attack path through the graph
# ---------------------------------------------------------------------------


@dataclass
class ProgramSlice:
    """A program slice: entry point → call chain → deepest reachable node.

    Replaces ``EntryAnalysisCard`` as the unit of analysis passed to LLM
    agents.  Each slice represents one attack path discovered by the
    Director/GraphGenerator.
    """

    entry_point: str
    """Node ID or function name of the entry point."""

    entry_type: str = ""
    """Type of entry: ``"function"``, ``"route"``, ``"class"``, …"""

    entry_file_path: str = ""
    """File path of the entry point."""

    entry_line: int = 0
    """Line number of the entry point."""

    path: list[GraphNode] = field(default_factory=list)
    """Ordered nodes along the call chain (entry → … → deepest)."""

    signals: list = field(default_factory=list)
    """Aggregated signal counts (``[(tag, count), …]`` or ``AggregatedSignal``)."""

    scores: dict[str, float] = field(default_factory=dict)
    """Named scores: ``{"pagerank": …, "attack_path": …, "final": …}``."""

    symbol_link_table: dict[str, str] = field(default_factory=dict)
    """Symbol → ``"file_path:line"`` for fast location lookup."""

    call_chain_depth: int = 0
    """Maximum depth of the call chain in this slice."""

    function_count: int = 0
    """Number of distinct functions in this slice."""

    # ------------------------------------------------------------------
    # Backward-compat converters
    # ------------------------------------------------------------------

    @property
    def final_score(self) -> float:
        return self.scores.get("final", 0.0)

    def to_entry_analysis_card(self) -> Any:
        """Convert to ``EntryAnalysisCard`` (backward compatibility).

        This allows consuming code (Brain, agents) that expects
        ``EntryAnalysisCard`` to continue working unchanged.
        """
        from agies.engine.v2.director.aggregator import (
            AggregatedSignal,
            EntryAnalysisCard,
            NodeMetadata,
        )

        functions_involved = []
        for gn in self.path:
            functions_involved.append(NodeMetadata(
                name=gn.name,
                file_path=gn.file_path,
                line=gn.line_start,
                final_score=gn.final_score,
                pagerank_score=gn.pagerank_score,
                attack_path_score=gn.attack_path_score,
                signal_types=list(gn.signals.keys()),
            ))

        # Deduplicate by name (keep first occurrence — typically the
        # shallowest in the call chain)
        seen_names: set[str] = set()
        deduped: list = []
        for meta in functions_involved:
            if meta.name not in seen_names:
                seen_names.add(meta.name)
                deduped.append(meta)
        functions_involved = deduped

        agg_signals = [
            AggregatedSignal(tag, count)
            for tag, count in self.signals
        ] if self.signals and isinstance(self.signals[0], tuple) else (
            list(self.signals)
        )

        return EntryAnalysisCard(
            entry=self.entry_point,
            entry_type=self.entry_type or "function",
            file_path=self.entry_file_path,
            line_number=self.entry_line,
            functions_involved=functions_involved,
            call_chain_depth=self.call_chain_depth,
            function_count=self.function_count or len(functions_involved),
            aggregated_signals=agg_signals,
            symbol_link_table=dict(self.symbol_link_table),
            final_score=self.final_score,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_node_id(file_path: str, func_name: str) -> str:
    """Build a globally unique node ID from file path and function name.

    Example: ``"src/utils.py::validate_input"``
    """
    return f"{file_path}::{func_name}"
