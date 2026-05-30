"""Pluggable ``GraphGenerator`` abstract interface.

Defines the contract that all graph generators must implement:

- ``build_program_graph()`` — the main entry point
- ``get_source_code()`` — source text for a function node
- ``get_node_signals()`` — SAST signals for a function node

Default implementations are provided for graph-theoretic operations
(PageRank, attack-path scoring, slice creation) that do not depend on
how the graph was built.

Usage::

    class MyGenerator(GraphGenerator):
        def build_program_graph(self, project_path, **kw):
            pg = ProgramGraph()
            # ... populate ...
            return pg

    pg = generator.build_program_graph("/path/to/project")
    slices = generator.create_slices(pg, entry_points)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class GraphGenerator(ABC):
    """Pluggable interface for building a ``ProgramGraph`` from source code.

    Two implementations exist:
      - ``TreeSitterGraphGenerator`` — wraps existing tree-sitter pipeline
      - ``CodeQLGraphGenerator`` — parses CodeQL SARIF/CSV output (stub)

    Switching generators means changing one import in the consuming code.
    """

    # ------------------------------------------------------------------
    # Abstract methods (must be implemented by every generator)
    # ------------------------------------------------------------------

    @abstractmethod
    def build_program_graph(
        self,
        project_path: str,
        entry_points: set[str] | None = None,
        signal_mul: dict[str, float] | None = None,
        feedback_store: Any = None,
        prescan_sinks: set[str] | None = None,
        mentioned_fnames: set[str] | None = None,
        mentioned_idents: set[str] | None = None,
        confirmed_idents: set[str] | None = None,
        suppressed_files: set[str] | None = None,
    ) -> Any:
        """Build the complete program graph for *project_path*.

        Returns a ``ProgramGraph`` populated with function nodes, call
        edges, file-level signal aggregates, and PageRank scores.

        Parameters
        ----------
        project_path : str
            Root directory of the project to analyse.
        entry_points : set[str] or None
            File paths of known entry points (gets personalization boost).
        signal_mul : dict[str, float] or None
            Signal-type → multiplier overrides.  Falls back to
            ``SIGNAL_MUL`` from ``director/signals.py``.
        feedback_store : FeedbackStore or None
            Previous-scan feedback for confirmed-idents / suppressed-files.
        prescan_sinks : set[str] or None
            File paths flagged by SAST pre-scan (gets extra boost).
        mentioned_fnames : set[str] or None
            File names explicitly referenced in user config or CLI.
        mentioned_idents : set[str] or None
            Identifiers explicitly referenced.
        confirmed_idents : set[str] or None
            Identifiers confirmed in previous scans (gets 5x boost).
        suppressed_files : set[str] or None
            Files with repeated false positives (gets 0.3x suppression).

        Returns
        -------
        ProgramGraph
            Fully populated program graph.
        """
        ...

    @abstractmethod
    def get_source_code(self, node_id: str) -> str | None:
        """Return the full source text for a function node.

        Parameters
        ----------
        node_id : str
            Globally unique node ID (``"file.py::func_name"``).

        Returns
        -------
        str or None
            The function body as source text, or None if not available.
        """
        ...

    @abstractmethod
    def get_node_signals(self, node_id: str) -> dict[str, float]:
        """Return SAST signals for a function node.

        Parameters
        ----------
        node_id : str
            Globally unique node ID.

        Returns
        -------
        dict[str, float]
            ``{signal_type: accumulated_multiplier}``, e.g.
            ``{"sql_sink": 80, "file_io": 10}``.  Empty dict if none.
        """
        ...

    # ------------------------------------------------------------------
    # Default implementations (graph-theoretic, generator-agnostic)
    # ------------------------------------------------------------------

    def compute_page_rank(
        self,
        graph: Any,
        personalization: dict[str, float] | None = None,
    ) -> dict[str, float]:
        """Run PageRank on the graph.

        Default implementation delegates to
        ``agies.engine.director.repomap._pagerank_pure``.

        Parameters
        ----------
        graph : ProgramGraph
            The program graph to rank.
        personalization : dict[str, float] or None
            Node ID → personalization weight.  ``None`` → uniform.

        Returns
        -------
        dict[str, float]
            Node ID → PageRank score.
        """
        nx_g = graph.to_networkx()
        if nx_g is None:
            return {}

        from agies.engine.v2.director.repomap import _pagerank_pure

        personalization = personalization or {
            n: 1.0 / len(nx_g.nodes)
            for n in nx_g.nodes
        }
        return _pagerank_pure(nx_g, weight="weight",
                              personalization=personalization)

    def compute_attack_paths(
        self,
        graph: Any,
        entries: list[str],
        sinks: list[str],
    ) -> dict[str, float]:
        """Score nodes on attack paths from *entries* to *sinks*.

        For each (entry, sink) pair where ``nx.has_path(G, entry, sink)``,
        every node that is both a descendant of *entry* and an ancestor of
        *sink* receives +500 score.

        Default implementation uses ``networkx`` directly on the graph's
        ``to_networkx()`` bridge, matching the logic in
        ``aggregator.compute_attack_path_scores``.

        Parameters
        ----------
        graph : ProgramGraph
        entries : list[str]
            Entry point node IDs.
        sinks : list[str]
            Sink node IDs.

        Returns
        -------
        dict[str, float]
            Node ID → accumulated attack-path score.
        """
        nx_g = graph.to_networkx()
        if nx_g is None:
            return {}

        import networkx as nx

        scores: dict[str, float] = {}
        for entry in entries:
            if entry not in nx_g:
                continue
            for sink in sinks:
                if sink not in nx_g:
                    continue
                try:
                    if nx.has_path(nx_g, entry, sink):
                        path_nodes = (
                            nx.descendants(nx_g, entry)
                            & nx.ancestors(nx_g, sink)
                        )
                        for n in path_nodes:
                            scores[n] = scores.get(n, 0.0) + 500.0
                except (nx.NetworkXError, nx.NetworkXNoPath):
                    continue

        return scores

    def create_slices(
        self,
        graph: Any,
        entry_points: set[str],
        signal_mul: dict[str, float] | None = None,
        max_slices: int = 15,
    ) -> list:
        """Create ranked ``ProgramSlice`` objects from the graph and entry points.

        Default implementation ranks entry points by combined score and
        produces a ``ProgramSlice`` for each.

        Parameters
        ----------
        graph : ProgramGraph
        entry_points : set[str]
            Set of entry point node IDs or function names.
        signal_mul : dict[str, float] or None
            Signal multiplier configuration (for aggregate signal display).
        max_slices : int
            Maximum number of slices to return (default 15).

        Returns
        -------
        list[ProgramSlice]
            Ranked slices, highest score first.
        """
        from agies.engine.graph.models import ProgramSlice, GraphNode

        if signal_mul is None:
            from agies.engine.v2.director.signals import SIGNAL_MUL
            signal_mul = SIGNAL_MUL

        slices: list[ProgramSlice] = []

        for ep in entry_points:
            # Find the entry node(s)
            ep_nodes = graph.lookup(ep)
            if not ep_nodes:
                continue
            ep_node = ep_nodes[0]

            # Expand call chain
            chain = graph.bfs_expand(ep, max_depth=8, max_nodes=30)
            path_nodes = [gn for _, gn, _ in chain] if chain else [ep_node]

            # Build symbol_link_table
            sym_table: dict[str, str] = {}
            for gn in path_nodes:
                if gn.name not in sym_table:
                    sym_table[gn.name] = f"{gn.file_path}:{gn.line_start}"

            # Aggregate signals across the path
            signal_counts: dict[str, int] = {}
            for gn in path_nodes:
                for sig in gn.signals:
                    signal_counts[sig] = signal_counts.get(sig, 0) + 1

            # Compute scores
            max_pr = max(
                (n.pagerank_score for n in path_nodes),
                default=0.0,
            )
            max_ap = max(
                (n.attack_path_score for n in path_nodes),
                default=0.0,
            )
            final_score = max_pr * 0.3 + max_ap * 0.7

            slice_obj = ProgramSlice(
                entry_point=ep,
                entry_type="function",
                entry_file_path=ep_node.file_path,
                entry_line=ep_node.line_start,
                path=path_nodes,
                signals=list(signal_counts.items()),
                scores={
                    "pagerank": max_pr,
                    "attack_path": max_ap,
                    "final": final_score,
                },
                symbol_link_table=sym_table,
                call_chain_depth=max(
                    (d for _, _, d in chain),
                    default=0,
                ),
                function_count=len(path_nodes),
            )
            slices.append(slice_obj)

        # Sort by final_score descending
        slices.sort(key=lambda s: s.final_score, reverse=True)
        return slices[:max_slices]
