"""``TreeSitterGraphGenerator`` — wraps existing tree-sitter extraction
into the ``GraphGenerator`` interface.

Wraps these existing components without rewriting them:

- ``_walk_source_files`` (director/__init__.py)
- ``RepoMap.build_graph`` (director/repomap.py)
- ``loader.build_index`` (sourcer/loader.py)
- ``rank_cards`` / ``compute_attack_path_scores`` (director/aggregator.py)
- ``SASTMatcher`` (engine/sast/matcher.py)
"""

from __future__ import annotations

import logging
import os
from typing import Any

from agies.engine.graph.base import GraphGenerator
from agies.engine.graph.models import (
    GraphNode,
    ProgramGraph,
    ProgramSlice,
    _make_node_id,
)

logger = logging.getLogger(__name__)


class TreeSitterGraphGenerator(GraphGenerator):
    """GraphGenerator implementation using tree-sitter for code analysis.

    Wraps the existing Director/RepoMap/Sourcer pipeline into the clean
    ``GraphGenerator`` interface so that consumers (Brain, agents) interact
    with ``ProgramGraph``/``ProgramSlice`` instead of scattered data types.

    Usage::

        gen = TreeSitterGraphGenerator()
        pg = gen.build_program_graph("/path/to/project")
        slices = gen.create_slices(pg, entry_points=...)
    """

    def __init__(
        self,
        signal_mul: dict[str, float] | None = None,
    ) -> None:
        self._signal_mul = signal_mul
        self._source_cache: dict[str, str] = {}
        """Cache for ``get_source_code()``, keyed by node ID."""

        self._signal_cache: dict[str, dict[str, float]] = {}
        """Cache for ``get_node_signals()``, keyed by node ID."""

        self._repomap: Any = None
        """Lazy-created ``RepoMap`` instance."""

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

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
    ) -> ProgramGraph:
        """Build a ``ProgramGraph`` by wrapping the Director pipeline.

        This method reuses the same code path as ``Director.run()`` but
        outputs a ``ProgramGraph`` instead of ``EntryAnalysisCard`` lists.
        """
        sm = signal_mul or self._signal_mul or _default_signal_mul()

        # Step 1: Discover source files
        from agies.engine.v2.director import _walk_source_files
        fnames = _walk_source_files(project_path)
        if not fnames:
            logger.warning("TreeSitterGraphGenerator: no source files in %s",
                           project_path)
            return ProgramGraph()

        logger.info(
            "TreeSitterGraphGenerator: %d source files",
            len(fnames),
        )

        # Step 1.5: SAST pre-scan
        if prescan_sinks is None:
            prescan_sinks = self._run_sast_prescan(fnames)

        # Step 2: Build RepoMap graph (tags + PageRank)
        from agies.engine.v2.director.repomap import RepoMap
        rm = self._get_repomap(project_path)

        confirmed = (confirmed_idents
                     or (feedback_store.get_confirmed_idents()
                         if feedback_store else set()))
        suppressed = (suppressed_files
                      or (feedback_store.get_suppressed_files()
                          if feedback_store else set()))

        G, pr_scores, ranked_tags, file_tags = rm.build_graph(
            fnames=fnames,
            entry_points=entry_points or set(),
            signal_mul=sm,
            confirmed_idents=confirmed,
            suppressed_files=suppressed,
            prescan_sinks=prescan_sinks,
        )
        if not G or not pr_scores:
            logger.warning("TreeSitterGraphGenerator: PageRank produced empty graph")
            return ProgramGraph()

        # Step 3: Detect entry points
        from agies.engine.v2.director import _detect_entry_points
        eps = entry_points or _detect_entry_points(fnames, file_tags)

        # Promote SAST prescan sinks to entry points
        if prescan_sinks:
            eps |= prescan_sinks

        # Step 3.5: Build FunctionIndex
        from agies.engine.v2.sourcer.loader import build_index
        fi = build_index(project_path, full_index_paths=set(eps))

        # Step 4: Identify sinks for attack-path scoring
        sinks: set[str] = set()
        for rel_fname, tags in file_tags.items():
            for tag in tags:
                if tag.kind == "signal" and tag.signal_type in (
                    "sql_sink", "cmd_exec", "dynamic_exec",
                    "serialization", "file_io", "critical_sink",
                ):
                    sinks.add(rel_fname)

        if not sinks:
            sinks = set(G.nodes)

        # Step 5: Attack-path scores
        from agies.engine.v2.director.aggregator import compute_attack_path_scores
        attack_scores = compute_attack_path_scores(
            G,
            entry_points=list(eps),
            sinks=list(sinks),
        )

        # Step 6: Merge into ProgramGraph
        pg = self._merge(fi, file_tags, pr_scores, attack_scores)

        # Cache for get_source_code()
        for path, sf in fi.sources.items():
            abs_path = os.path.normpath(os.path.join(project_path, path)) \
                if not os.path.isabs(path) else path
            self._source_cache[abs_path] = sf.source

        # Cache for get_node_signals()
        for nid, node in pg.nodes.items():
            self._signal_cache[nid] = dict(node.signals)

        return pg

    def get_source_code(self, node_id: str) -> str | None:
        """Return the source text for a function node from cache."""
        return self._source_cache.get(_node_id_file(node_id))

    def get_node_signals(self, node_id: str) -> dict[str, float]:
        """Return SAST signals for a function node from cache."""
        return self._signal_cache.get(node_id, {})

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_repomap(self, project_path: str) -> Any:
        """Lazy-create a ``RepoMap`` instance for *project_path*."""
        if self._repomap is None:
            from agies.engine.v2.director.repomap import RepoMap
            self._repomap = RepoMap(root=project_path)
        return self._repomap

    def _run_sast_prescan(
        self,
        fnames: list[str],
    ) -> set[str]:
        """Run SAST pre-scan, returning file paths with critical sink patterns.

        Reuses the same matcher as ``Director.run()``.
        """
        prescan_sinks: set[str] = set()
        try:
            from agies.engine.v2.sast.matcher import get_matcher as _get_sast_matcher
            _sm = _get_sast_matcher()
            common = os.path.commonpath(fnames) if fnames else ""
            for fname in fnames:
                rel = os.path.relpath(fname, common) if common else fname
                matches = _sm.match_file(fname)
                if matches:
                    prescan_sinks.add(rel)
            if prescan_sinks:
                logger.info(
                    "TreeSitterGraphGenerator: SAST pre-scan found "
                    "%d file(s) with critical sink patterns",
                    len(prescan_sinks),
                )
        except Exception as exc:
            logger.debug("SAST pre-scan skipped: %s", exc)
        return prescan_sinks

    def _merge(
        self,
        fi: Any,
        file_tags: dict[str, set[Any]],
        pr_scores: dict[str, float],
        attack_scores: dict[str, float],
    ) -> ProgramGraph:
        """Merge FunctionIndex + RepoMap data into a ProgramGraph.

        Parameters
        ----------
        fi : FunctionIndex
            Extracted functions and call graph.
        file_tags : dict[str, set[Tag]]
            File-level tags from ``RepoMap.build_graph``.  Keyed by relative
            file path.
        pr_scores : dict[str, float]
            File-level PageRank scores, keyed by relative file path.
        attack_scores : dict[str, float]
            Attack-path scores, keyed by file path (relative or absolute).
        """
        from agies.engine.v2.director.repomap import Tag

        pg = ProgramGraph()

        # Build a map: file_path (relative) → signal map from file_tags
        file_signal_map: dict[str, dict[str, float]] = {}
        for rel_fname, tags in file_tags.items():
            signal_dict: dict[str, float] = {}
            for tag in tags:
                if tag.kind == "signal" and tag.signal_type:
                    signal_dict[tag.signal_type] = signal_dict.get(
                        tag.signal_type, 0.0
                    ) + pr_scores.get(tag.rel_fname, 1.0)
            if signal_dict:
                file_signal_map[rel_fname] = signal_dict

        for fn in fi.funcs:
            node_id = _make_node_id(fn.file_path, fn.fullname or fn.name)

            # Map file-level signals to this function
            matched_key = _best_file_key(fn.file_path, file_signal_map)
            signals = file_signal_map.get(matched_key, {})

            # Map file-level scores
            pr = pr_scores.get(matched_key, 0.0)
            ap = attack_scores.get(matched_key, 0.0)

            node = GraphNode(
                id=node_id,
                name=fn.name,
                qualified_name=fn.fullname or fn.name,
                file_path=fn.file_path,
                line_start=fn.line_start,
                line_end=fn.line_end,
                signature=fn.signature,
                source_code=fn.body,
                signals=signals,
                pagerank_score=pr,
                attack_path_score=ap,
            )
            pg.add_node(node)

        # Build forward call graph — per-file only to avoid false edges
        # when functions in different files happen to share names.
        # fi.call_graph is {callee_name → {caller_names}} (merged globally)
        # fi.file_index is {file_path → [SourceFunction]}
        # We iterate per-file and only create edges within the same file.
        file_name_ids: dict[str, dict[str, list[str]]] = {}
        for fn in fi.funcs:
            nid = _make_node_id(fn.file_path, fn.fullname or fn.name)
            if nid in pg.nodes:
                file_name_ids.setdefault(fn.file_path, {}).setdefault(fn.name, []).append(nid)

        for file_path, name_idx in file_name_ids.items():
            file_names = set(name_idx.keys())
            for callee_name, caller_names in fi.call_graph.items():
                if callee_name not in file_names:
                    continue
                for caller_name in caller_names:
                    if caller_name not in file_names:
                        continue
                    for cid in name_idx[caller_name]:
                        for cal in name_idx[callee_name]:
                            pg.add_edge(cid, cal)

        # Store file-level aggregates
        pg.file_signals = dict(file_signal_map)
        pg.file_scores = dict(pr_scores)

        return pg

    # ------------------------------------------------------------------
    # Slice creation (override default for backward compat)
    # ------------------------------------------------------------------

    def create_slices(
        self,
        graph: ProgramGraph,
        entry_points: set[str],
        signal_mul: dict[str, float] | None = None,
        max_slices: int = 15,
    ) -> list[ProgramSlice]:
        """Create ranked slices from *entry_points*.

        Uses BFS expansion for each entry point, then sorts by
        combined PageRank x 0.3 + Attack-path x 0.7.
        """
        from agies.engine.graph.models import ProgramSlice

        sm = signal_mul or self._signal_mul or _default_signal_mul()

        slices: list[ProgramSlice] = []

        for ep in sorted(entry_points):
            ep_nodes = graph.lookup(ep)
            if not ep_nodes:
                # Try as a file path
                ep_nodes = graph.file_lookup(ep)
            if not ep_nodes:
                continue

            ep_node = ep_nodes[0]
            # Find what functions this entry reaches
            chain = graph.bfs_expand(ep_node.name, max_depth=8, max_nodes=30)
            path_nodes = [gn for _, gn, _ in chain] if chain else [ep_node]

            # Build symbol table
            sym_table: dict[str, str] = {}
            for gn in path_nodes:
                if gn.name not in sym_table:
                    sym_table[gn.name] = f"{gn.file_path}:{gn.line_start}"

            # Aggregate signals
            signal_counts: dict[str, int] = {}
            for gn in path_nodes:
                for sig in gn.signals:
                    signal_counts[sig] = signal_counts.get(sig, 0) + 1

            # Scores
            max_pr = max((n.pagerank_score for n in path_nodes), default=0.0)
            max_ap = max((n.attack_path_score for n in path_nodes), default=0.0)
            final_score = max_pr * 0.3 + max_ap * 0.7

            sl = ProgramSlice(
                entry_point=ep_node.name,
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
                call_chain_depth=max((d for _, _, d in chain), default=0),
                function_count=len(path_nodes),
            )
            slices.append(sl)

        slices.sort(key=lambda s: s.final_score, reverse=True)
        return slices[:max_slices]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _default_signal_mul() -> dict[str, float]:
    """Return the default SIGNAL_MUL from director/signals.py."""
    from agies.engine.v2.director.signals import SIGNAL_MUL
    return dict(SIGNAL_MUL)


def _node_id_file(node_id: str) -> str:
    """Extract the file path portion from a node ID.

    ``"src/main.py::run"`` → ``"src/main.py"``
    """
    if "::" in node_id:
        return node_id.rsplit("::", 1)[0]
    return node_id


def _best_file_key(
    file_path: str,
    signal_map: dict[str, dict[str, float]],
) -> str:
    """Find the best matching key in *signal_map* for *file_path*.

    Tries exact match, then basename-only match, then suffix match.
    Returns empty string if no match.
    """
    if file_path in signal_map:
        return file_path

    base = os.path.basename(file_path)
    for key in signal_map:
        if os.path.basename(key) == base:
            return key
    for key in signal_map:
        if file_path.endswith(key) or key.endswith(file_path):
            return key

    # Try normalised absolute
    abs_fp = os.path.normpath(file_path)
    for key in signal_map:
        if os.path.normpath(key) == abs_fp:
            return key

    return ""
