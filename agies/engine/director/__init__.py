"""Director — strategic entry-point ranking engine.

The Director replaces the old ``urgency_score`` heuristic with a risk-weighted
PageRank + attack-path reachability analysis to select which entry points
deserve LLM budget.

Pipeline::

    source files
      → repomap.py (tag extraction + PageRank with signal weights)
      → aggregator.py (has_path + card generation)
      → ranked EntryAnalysisCard list

Library mode guard: if entry points > 50, PageRank-select top 10 before
path analysis to prevent memory overflow.

Recursive agents can call ``get_neighbors(symbol)`` to expand beyond
preloaded functions at audit time.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from agies.engine.director.aggregator import (
    EntryAnalysisCard,
    NodeMetadata,
    build_symbol_link_table,
    compute_attack_path_scores,
    rank_cards,
)
from agies.engine.director.repomap import RepoMap
from agies.engine.director.signals import SIGNAL_MUL
from agies.engine.feedback import FeedbackStore

logger = logging.getLogger(__name__)

# Directories always skipped when walking source files
EXCLUDED_DIRS = frozenset({
    ".git", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    ".env", "dist", "build", ".tox", ".eggs", "egg-info",
    ".idea", ".vscode", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".terraform", ".next", ".nuxt", ".aider*", "__pycache__",
})

# Source file extensions we can analyze
SOURCE_EXTS = frozenset({
    ".py", ".pyw", ".java", ".js", ".jsx", ".ts", ".tsx",
    ".rb", ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".cc",
    ".cs", ".swift", ".kt", ".php",
})

# Entry point heuristics (file-level patterns)
ENTRY_POINT_PATTERNS: list[str] = [
    "main",
    "app",
    "cli",
    "server",
    "index",
    "__main__",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _walk_source_files(project_path: str) -> list[str]:
    """Walk *project_path* and return all parseable source file paths."""
    fnames: list[str] = []
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in SOURCE_EXTS:
                fnames.append(os.path.join(root, fname))
    return sorted(fnames)


def _detect_entry_points(
    fnames: list[str],
    file_tags: dict[str, set],
) -> set[str]:
    """Heuristic entry-point detection from file names and tag patterns.

    Priority:
      1. Files named like entry points (main.py, app.py, cli.py, …)
      2. Files containing ``main`` function definitions
      3. Files with route/serving signal tags
    """
    entry_points: set[str] = set()

    for fname in fnames:
        basename = Path(fname).stem.lower()
        if basename in ENTRY_POINT_PATTERNS:
            rel = os.path.relpath(fname, os.path.commonpath(fnames))
            entry_points.add(rel)

    # Look for main() functions in tags
    for rel_fname, tags in file_tags.items():
        for tag in tags:
            if tag.kind == "def" and tag.name == "main":
                entry_points.add(rel_fname)
            if tag.kind == "signal" and tag.signal_type in (
                "network_operation", "cmd_exec",
            ):
                entry_points.add(rel_fname)

    # If still empty, use top PageRank file if available
    if not entry_points and fnames:
        rel = os.path.relpath(fnames[0], os.path.commonpath(fnames))
        entry_points.add(rel)

    return entry_points


# ---------------------------------------------------------------------------
# Director
# ---------------------------------------------------------------------------


class Director:
    """Strategic analysis director — ranks entry points by risk.

    Usage::

        director = Director("/path/to/project")
        cards = director.run()
        for card in cards[:5]:
            print(f"{card.entry}: {card.final_score:.3f}")
    """

    def __init__(
        self,
        project_path: str,
        entry_points: set[str] | None = None,
        signal_mul: dict[str, float] | None = None,
        repomap: RepoMap | None = None,
        feedback_store: FeedbackStore | None = None,
    ) -> None:
        self.project_path = project_path
        self.entry_points = entry_points
        self.signal_mul = signal_mul or dict(SIGNAL_MUL)
        self._repomap = repomap or RepoMap(root=project_path)
        self._feedback_store = feedback_store or FeedbackStore()

        # Held by run() for get_neighbors()
        self._file_tags: dict[str, set] = {}
        self._last_cards: list[EntryAnalysisCard] = []

    def repo_map(self) -> RepoMap:
        """Access the underlying RepoMap instance (lazy)."""
        return self._repomap

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------

    def run(
        self,
        max_cards: int = 15,
        library_mode: bool = False,
    ) -> list[EntryAnalysisCard]:
        """Run the full Director pipeline.

        Parameters
        ----------
        max_cards : int
            Maximum number of cards to return.  Default 15.
        library_mode : bool
            If True and entry points > 50, apply PageRank pre-filter to
            top 10 before path analysis (prevents memory overflow).

        Returns
        -------
        list[EntryAnalysisCard]
            Ranked cards, highest risk first.
        """
        # Step 1: Discover source files
        fnames = _walk_source_files(self.project_path)
        if not fnames:
            logger.warning("Director: no source files found in %s", self.project_path)
            return []

        logger.info(
            "Director: found %d source files in %s",
            len(fnames),
            self.project_path,
        )

        # Step 1.5: SAST pre-scan -- identify files with critical sink
        # patterns (pickle.loads, eval, exec, etc.) using existing
        # tree-sitter rules in engine/rules/.  These files get a 100x
        # personalization boost in the PageRank so they naturally rank
        # at the top and enter the LLM analysis budget.
        prescan_sinks: set[str] = set()
        try:
            from agies.engine.sast.matcher import get_matcher as _get_sast_matcher
            _sm = _get_sast_matcher()
            for fname in fnames:
                rel = os.path.relpath(fname, os.path.commonpath(fnames))
                matches = _sm.match_file(fname)
                if matches:
                    prescan_sinks.add(rel)
                    logger.debug(
                        "SAST pre-scan: matched %d rule(s) in %s",
                        len(matches), rel,
                    )
            if prescan_sinks:
                logger.info(
                    "Director: SAST pre-scan found %d file(s) with critical sink patterns",
                    len(prescan_sinks),
                )
        except Exception as exc:
            logger.debug("SAST pre-scan skipped: %s", exc)

        # Step 2: Build graph with signal-weighted PageRank
        confirmed_idents = self._feedback_store.get_confirmed_idents()
        suppressed_files = self._feedback_store.get_suppressed_files()
        G, pr_scores, ranked_tags, file_tags = self._repomap.build_graph(
            fnames=fnames,
            entry_points=self.entry_points or set(),
            signal_mul=self.signal_mul,
            confirmed_idents=confirmed_idents,
            suppressed_files=suppressed_files,
            prescan_sinks=prescan_sinks,
        )
        self._file_tags = file_tags

        if not G or not pr_scores:
            logger.warning("Director: PageRank produced empty graph")
            return []

        # Step 3: Detect entry points (if not provided)
        if not self.entry_points:
            self.entry_points = _detect_entry_points(fnames, file_tags)

        # Critical sinks from SAST pre-scan are automatically promoted to
        # entry points so they receive analysis cards.  Without this, a file
        # like runner_app.py (pickle.loads) would only be a sink node and
        # never generate a card — exactly the bug the old _SINK_PATTERNS
        # hack in brain.py was working around.
        if prescan_sinks:
            added = prescan_sinks - self.entry_points
            if added:
                self.entry_points |= prescan_sinks
                logger.info(
                    "Director: promoted %d critical-sink file(s) to entry points",
                    len(added),
                )

        logger.info(
            "Director: %d entry points, %d graph nodes",
            len(self.entry_points),
            len(G),
        )

        # --- Library mode guard ---
        if library_mode and len(self.entry_points) > 50:
            # Sort entry points by PageRank, take top 10
            eps_sorted = sorted(
                self.entry_points,
                key=lambda ep: pr_scores.get(ep, 0),
                reverse=True,
            )
            self.entry_points = set(eps_sorted[:10])
            logger.info(
                "Director: library mode — reduced to top 10 entry points by PageRank"
            )

            # Re-add SAST-prescan critical sink files that were dropped
            # by the PageRank filter.  Without this, picking 190 files that
            # contain pickle.load, subprocess, etc. get cards but land in
            # cold territory and never enter bulk analysis.
            if prescan_sinks:
                dropped = prescan_sinks - self.entry_points
                if dropped:
                    self.entry_points |= dropped
                    logger.info(
                        "Director: re-added %d SAST critical-sink file(s) after library filter",
                        len(dropped),
                    )

        # Step 4: Identify sinks (nodes with high-risk signals)
        sinks: set[str] = set()
        for rel_fname, tags in file_tags.items():
            for tag in tags:
                if tag.kind == "signal" and tag.signal_type in (
                    "sql_sink", "cmd_exec", "dynamic_exec",
                ):
                    # Use the node's rel_fname as its graph identifier
                    sinks.add(rel_fname)
                elif tag.kind == "signal" and tag.signal_type in (
                    "serialization", "file_io", "critical_sink",
                ):
                    sinks.add(rel_fname)

        if not sinks:
            # Fallback: use all nodes as potential sinks
            sinks = set(G.nodes)

        # Step 5: Attack-path scores
        attack_scores = compute_attack_path_scores(
            G,
            entry_points=list(self.entry_points),
            sinks=list(sinks),
        )

        # Step 6: Rank cards
        cards = rank_cards(
            G=G,
            entry_points=self.entry_points,
            pagerank_scores=pr_scores,
            attack_scores=attack_scores,
            file_tags=file_tags,
            signal_mul=self.signal_mul,
        )

        # Step 7: Apply max_cards limit
        cards = cards[:max_cards]

        # Step 8: Build symbol_link_table for each card
        for card in cards:
            card.symbol_link_table = build_symbol_link_table(
                card.functions_involved
            )

            # Refine file_path for the entry
            for fn in card.functions_involved:
                if fn.name == card.entry:
                    card.file_path = fn.file_path
                    card.line_number = fn.line
                    break

        self._last_cards = cards
        logger.info(
            "Director: produced %d cards (top: %s = %.4f)",
            len(cards),
            cards[0].entry if cards else "none",
            cards[0].final_score if cards else 0,
        )
        return cards

    # ------------------------------------------------------------------
    # Recursive expansion
    # ------------------------------------------------------------------

    def get_neighbors(
        self,
        symbol: str,
    ) -> list[NodeMetadata]:
        """Return metadata for functions related to *symbol*.

        Called by recursive agents that want to explore additional
        functions beyond those preloaded in the cards.
        """
        tags = self._repomap.get_neighbors(symbol, self._file_tags)
        nodes: list[NodeMetadata] = []
        seen: set[str] = set()
        for tag in tags:
            if tag.name not in seen:
                seen.add(tag.name)
                nodes.append(NodeMetadata(
                    name=tag.name,
                    file_path=tag.fname or tag.rel_fname,
                    line=tag.line,
                ))
        return nodes

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a human-readable summary of the last run."""
        if not self._last_cards:
            return "Director: no cards (run() not called yet)"
        lines: list[str] = [
            f"Director: {len(self._last_cards)} cards",
            f"{'Score':>10} {'Entry Point':<30} {'Depth':<6} {'Signals'}",
            f"{'-'*10} {'-'*30} {'-'*6} {'-'*20}",
        ]
        for card in self._last_cards[:10]:
            sigs = ", ".join(s.tag for s in card.aggregated_signals[:3])
            lines.append(
                f"{card.final_score:>10.4f} {card.entry:<30} "
                f"{card.call_chain_depth:<6} {sigs}"
            )
        return "\n".join(lines)
