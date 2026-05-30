"""Attack-chain card generation for the Director layer.

Takes the PageRank output + call graph from ``repomap.py`` and applies
``has_path`` reachability analysis to produce ranked ``EntryAnalysisCard`` s.

Each card represents an entry point and its call chain, enriched with
``NodeMetadata`` (final_score, signal_types) and a ``symbol_link_table``
for fast symbol → location lookup by downstream recursive agents.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class NodeMetadata:
    """Per-function metadata attached to each item in ``functions_involved``."""

    name: str
    file_path: str
    line: int
    final_score: float = 0.0
    pagerank_score: float = 0.0
    attack_path_score: float = 0.0
    signal_types: list[str] = field(default_factory=list)


@dataclass
class AggregatedSignal:
    """Aggregated signal count for a card."""

    tag: str  # e.g. "sql_sink"
    count: int = 0


@dataclass
class EntryAnalysisCard:
    """Analysis card for one entry point — the Director's primary output unit.

    The ``symbol_link_table`` maps each function name involved in the
    call chain to its physical location (``"file_path:line"``), enabling
    downstream recursive agents to instantly locate any function.
    """

    entry: str  # Function / symbol name of the entry point
    entry_type: str  # e.g. "function", "class", "route"
    file_path: str
    line_number: int
    functions_involved: list[NodeMetadata] = field(default_factory=list)
    call_chain_depth: int = 0
    function_count: int = 0
    aggregated_signals: list[AggregatedSignal] = field(default_factory=list)
    symbol_link_table: dict[str, str] = field(default_factory=dict)
    final_score: float = 0.0


# ---------------------------------------------------------------------------
# symbol_link_table builder
# ---------------------------------------------------------------------------


def build_symbol_link_table(functions: list[NodeMetadata]) -> dict[str, str]:
    """Build ``symbol → "file_path:line"`` lookup."""
    table: dict[str, str] = {}
    for fn in functions:
        # First occurrence wins (most important)
        if fn.name not in table:
            table[fn.name] = f"{fn.file_path}:{fn.line}"
    return table


# ---------------------------------------------------------------------------
# has_path reachability
# ---------------------------------------------------------------------------


def compute_attack_path_scores(
    G: Any,
    entry_points: list[str],
    sinks: list[str],
) -> dict[str, float]:
    """Score nodes on attack paths from entry points to sinks.

    For each (entry, sink) pair where ``nx.has_path(G, entry, sink)``,
    every node that is both a descendent of *entry* and an ancestor of
    *sink* (i.e., on a potential attack path) gets a score boost.

    Uses set intersection of ``nx.descendants`` and ``nx.ancestors`` to
    handle parallel/multiple paths between the same entry and sink.

    Returns
    -------
    dict[node, score]
        Accumulated attack-path score per node.  Each path adds 500 to
        every node on it.
    """
    import networkx as nx

    scores: dict[str, float] = defaultdict(float)
    for sink in sinks:
        if sink not in G:
            continue
        ancestors = nx.ancestors(G, sink)
        for entry in entry_points:
            if entry not in G:
                continue
            if not nx.has_path(G, entry, sink):
                continue
            descendants = nx.descendants(G, entry)
            on_path = ancestors & descendants
            for node in on_path:
                scores[node] += 500
            # Also boost the entry and sink themselves
            scores[entry] += 500
            scores[sink] += 500

    return dict(scores)


# ---------------------------------------------------------------------------
# Card ranking
# ---------------------------------------------------------------------------


def _aggregate_signals(file_tags: dict[str, set], entry: str) -> list[AggregatedSignal]:
    """Collect and count signal types touching *entry*."""
    counts: dict[str, int] = defaultdict(int)
    for rel_fname, tags in file_tags.items():
        for tag in tags:
            if tag.kind == "signal" and tag.name:
                counts[tag.signal_type] += 1
    return [
        AggregatedSignal(tag=st, count=c)
        for st, c in sorted(counts.items(), key=lambda x: -x[1])
    ]


def rank_cards(
    G: Any,
    entry_points: set[str],
    pagerank_scores: dict[str, float],
    attack_scores: dict[str, float],
    file_tags: dict[str, set],
    signal_mul: dict[str, float] | None = None,
) -> list[EntryAnalysisCard]:
    """Build and rank cards from PageRank + attack-path scores.

    Final score formula::

        final = pagerank_score * 0.3 + attack_path_score * 0.7

    Cards are sorted by ``final_score`` descending.
    """
    signal_mul = signal_mul or {}
    cards: list[EntryAnalysisCard] = []

    for ep in entry_points:
        pr = pagerank_scores.get(ep, 0)
        ap = attack_scores.get(ep, 0)
        final = pr * 0.3 + ap * 0.7

        # Build functions_involved from file_tags — only the entry point's
        # own file, so each card carries only its own functions.
        functions: list[NodeMetadata] = []
        seen_fns: set[str] = set()
        signals_for_card: list[str] = []

        ep_tags = file_tags.get(ep, set())
        for tag in ep_tags:
            if tag.name not in seen_fns:
                seen_fns.add(tag.name)
                sig_types: list[str] = []
                if tag.kind == "signal" and tag.signal_type:
                    sig_types.append(tag.signal_type)
                    signals_for_card.append(tag.signal_type)

                functions.append(NodeMetadata(
                    name=tag.name,
                    file_path=tag.fname or tag.rel_fname,
                    line=tag.line,
                    pagerank_score=pagerank_scores.get(tag.rel_fname, 0),
                    attack_path_score=attack_scores.get(ep, 0),
                    signal_types=sig_types,
                ))

        # Deduplicate functions by name (keep the first / best one)
        deduped: dict[str, NodeMetadata] = {}
        for fn in functions:
            if fn.name not in deduped:
                deduped[fn.name] = fn
            else:
                # Merge signal types
                existing = deduped[fn.name]
                existing.signal_types = list(
                    set(existing.signal_types + fn.signal_types)
                )

        # Compute final_score per function
        for fn in deduped.values():
            fn.final_score = (
                fn.pagerank_score * 0.3 + fn.attack_path_score * 0.7
            )

        functions_list = list(deduped.values())

        # Aggregate signals
        sig_counts: dict[str, int] = {}
        for st in signals_for_card:
            sig_counts[st] = sig_counts.get(st, 0) + 1
        aggregated = [
            AggregatedSignal(tag=st, count=c)
            for st, c in sorted(sig_counts.items(), key=lambda x: -x[1])
        ]

        card = EntryAnalysisCard(
            entry=ep,
            entry_type="function",
            file_path=ep,  # best-effort; caller should refine
            line_number=0,
            functions_involved=functions_list,
            call_chain_depth=len(functions_list),
            function_count=len(functions_list),
            aggregated_signals=aggregated,
            symbol_link_table=build_symbol_link_table(functions_list),
            final_score=final,
        )
        cards.append(card)

    return sorted(cards, key=lambda c: c.final_score, reverse=True)


# ---------------------------------------------------------------------------
# Call chain expansion (BFS through FunctionIndex call graph)
# ---------------------------------------------------------------------------
# This runs at Brain dispatch time (after Sourcer has built the FunctionIndex),
# not during Director Phase 0.  Director identifies *which* entry points are
# dangerous; expand_call_chain retrieves *all* reachable functions for analysis.


def expand_call_chain(
    entry_func_name: str,
    function_index: FunctionIndex,
    max_depth: int = 8,
    max_nodes: int = 30,
) -> list[tuple[str, SourceFunction, int]]:
    """BFS-expand the call chain from *entry_func_name*.

    Uses ``FunctionIndex.call_graph`` (callee → set[caller]) to traverse
    callees of each visited node.  Returns ordered list of
    ``(function_name, SourceFunction, depth)`` tuples where depth=0 is the
    entry function itself.

    Parameters
    ----------
    entry_func_name : str
        Name of the entry function to expand from.
    function_index : FunctionIndex
        Built function index (must have call_graph populated).
    max_depth : int
        Maximum call-chain depth to traverse (default 8).
    max_nodes : int
        Maximum total nodes to collect (default 30).

    Returns
    -------
    list[(str, SourceFunction, int)]
        Ordered chain: entry → depth=1 → depth=2 → …
    """
    from agies.engine.v2.sourcer.models import FunctionIndex, SourceFunction

    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque()
    queue.append((entry_func_name, 0))
    chain: list[tuple[str, SourceFunction, int]] = []

    while queue and len(chain) < max_nodes:
        name, depth = queue.popleft()
        if name in visited or depth > max_depth:
            continue
        visited.add(name)

        # Look up function body in the index
        fns = function_index.lookup(name)
        if fns:
            chain.append((name, fns[0], depth))

        # BFS: find what this function calls (forward traversal)
        callees = function_index._get_direct_callees(name)
        for callee in sorted(callees):
            if callee not in visited:
                queue.append((callee, depth + 1))

    return chain
