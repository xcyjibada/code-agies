"""BlackboardAggregator — cross-agent knowledge sharing for parallel Phase D.

Design
------
v3 runs multiple Intent/Logic agents in parallel. The BlackboardAggregator
collects all ``KnowledgeEntry`` records from completed agents and makes them
available for downstream phases:

1. **Intent cache** — same function across paths → compute once, reuse N times
2. **Knowledge cross-reference** — Agent A's finding about function X is
   injected into Logic Agent analyzing a path that also touches function X
3. **Verification enrichment** — all collected knowledge about a path's
   functions is injected into the Verification Agent's prompt

See ``docs/v3/plan.md`` Phase E for full design.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from typing import Any

from agies.engine.v3.aggregator.models import (
    CachedIntent,
    IntentResult,
    KnowledgeEntry,
    AgentPhaseResult,
    compute_body_hash,
)

logger = logging.getLogger(__name__)


class BlackboardAggregator:
    """Collects and distributes cross-agent knowledge for v3 pipeline.

    Usage::

        bb = BlackboardAggregator()

        # Phase D — agents record knowledge as they run
        bb.record_knowledge("Helper.parse", "No input validation")

        # Phase D — Intent results cached
        bb.cache_intent("validatePath", IntentResult(...))

        # Phase E — retrieve for next agent
        intent = bb.get_intent("validatePath", "src/util.py")
        prior = bb.get_prior_knowledge("Helper.parse")
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Intent cache: (func_name, file_path) → CachedIntent
        self._intent_cache: dict[tuple[str, str], CachedIntent] = {}

        # Knowledge entries: key → list[KnowledgeEntry]
        self._knowledge: dict[str, list[KnowledgeEntry]] = defaultdict(list)

        # Phase results from Logic Agents
        self._phase_results: dict[str, AgentPhaseResult] = {}

        self._created_at = time.time()

    # ------------------------------------------------------------------
    # Intent cache
    # ------------------------------------------------------------------

    @staticmethod
    def _cache_key(fn_body_hash: str, file_name: str) -> tuple[str, str]:
        """Normalise cache key — use body hash + filename, not unstable paths."""
        import os
        return (fn_body_hash, os.path.basename(file_name))

    def cache_intent(self, result: IntentResult) -> None:
        """Cache an Intent Agent result for future reuse."""
        with self._lock:
            import os
            basename = os.path.basename(result.file_path)
            if result.fn_body_hash:
                key = (result.fn_body_hash, basename)
            else:
                key = (result.func_name, basename)
            if key in self._intent_cache:
                logger.debug("Intent cache: overwriting %s::%s", *key)
            cached = CachedIntent(result=result, hit_count=0)
            self._intent_cache[key] = cached

    def get_intent(
        self,
        func_name: str,
        file_path: str,
        func_body: str = "",
    ) -> IntentResult | None:
        """Retrieve a cached Intent result, incrementing the hit counter."""
        with self._lock:
            import os
            basename = os.path.basename(file_path)
            if func_body:
                body_hash = compute_body_hash(func_body)
                key = (body_hash, basename)
                cached = self._intent_cache.get(key)
                if cached is not None:
                    cached.hit_count += 1
                    return cached.result
            name_key = (func_name, basename)
            cached = self._intent_cache.get(name_key)
            if cached is not None:
                logger.debug(
                    "Intent cache: name-based hit for %s / %s (hash-based key %s not found)",
                    func_name, file_path, func_body[:40] if func_body else "(no body)",
                )
                cached.hit_count += 1
                return cached.result
            return None

    def intent_cache_stats(self) -> dict[str, int]:
        """Return cache size and total hit count (for metrics)."""
        total_hits = sum(c.hit_count for c in self._intent_cache.values())
        return {
            "cached_functions": len(self._intent_cache),
            "total_cache_hits": total_hits,
        }

    # ------------------------------------------------------------------
    # Knowledge recording and retrieval
    # ------------------------------------------------------------------

    def record_knowledge(
        self,
        key: str,
        value: str,
        source_path_id: str = "",
    ) -> None:
        """Record a piece of discovered logic."""
        with self._lock:
            entry = KnowledgeEntry(
                key=key,
                value=value,
                source_path_id=source_path_id,
            )
            self._knowledge[key].append(entry)

    def get_prior_knowledge(self, function_name: str) -> str:
        """Generate a ``[PRIOR_KNOWLEDGE]`` block for a function.

        Returns an empty string if no knowledge is recorded.
        """
        entries = self._knowledge.get(function_name, [])
        if not entries:
            return ""
        block = "\n".join(f"  - {e.value}" for e in entries)
        return f"[PRIOR_KNOWLEDGE for {function_name}]:\n{block}"

    def get_all_prior_knowledge(self, function_names: list[str]) -> str:
        """Generate prior knowledge for a list of function names.

        Used to inject all relevant knowledge into a Verification Agent.
        """
        blocks: list[str] = []
        for fname in function_names:
            pk = self.get_prior_knowledge(fname)
            if pk:
                blocks.append(pk)
        return "\n\n".join(blocks)

    def merge_knowledge_from_agents(
        self,
        phase_results: list[AgentPhaseResult],
    ) -> None:
        """Collect knowledge from multiple phase results after Phase D."""
        for r in phase_results:
            if r.analysis:
                self.record_knowledge(
                    f"path:{r.path_id}",
                    r.analysis,
                    source_path_id=r.path_id,
                )

    # ------------------------------------------------------------------
    # Phase results
    # ------------------------------------------------------------------

    def record_phase_result(self, result: AgentPhaseResult) -> None:
        """Store a completed Phase D result."""
        with self._lock:
            self._phase_results[result.path_id] = result

    def get_phase_results(self) -> list[AgentPhaseResult]:
        """Get all Phase D results."""
        return list(self._phase_results.values())

    def summary(self) -> str:
        """Human-readable summary of blackboard state."""
        return (
            f"Blackboard: {len(self._intent_cache)} cached intents, "
            f"{sum(len(v) for v in self._knowledge.values())} knowledge entries, "
            f"{len(self._phase_results)} phase results"
        )
