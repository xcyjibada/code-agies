"""PathCodeLoader — Phase D Step 1.

Converts CodeQL path coordinates into function blocks for the Intent Agent pool.

Key feature: blackboard-aware — checks for cached Intent results before
dispatching a new Intent Agent task (Phase D efficiency).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from agies.engine.v3.aggregator.blackboard import BlackboardAggregator
from agies.engine.v3.aggregator.models import IntentResult
from agies.engine.v3.agents.intent_agent import IntentAgentTask

logger = logging.getLogger(__name__)

# Default group size — how many functions per Intent Agent task
_INTENT_GROUP_SIZE = 5


@dataclass
class PathCodeLoaderResult:
    """Result of loading and grouping path code."""

    path_id: str
    tasks: list[IntentAgentTask]
    """New Intent Agent tasks to execute (not in cache)."""

    cached: list[IntentResult]
    """Intent results already in cache (no LLM needed)."""

    total_functions: int = 0
    """Total functions on the path."""

    cache_hit_count: int = 0
    """How many functions were served from cache."""


class PathCodeLoader:
    """Loads path coordinates and prepares Intent Agent tasks.

    Usage::

        loader = PathCodeLoader(project_path, blackboard)
        result = loader.prepare(path_slice)
        # result.tasks → dispatch to Intent Agent pool
        # result.cached → use directly in merge
    """

    def __init__(
        self,
        project_path: str = "",
        blackboard: BlackboardAggregator | None = None,
        extractor=None,
    ) -> None:
        self._project_path = project_path
        self._blackboard = blackboard or BlackboardAggregator()
        self._extractor = extractor

    @property
    def blackboard(self) -> BlackboardAggregator:
        return self._blackboard

    def prepare(
        self,
        path_id: str,
        nodes: list[dict[str, Any]],
        *,
        group_size: int = _INTENT_GROUP_SIZE,
        readme_summary: str = "",
    ) -> PathCodeLoaderResult:
        """Prepare functions from path nodes for Intent Agent processing.

        Checks the blackboard cache for each function — cached functions
        skip LLM processing.
        """
        tasks: list[IntentAgentTask] = []
        cached: list[IntentResult] = []
        cache_hits = 0
        batch_index = 0

        # Group functions, checking cache per-function
        current_batch: list[dict[str, Any]] = []

        for node in nodes:
            func_name = node.get("function_name", "")
            file_path = node.get("file_path", "")

            # Check blackboard cache (pass fn_body hash for precise lookup)
            if self._blackboard:
                func_body = node.get("code") or node.get("snippet", "")
                cached_intent = self._blackboard.get_intent(func_name, file_path, func_body=func_body)
                if cached_intent is not None:
                    cached.append(cached_intent)
                    cache_hits += 1
                    continue

            # Not cached — add to current batch
            current_batch.append(node)

            if len(current_batch) >= group_size:
                tasks.append(self._make_task(
                    path_id, batch_index, current_batch, readme_summary,
                ))
                current_batch = []
                batch_index += 1

        # Remainder
        if current_batch:
            tasks.append(self._make_task(
                path_id, batch_index, current_batch, readme_summary,
            ))

        return PathCodeLoaderResult(
            path_id=path_id,
            tasks=tasks,
            cached=cached,
            total_functions=len(nodes),
            cache_hit_count=cache_hits,
        )

    def _make_task(
        self,
        path_id: str,
        batch_index: int,
        functions: list[dict[str, Any]],
        readme_summary: str = "",
    ) -> IntentAgentTask:
        """Create an IntentAgentTask from a batch of functions."""
        return IntentAgentTask(
            batch_id=f"{path_id}-batch-{batch_index}",
            path_id=path_id,
            functions=functions,
            readme_summary=readme_summary,
        )

    def register_intent_results(
        self,
        intent_results: list[IntentResult],
    ) -> None:
        """Cache Intent results in the blackboard after execution."""
        if self._blackboard and intent_results:
            for r in intent_results:
                self._blackboard.cache_intent(r)

    def summary(self, result: PathCodeLoaderResult) -> str:
        """Human-readable summary of loading result."""
        return (
            f"Path {result.path_id}: {result.total_functions} functions, "
            f"{len(result.tasks)} new tasks, "
            f"{result.cache_hit_count} cache hits"
        )
