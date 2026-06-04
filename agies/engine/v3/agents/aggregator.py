"""PathResultAggregator — collects and merges outputs from parallel Logic Agents.

Phase D Step 5 / Phase E bridge.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from agies.engine.v3.aggregator.models import AgentPhaseResult

logger = logging.getLogger(__name__)


@dataclass
class AggregatedPipelineResult:
    """Final aggregated output from one run of the v3 pipeline."""

    total_paths: int = 0
    vulnerable_paths: int = 0
    safe_paths: int = 0
    paths_skipped: int = 0

    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    """High-confidence (>= 7) vulnerabilities found."""

    interesting_findings: list[dict[str, Any]] = field(default_factory=list)
    """Medium confidence (4-6) findings — suspicious but not confirmed."""

    blackboard_summary: str = ""
    """Blackboard summary for display."""

    total_duration_seconds: float = 0.0


class PathResultAggregator:
    """Aggregates Logic Agent outputs from parallel paths."""

    def __init__(self) -> None:
        self._results: list[AgentPhaseResult] = []

    def add(self, result: AgentPhaseResult) -> None:
        """Add a single Phase D result."""
        self._results.append(result)

    def add_batch(self, results: list[AgentPhaseResult]) -> None:
        """Add multiple results at once."""
        self._results.extend(results)

    def aggregate(
        self,
        blackboard_summary: str = "",
    ) -> AggregatedPipelineResult:
        """Aggregate all collected results into a final pipeline output."""
        vulnerable = [
            r for r in self._results if r.is_vulnerable
        ]
        interesting = [
            r for r in self._results if 4 <= r.confidence < 7
        ]
        safe = [
            r for r in self._results if r.confidence < 4
        ]

        return AggregatedPipelineResult(
            total_paths=len(self._results),
            vulnerable_paths=len(vulnerable),
            safe_paths=len(safe),
            paths_skipped=0,
            vulnerabilities=[
                {
                    "path_id": r.path_id,
                    "vuln_type": r.vuln_type,
                    "confidence": r.confidence,
                    "contradictions": r.contradictions,
                    "analysis": r.analysis,
                }
                for r in vulnerable
            ],
            interesting_findings=[
                {
                    "path_id": r.path_id,
                    "vuln_type": r.vuln_type,
                    "confidence": r.confidence,
                    "contradictions": r.contradictions,
                }
                for r in interesting
            ],
            blackboard_summary=blackboard_summary,
        )

    def summary_text(self, result: AggregatedPipelineResult) -> str:
        """Generate a one-line summary."""
        return (
            f"v3 analysis: {result.total_paths} paths, "
            f"{result.vulnerable_paths} vulnerable, "
            f"{result.safe_paths} safe, "
            f"{len(result.interesting_findings)} interesting"
        )
