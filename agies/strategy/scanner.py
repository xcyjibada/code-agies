"""Strategy engine — orchestrates file prioritization and chunked scanning.

Two-phase approach:
- Phase 1: High-value targets (top 20%, deep analysis)
- Phase 2: Full coverage (remaining 80%, lighter analysis)
"""

import os
from typing import Optional

from .prioritizer import FilePrioritizer, ScoredFile
from .chunker import DynamicChunker, ChunkMetrics


class StrategyEngine:
    """Orchestrate scanning strategy: prioritize, chunk, and analyze."""

    def __init__(
        self,
        target_root: str,
        llm_model=None,
        phase1_ratio: float = 0.2,
        phase1_min_files: int = 10,
        phase1_max_files: int = 100,
    ):
        self.target_root = os.path.abspath(target_root)
        self.prioritizer = FilePrioritizer(target_root, llm_model)
        self.chunker = DynamicChunker()
        self.phase1_ratio = phase1_ratio
        self.phase1_min = phase1_min_files
        self.phase1_max = phase1_max_files

        self.priority_files: list[ScoredFile] = []

    def analyze_project(self, all_files: list[str]) -> dict:
        """Full analysis with priority-based phased approach.

        Returns:
            dict with:
            - "high_value_files": list of paths for Phase 1
            - "remaining_files": list of paths for Phase 2
            - "chunks": Pre-computed chunks for each phase
            - "priority_summary": Human-readable summary
        """
        # Score all files
        self.priority_files = self.prioritizer.prioritize(all_files)

        if not self.priority_files:
            return {
                "high_value_files": [],
                "remaining_files": all_files,
                "chunks": {"phase1": [], "phase2": [all_files]},
                "priority_summary": "No high-value files identified.",
            }

        # Phase 1: top N files
        n_phase1 = max(
            self.phase1_min,
            min(self.phase1_max, int(len(self.priority_files) * self.phase1_ratio)),
        )
        high_value = [sf.path for sf in self.priority_files[:n_phase1]]

        # Phase 2: remaining files (deprioritize already-scanned)
        priority_set = set(high_value)
        remaining = [f for f in all_files if f not in priority_set]

        # Build chunks
        phase1_chunks = self.chunker.chunk_files(high_value, context_pressure=0.0)
        phase2_chunks = self.chunker.chunk_files(remaining, context_pressure=0.5)

        # Summary
        top_reasons = []
        for sf in self.priority_files[:5]:
            rel = os.path.relpath(sf.path, self.target_root)
            top_reasons.append(f"- [{sf.score}] {rel} — {sf.reason[:60]}")

        summary = (
            f"**Priority Scan Summary:**\n"
            f"- Total files: {len(all_files)}\n"
            f"- Phase 1 (deep): {len(high_value)} high-value files, "
            f"{len(phase1_chunks)} chunk(s)\n"
            f"- Phase 2 (coverage): {len(remaining)} remaining files, "
            f"{len(phase2_chunks)} chunk(s)\n"
            f"\n**Top Priority Files:**\n" + "\n".join(top_reasons)
        )

        return {
            "high_value_files": high_value,
            "remaining_files": remaining,
            "chunks": {
                "phase1": phase1_chunks,
                "phase2": phase2_chunks,
            },
            "priority_summary": summary,
        }

    def record_chunk_result(self, num_files: int, avg_tokens: float, analysis_time: float):
        """Feed back metrics to improve chunking."""
        self.chunker.update_metrics(ChunkMetrics(
            avg_tokens=avg_tokens,
            num_files=num_files,
            analysis_time=analysis_time,
        ))
