"""Dynamic chunker — adaptively size file chunks based on context pressure.

Inspired by Sandyaa's RLM-based dynamic chunking:
- Targets ~30K tokens per chunk
- Adjusts based on context window pressure, analysis time, and file sizes
- Uses exponential moving average (alpha=0.3) for smooth adaptation
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ChunkMetrics:
    """Metrics from processing a single chunk."""
    avg_tokens: float
    num_files: int
    analysis_time: float  # seconds


class DynamicChunker:
    """Adaptively determine chunk sizes based on runtime metrics."""

    def __init__(
        self,
        target_size_tokens: int = 30000,
        min_chunk: int = 5,
        max_chunk: int = 50,
        ema_alpha: float = 0.3,
    ):
        self.target_size = target_size_tokens
        self.min_chunk = min_chunk
        self.max_chunk = max_chunk
        self.ema_alpha = ema_alpha

        # Running metrics (EMA-smoothed)
        self.avg_tokens_per_file: float = 500.0  # Initial estimate
        self.total_files_processed: int = 0

    def update_metrics(self, metrics: ChunkMetrics):
        """Update rolling averages after processing a chunk."""
        self.total_files_processed += metrics.num_files

        # EMA update
        self.avg_tokens_per_file = (
            self.ema_alpha * metrics.avg_tokens
            + (1 - self.ema_alpha) * self.avg_tokens_per_file
        )

    def get_chunk_size(
        self,
        context_pressure: float = 0.0,
        analysis_time: float = 0.0,
        large_file_ratio: float = 0.0,
    ) -> int:
        """Calculate optimal chunk size for the next batch.

        Args:
            context_pressure: Current context usage (0.0-1.0), e.g. how full
                              the LLM context window is.
            analysis_time: Seconds spent on the last chunk analysis.
            large_file_ratio: Fraction of files > 0.5MB in the remaining queue.

        Returns:
            Number of files per chunk (bounded by [min_chunk, max_chunk]).
        """
        # Base estimate
        chunk_size = self.target_size / max(self.avg_tokens_per_file, 1)

        # Context pressure: shrink when context is full
        if context_pressure > 0.7:
            chunk_size *= 0.5
        elif context_pressure > 0.5:
            chunk_size *= 0.7

        # Analysis time: shrink if last chunk took too long
        if analysis_time > 300:   # >5 min
            chunk_size *= 0.8
        elif analysis_time > 600:  # >10 min
            chunk_size *= 0.5

        # Large files: shrink chunk to avoid token overflow
        if large_file_ratio > 0.3:
            chunk_size *= 0.7
        elif large_file_ratio > 0.1:
            chunk_size *= 0.85

        return max(self.min_chunk, min(self.max_chunk, int(chunk_size)))

    def chunk_files(
        self,
        files: list[str],
        context_pressure: float = 0.0,
        analysis_time: float = 0.0,
    ) -> list[list[str]]:
        """Split a list of files into optimally-sized chunks."""
        if not files:
            return []

        large_ratio = 0.0
        try:
            large_count = sum(1 for f in files if os.path.getsize(f) > 500 * 1024)
            large_ratio = large_count / len(files)
        except (OSError, FileNotFoundError):
            pass

        chunk_size = self.get_chunk_size(
            context_pressure=context_pressure,
            analysis_time=analysis_time,
            large_file_ratio=large_ratio,
        )

        return [
            files[i:i + chunk_size]
            for i in range(0, len(files), chunk_size)
        ]
