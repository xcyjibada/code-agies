"""AI-driven scanning strategy — file prioritization + dynamic chunking.

Provides a two-phase scanning approach:
1. Phase 1 — High-value targets (AI/heuristic selected, deep analysis)
2. Phase 2 — Full coverage (remaining files, lighter analysis)

Usage:
    from agies.strategy import StrategyEngine

    engine = StrategyEngine(target_root="/path/to/target")
    result = engine.analyze_project(all_files)
    print(result["priority_summary"])
    for chunk in result["chunks"]["phase1"]:
        # analyze each chunk...
        engine.record_chunk_result(num_files, avg_tokens, analysis_time)
"""

from .scanner import StrategyEngine
from .prioritizer import FilePrioritizer, ScoredFile
from .chunker import DynamicChunker, ChunkMetrics

__all__ = [
    "StrategyEngine",
    "FilePrioritizer",
    "ScoredFile",
    "DynamicChunker",
    "ChunkMetrics",
]
