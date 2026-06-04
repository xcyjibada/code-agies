"""Path discovery backends for v3 pipeline (Phase A).

Two implementations:

- ``TreeSitterPathFinder`` — uses existing tree-sitter extractor + call graph
  to find source→sink paths. No CodeQL binary needed.
- ``CodeQLPathFinder`` — (planned) wraps ``CodeQLQueryRunner`` for precise
  dataflow paths. Requires ``codeql`` CLI.

Both output ``CodeQlPath`` objects consumed by ``slicer/``, ``prompts/``,
and ``agents/``.
"""

from agies.engine.v3.pathfinder.sink_patterns import (
    classify_sink,
    classify_sensitive_body,
    KNOWN_SINK_NAMES,
)
from agies.engine.v3.pathfinder.treesitter import TreeSitterPathFinder

__all__ = [
    "TreeSitterPathFinder",
    "classify_sink",
    "classify_sensitive_body",
    "KNOWN_SINK_NAMES",
]
