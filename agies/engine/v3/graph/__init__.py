"""CPG (Code Property Graph) builder — lightweight NetworkX-based graph.

Builds a Code Property Graph from source code using tree-sitter ``.scm``
queries + Python callback registry (Query-Callback Registration pattern).

See ``builder.py`` (``CpgBuilder``) for the main entry point.
"""

from agies.engine.v3.graph.builder import CpgBuilder
from agies.engine.v3.graph.models import (
    WRITES_TO,
    READS,
    CALLS,
    ATTRIBUTE_OF,
    make_node_id,
)

__all__ = [
    "CpgBuilder",
    "WRITES_TO",
    "READS",
    "CALLS",
    "ATTRIBUTE_OF",
    "make_node_id",
]
