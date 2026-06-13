"""CPG node/edge type constants and data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Edge relationship types
WRITES_TO = "WRITES_TO"  # variable assignment: val → var
READS = "READS"  # variable read in expression: var → reader_context
CALLS = "CALLS"  # function call: caller → callee
RETURNS_TO = "RETURNS_TO"  # return value flow: return_stmt → call_site
ATTRIBUTE_OF = "ATTRIBUTE_OF"  # attribute access: obj → attr
CONTAINS = "CONTAINS"  # container membership: list/dict → element

# Node attribute keys
ATTR_FILE = "file"  # source file path
ATTR_LINE = "line"  # line number
ATTR_COL = "column"  # column number
ATTR_TEXT = "text"  # source text of the node
ATTR_TYPE = "type"  # tree-sitter node type
ATTR_KIND = "kind"  # 'var', 'val', 'call', 'func_def', etc.

# Node kind values
KIND_VAR = "var"
KIND_VAL = "val"
KIND_CALL = "call"
KIND_FUNC_DEF = "func_def"
KIND_RETURN = "return"
KIND_ATTR = "attr"
KIND_OBJ = "obj"
KIND_ARG = "arg"


def make_node_id(file_path: str, byte_offset: int) -> str:
    """Create a unique, deterministic node ID."""
    return f"{file_path}:{byte_offset}"


@dataclass
class CpgNode:
    """A node in the CPG with position and text metadata."""
    id: str
    file: str
    line: int
    column: int
    text: str
    kind: str
    byte_offset: int = 0
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class CpgEdge:
    """An edge in the CPG with relationship type."""
    source_id: str
    target_id: str
    relationship: str
    attributes: dict[str, Any] = field(default_factory=dict)
