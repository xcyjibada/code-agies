"""GRAPH_TRANSFORMERS registry — maps .scm captures to NetworkX edge builders.

Each entry is ``(query_filename, tag_name) → callable(G, captures, source_bytes, file_path)``.
The callable receives the NetworkX DiGraph, a dict of all captures from the current match,
the raw source bytes, and the source file path.
"""

from __future__ import annotations

import os
from typing import Any, Callable

import networkx as nx

from agies.engine.v3.graph.models import (
    WRITES_TO,
    READS,
    CALLS,
    RETURNS_TO,
    ATTRIBUTE_OF,
    ATTR_FILE,
    ATTR_LINE,
    ATTR_COL,
    ATTR_TEXT,
    ATTR_TYPE,
    ATTR_KIND,
    KIND_VAR,
    KIND_VAL,
    KIND_CALL,
    KIND_FUNC_DEF,
    KIND_RETURN,
    KIND_ATTR,
    KIND_OBJ,
    KIND_ARG,
    make_node_id,
)


def _text(source_bytes: bytes, node: Any) -> str:
    """Extract source text from a tree-sitter node."""
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _add_node(
    G: nx.DiGraph,
    node: Any,
    source_bytes: bytes,
    file_path: str,
    kind: str,
) -> str:
    """Add a syntax node to the graph, returning its node ID."""
    node_id = make_node_id(file_path, node.start_byte)
    attrs = G.nodes.get(node_id)
    if attrs is not None:
        return node_id
    G.add_node(
        node_id,
        **{
            ATTR_FILE: file_path,
            ATTR_LINE: node.start_point[0] + 1,
            ATTR_COL: node.start_point[1] + 1,
            ATTR_TEXT: _text(source_bytes, node),
            ATTR_TYPE: node.type,
            ATTR_KIND: kind,
        },
    )
    return node_id


def _add_edge(
    G: nx.DiGraph,
    src: Any,
    dst: Any,
    source_bytes: bytes,
    file_path: str,
    rel: str,
    src_kind: str = KIND_VAL,
    dst_kind: str = KIND_VAR,
) -> None:
    """Add an edge between two syntax nodes."""
    src_id = _add_node(G, src, source_bytes, file_path, src_kind)
    dst_id = _add_node(G, dst, source_bytes, file_path, dst_kind)
    G.add_edge(src_id, dst_id, relationship=rel)


# ── Python transformers ──

def _py_assign(G: nx.DiGraph, captures: dict[str, list[Any]],
               source_bytes: bytes, file_path: str) -> None:
    """x = val  →  WRITES_TO(val, x)"""
    for var, val in zip(captures.get("var", []), captures.get("val", [])):
        _add_edge(G, val, var, source_bytes, file_path, WRITES_TO)


def _py_aug_assign(G: nx.DiGraph, captures: dict[str, list[Any]],
                   source_bytes: bytes, file_path: str) -> None:
    """x += val  →  READS(x), WRITES_TO(val, x)"""
    for var, val in zip(captures.get("var", []), captures.get("val", [])):
        _add_edge(G, val, var, source_bytes, file_path, WRITES_TO)
        _add_edge(G, var, var, source_bytes, file_path, READS)


def _py_attr_assign(G: nx.DiGraph, captures: dict[str, list[Any]],
                    source_bytes: bytes, file_path: str) -> None:
    """self.x = val  →  WRITES_TO(val, self.x) + ATTRIBUTE_OF(self, x)"""
    for obj, attr, val in zip(
        captures.get("obj", []), captures.get("attr", []), captures.get("val", [])
    ):
        _add_edge(G, val, attr, source_bytes, file_path, WRITES_TO,
                  dst_kind=KIND_ATTR)
        _add_edge(G, obj, attr, source_bytes, file_path, ATTRIBUTE_OF,
                  src_kind=KIND_OBJ, dst_kind=KIND_ATTR)


def _py_attr_access(G: nx.DiGraph, captures: dict[str, list[Any]],
                    source_bytes: bytes, file_path: str) -> None:
    """obj.attr  →  READS(obj, attr), ATTRIBUTE_OF(obj, attr)"""
    for obj, attr in zip(captures.get("obj", []), captures.get("attr", [])):
        _add_edge(G, obj, attr, source_bytes, file_path, ATTRIBUTE_OF,
                  src_kind=KIND_OBJ, dst_kind=KIND_ATTR)
        _add_edge(G, obj, attr, source_bytes, file_path, READS,
                  src_kind=KIND_OBJ, dst_kind=KIND_ATTR)


def _py_return(G: nx.DiGraph, captures: dict[str, list[Any]],
               source_bytes: bytes, file_path: str) -> None:
    """return val  →  add return node (linked to function def later)"""
    for ret_val in captures.get("ret_val", []):
        _add_node(G, ret_val, source_bytes, file_path, KIND_RETURN)


def _py_call(G: nx.DiGraph, captures: dict[str, list[Any]],
             source_bytes: bytes, file_path: str) -> None:
    """func(arg)  →  CALLS(func, arg) for each argument"""
    call_fns = captures.get("call_fn", [])
    call_args = captures.get("call_arg", [])
    for cf in call_fns:
        _add_node(G, cf, source_bytes, file_path, KIND_CALL)
    for arg in call_args:
        _add_node(G, arg, source_bytes, file_path, KIND_ARG)


# ── Transformer registry ──

# Mapping: (query_filename, tag_name) → handler function
GRAPH_TRANSFORMERS: dict[tuple[str, str], Callable] = {
    # Python data flow
    ("python/data_flow.scm", "assign"): _py_assign,
    ("python/data_flow.scm", "aug_assign"): _py_aug_assign,
    ("python/data_flow.scm", "attr_assign"): _py_attr_assign,
    ("python/data_flow.scm", "attr_access"): _py_attr_access,
    ("python/data_flow.scm", "return_stmt"): _py_return,
    ("python/data_flow.scm", "call_node"): _py_call,
    ("python/data_flow.scm", "tuple_assign"): _py_assign,  # same handler

    # Python calls
    ("python/calls.scm", "simple_call"): _py_call,
    ("python/calls.scm", "method_call"): _py_call,
    ("python/calls.scm", "chained_call"): _py_call,

    # Java data flow
    ("java/data_flow.scm", "assign"): _py_assign,
    ("java/data_flow.scm", "field_assign"): _py_attr_assign,
    ("java/data_flow.scm", "var_decl"): _py_assign,
    ("java/data_flow.scm", "return_stmt"): _py_return,
    ("java/data_flow.scm", "call_node"): _py_call,
    ("java/data_flow.scm", "field_access"): _py_attr_access,

    # JS data flow
    ("js/data_flow.scm", "assign"): _py_assign,
    ("js/data_flow.scm", "var_decl"): _py_assign,
    ("js/data_flow.scm", "prop_assign"): _py_attr_assign,
    ("js/data_flow.scm", "prop_access"): _py_attr_access,
    ("js/data_flow.scm", "return_stmt"): _py_return,
    ("js/data_flow.scm", "call_node"): _py_call,
}


def _query_filename(path: str) -> str:
    """Convert absolute path → relative ``{lang}/{query}.scm`` key."""
    # Normalise: /.../graph/queries/python/data_flow.scm → python/data_flow.scm
    parts = path.replace("\\", "/").split("/")
    # Find "queries/" in the path
    try:
        idx = parts.index("queries")
        return "/".join(parts[idx + 1 :])
    except ValueError:
        return os.path.basename(path)


def list_registered_queries(query_dir: str) -> list[str]:
    """List all .scm queries that have registered transformers."""
    registered = set(k[0] for k in GRAPH_TRANSFORMERS)
    matched: list[str] = []
    for root, _dirs, files in os.walk(query_dir):
        for f in files:
            if not f.endswith(".scm"):
                continue
            full = os.path.join(root, f)
            rel = _query_filename(full)
            if rel in registered:
                matched.append(full)
    return sorted(matched)
