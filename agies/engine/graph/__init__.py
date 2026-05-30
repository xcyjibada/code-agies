"""Pluggable graph generation layer.

Provides ``GraphGenerator`` (ABC), ``ProgramGraph`` (unified graph data
model), and ``TreeSitterGraphGenerator`` (default implementation wrapping
existing tree-sitter extraction).

Usage::

    from agies.engine.graph import GraphGenerator, ProgramGraph, TreeSitterGraphGenerator

    generator = TreeSitterGraphGenerator()
    pg = generator.build_program_graph("/path/to/project")
    slices = generator.create_slices(pg, entry_points)
"""

from __future__ import annotations

from agies.engine.graph.base import GraphGenerator
from agies.engine.graph.models import (
    GraphEdge,
    GraphNode,
    ProgramGraph,
    ProgramSlice,
    _make_node_id,
)
from agies.engine.graph.treesitter import TreeSitterGraphGenerator
from agies.engine.graph.codeql import CodeQLGraphGenerator
from agies.engine.graph.joern import JoernGraphGenerator

__all__ = [
    "GraphGenerator",
    "GraphNode",
    "GraphEdge",
    "ProgramGraph",
    "ProgramSlice",
    "TreeSitterGraphGenerator",
    "CodeQLGraphGenerator",
    "JoernGraphGenerator",
    "_make_node_id",
]
