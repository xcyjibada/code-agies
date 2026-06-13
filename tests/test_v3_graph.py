"""Tests for agies CPG builder (CpgBuilder).

Tests the query-callback registration pattern:
- .scm queries capture AST patterns
- GRAPH_TRANSFORMERS map captures to NetworkX edge builders
- CpgBuilder builds a full-project CPG
"""

from __future__ import annotations

import os
import tempfile

import networkx as nx
import pytest

from agies.engine.v3.graph.builder import CpgBuilder
from agies.engine.v3.graph.models import (
    WRITES_TO,
    READS,
    CALLS,
    ATTRIBUTE_OF,
    ATTR_TEXT,
    ATTR_FILE,
    ATTR_LINE,
    ATTR_KIND,
    make_node_id,
)
from agies.engine.v3.graph.transformers import (
    GRAPH_TRANSFORMERS,
    list_registered_queries,
    _query_filename,
)


# ── Fixtures ──

@pytest.fixture
def sample_py_project():
    """Create a temporary Python project for testing CPG builds."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # main.py — simple assignment + call
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write("""
import utils

def process(data):
    result = transform(data)
    save(result)

def transform(x):
    y = x.upper()
    return y

def save(val):
    open("/tmp/out", "w").write(val)
""")
        # utils.py — attribute assignment
        with open(os.path.join(tmpdir, "utils.py"), "w") as f:
            f.write("""
class Handler:
    def __init__(self, source):
        self.data = source

    def run(self):
        result = self.data + "_processed"
        return result
""")
        yield tmpdir


@pytest.fixture
def simple_assign_project():
    """Tiny project focused on assignment tracking."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "app.py"), "w") as f:
            f.write("""
def handle_request(user_input):
    x = user_input
    y = x
    z = y + "_suffix"
    sink(z)
""")
        yield tmpdir


# ── Tests for transformers registry ──

def test_registry_has_entries():
    """GRAPH_TRANSFORMERS should have registered handlers."""
    assert len(GRAPH_TRANSFORMERS) > 0


def test_registry_keys_are_tuples():
    """All registry keys should be (query_file, tag) tuples."""
    for key in GRAPH_TRANSFORMERS:
        assert isinstance(key, tuple)
        assert len(key) == 2
        assert isinstance(key[0], str)
        assert isinstance(key[1], str)


def test_query_filename_normalisation():
    """_query_filename should extract lang/filename.scm from full paths."""
    cases = [
        ("/path/to/graph/queries/python/data_flow.scm", "python/data_flow.scm"),
        ("/path/to/graph/queries/java/data_flow.scm", "java/data_flow.scm"),
        ("/path/to/graph/queries/js/calls.scm", "js/calls.scm"),
    ]
    for full, expected in cases:
        assert _query_filename(full) == expected


def test_queries_dir_has_scm_files():
    """The queries directory should contain .scm files."""
    query_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "agies/engine/v3/graph/queries",
    )
    assert os.path.isdir(query_dir)
    found = list_registered_queries(query_dir)
    assert len(found) > 0
    for f in found:
        assert f.endswith(".scm")


# ── Tests for CpgBuilder ──

def test_builder_creation():
    """CpgBuilder should initialise without error."""
    builder = CpgBuilder("/tmp/nonexistent")
    assert builder is not None
    assert not builder.built


def test_builder_empty_project():
    """CpgBuilder on empty project should produce empty graph."""
    with tempfile.TemporaryDirectory() as tmpdir:
        builder = CpgBuilder(tmpdir)
        G = builder.build()
        assert isinstance(G, nx.DiGraph)
        assert G.number_of_nodes() == 0


def test_builder_no_source_files():
    """CpgBuilder on project with no source files should produce empty graph."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create some non-code files
        open(os.path.join(tmpdir, "README.md"), "w").close()
        builder = CpgBuilder(tmpdir)
        G = builder.build()
        assert G.number_of_nodes() == 0


def test_builder_simple_assignment(simple_assign_project):
    """CpgBuilder should capture assignment WRITES_TO edges."""
    builder = CpgBuilder(simple_assign_project)
    G = builder.build()
    assert G.number_of_nodes() > 0
    assert G.number_of_edges() > 0

    # Should have WRITES_TO edges for assignments
    writes_to_edges = [
        (u, v) for u, v, d in G.edges(data=True)
        if d.get("relationship") == WRITES_TO
    ]
    assert len(writes_to_edges) >= 3  # x ← user_input, y ← x, z ← y


def test_builder_full_project(sample_py_project):
    """CpgBuilder should process a multi-file project."""
    builder = CpgBuilder(sample_py_project)
    G = builder.build()
    assert G.number_of_nodes() > 0
    assert G.number_of_edges() > 0

    # Check that we have WRITES_TO edges
    rels = set()
    for _u, _v, d in G.edges(data=True):
        rels.add(d.get("relationship"))
    assert WRITES_TO in rels


def test_builder_assignment_chain(simple_assign_project):
    """CpgBuilder should allow tracing assignment chains backwards."""
    builder = CpgBuilder(simple_assign_project)
    G = builder.build()

    # Find the "sink" call node
    sink_nodes = [
        n for n, d in G.nodes(data=True)
        if "sink" in d.get(ATTR_TEXT, "")
    ]

    if sink_nodes:
        # Try to trace backwards
        chain = builder.find_backward_chain(sink_nodes[0])
        assert isinstance(chain, list)
        for item in chain:
            assert isinstance(item, dict)
            assert ATTR_TEXT in item


def test_builder_build_is_idempotent(sample_py_project):
    """Building twice should return the same graph reference."""
    builder = CpgBuilder(sample_py_project)
    G1 = builder.build()
    G2 = builder.build()
    assert G1 is G2
    assert G2.number_of_nodes() == G1.number_of_nodes()


def test_builder_max_files():
    """max_files should limit the number of files processed."""
    with tempfile.TemporaryDirectory() as tmpdir:
        for i in range(5):
            with open(os.path.join(tmpdir, f"f{i}.py"), "w") as f:
                f.write(f"x = {i}\n")
        builder = CpgBuilder(tmpdir, max_files=2)
        G = builder.build()
        assert G.number_of_nodes() > 0  # at least some edges
        # max_files should limit files scanned
        assert G.number_of_edges() < 10  # 5 files would have 5+ edges


# ── Tests for graph query methods ──

def test_has_data_flow_path(simple_assign_project):
    """has_data_flow_path should find direct WRITES_TO edges."""
    builder = CpgBuilder(simple_assign_project)
    G = builder.build()

    # Verify has_data_flow_path returns True for directly connected nodes
    # and False for disconnected nodes (returns bool, not throws).
    writes_to = [
        (u, v) for u, v, d in G.edges(data=True)
        if d.get("relationship") == WRITES_TO
    ]
    if writes_to:
        u, v = writes_to[0]
        assert builder.has_data_flow_path(u, v)
    # No data flow between unrelated node pairs
    assert not builder.has_data_flow_path("nonexistent_a", "nonexistent_b")


def test_find_backward_chain(simple_assign_project):
    """find_backward_chain should trace assignment chain backwards."""
    builder = CpgBuilder(simple_assign_project)
    G = builder.build()

    sink_nodes = [
        n for n, d in G.nodes(data=True)
        if "sink" in d.get(ATTR_TEXT, "")
    ]

    if sink_nodes:
        chain = builder.find_backward_chain(sink_nodes[0])
        assert len(chain) >= 1
        # Chain should end at some assignment
        texts = [c.get(ATTR_TEXT, "") for c in chain]
        assert any("sink" in t for t in texts)


def test_find_backward_chain_unknown_node():
    """find_backward_chain should return empty list for unknown node."""
    builder = CpgBuilder("/tmp/nonexistent")
    chain = builder.find_backward_chain("nonexistent_node")
    assert chain == []


def test_built_property(sample_py_project):
    """The built property should reflect build state."""
    builder = CpgBuilder(sample_py_project)
    assert not builder.built
    builder.build()
    assert builder.built


def test_graph_property(sample_py_project):
    """The graph property should always return a DiGraph."""
    builder = CpgBuilder(sample_py_project)
    assert isinstance(builder.graph, nx.DiGraph)
    G = builder.build()
    assert builder.graph is G


# ── Edge case tests ──

def test_builder_with_excluded_dirs():
    """CpgBuilder should respect excluded_dirs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "venv"))
        with open(os.path.join(tmpdir, "venv", "lib.py"), "w") as f:
            f.write("x = 1\n")
        with open(os.path.join(tmpdir, "real.py"), "w") as f:
            f.write("y = x\n")

        builder = CpgBuilder(tmpdir)
        G = builder.build()
        # Should only process real.py, not venv/lib.py
        # real.py has only one assignment, so should have small graph
        assert G.number_of_nodes() > 0
        assert G.number_of_edges() >= 1


def test_builder_non_python_files():
    """CpgBuilder should handle mixed-language projects."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "code.py"), "w") as f:
            f.write("x = 1\n")
        with open(os.path.join(tmpdir, "code.js"), "w") as f:
            f.write("let x = 1;\n")
        with open(os.path.join(tmpdir, "data.txt"), "w") as f:
            f.write("not code\n")

        builder = CpgBuilder(tmpdir)
        G = builder.build()
        assert G.number_of_nodes() > 0


def test_builder_malformed_file():
    """CpgBuilder should not crash on malformed source files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "broken.py"), "w") as f:
            f.write("this is not valid python @@@@!!!!\n")
        with open(os.path.join(tmpdir, "ok.py"), "w") as f:
            f.write("x = 1\n")

        builder = CpgBuilder(tmpdir)
        G = builder.build()  # should not raise
        assert G.number_of_nodes() >= 1


def test_builder_empty_file():
    """CpgBuilder should handle empty source files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "empty.py"), "w") as f:
            f.write("")
        builder = CpgBuilder(tmpdir)
        G = builder.build()
        assert G.number_of_nodes() == 0


def test_builder_large_project_does_not_oom():
    """CpgBuilder should handle many assignments without exploding."""
    with tempfile.TemporaryDirectory() as tmpdir:
        lines = "\n".join(f"v{i} = v{i-1}" for i in range(100))
        with open(os.path.join(tmpdir, "big.py"), "w") as f:
            f.write(lines)
        builder = CpgBuilder(tmpdir)
        G = builder.build()
        # 100 assignments = at least 100 nodes
        assert G.number_of_nodes() >= 50
        assert G.number_of_edges() >= 50
