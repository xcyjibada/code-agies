"""Tests for ``agies.engine.graph.models`` — ProgramGraph, GraphNode, etc."""

from __future__ import annotations

import pytest

from agies.engine.graph.models import (
    GraphEdge,
    GraphNode,
    ProgramGraph,
    ProgramSlice,
    _make_node_id,
)


# ---------------------------------------------------------------------------
# GraphNode
# ---------------------------------------------------------------------------


class TestGraphNode:
    def test_create(self) -> None:
        node = GraphNode(
            id="foo.py::bar",
            name="bar",
            qualified_name="foo.bar",
            file_path="foo.py",
            line_start=10,
            line_end=30,
        )
        assert node.id == "foo.py::bar"
        assert node.final_score == 0.0  # default score is zero

    def test_final_score_formula(self) -> None:
        node = GraphNode(
            id="x.py::f",
            name="f",
            qualified_name="x.f",
            file_path="x.py",
            pagerank_score=100,
            attack_path_score=200,
        )
        # final = pr * 0.3 + ap * 0.7
        assert node.final_score == pytest.approx(100 * 0.3 + 200 * 0.7)

    def test_signals(self) -> None:
        node = GraphNode(
            id="a.py::b",
            name="b",
            qualified_name="a.b",
            file_path="a.py",
            signals={"sql_sink": 80, "file_io": 10},
        )
        assert node.signals["sql_sink"] == 80
        assert node.signals["file_io"] == 10


# ---------------------------------------------------------------------------
# GraphEdge
# ---------------------------------------------------------------------------


class TestGraphEdge:
    def test_create(self) -> None:
        edge = GraphEdge(caller_id="a.py::f1", callee_id="b.py::f2")
        assert edge.caller_id == "a.py::f1"
        assert edge.callee_id == "b.py::f2"
        assert edge.call_sites == []

    def test_with_call_site(self) -> None:
        edge = GraphEdge(
            caller_id="a.py::f1",
            callee_id="b.py::f2",
            call_sites=[("a.py", 42)],
        )
        assert edge.call_sites == [("a.py", 42)]


# ---------------------------------------------------------------------------
# ProgramGraph
# ---------------------------------------------------------------------------


class TestProgramGraph:
    def test_empty(self) -> None:
        pg = ProgramGraph()
        assert pg.total_nodes == 0
        assert pg.total_edges == 0
        assert pg.call_graph == {}

    def test_add_node(self) -> None:
        pg = ProgramGraph()
        node = GraphNode(
            id="main.py::run",
            name="run",
            qualified_name="main.run",
            file_path="main.py",
            line_start=1,
            line_end=5,
        )
        pg.add_node(node)
        assert pg.total_nodes == 1
        assert "main.py" in pg.file_nodes
        assert "run" in pg.name_index

    def test_add_edge(self) -> None:
        pg = ProgramGraph()
        for nid, name, fp in [
            ("a.py::f1", "f1", "a.py"),
            ("a.py::f2", "f2", "a.py"),
        ]:
            pg.add_node(GraphNode(id=nid, name=name,
                        qualified_name=name, file_path=fp))
        pg.add_edge("a.py::f1", "a.py::f2")

        assert pg.total_edges == 1
        callers = pg.get_callers("a.py::f2")
        assert len(callers) == 1
        assert callers[0].name == "f1"

        callees = pg.get_callees("a.py::f1")
        assert len(callees) == 1
        assert callees[0].name == "f2"

    def test_lookup(self) -> None:
        pg = ProgramGraph()
        node = GraphNode(
            id="x.py::f", name="f",
            qualified_name="x.f", file_path="x.py",
        )
        pg.add_node(node)
        assert len(pg.lookup("f")) == 1
        assert pg.lookup("f")[0].id == "x.py::f"
        assert pg.lookup("nonexistent") == []

    def test_file_lookup(self) -> None:
        pg = ProgramGraph()
        pg.add_node(GraphNode(
            id="a.py::f1", name="f1",
            qualified_name="a.f1", file_path="a.py",
        ))
        pg.add_node(GraphNode(
            id="a.py::f2", name="f2",
            qualified_name="a.f2", file_path="a.py",
        ))
        assert len(pg.file_lookup("a.py")) == 2
        assert pg.file_lookup("b.py") == []

    def test_call_graph_property(self) -> None:
        """call_graph must return {callee_name: {caller_names}}."""
        pg = ProgramGraph()
        for nid, name, fp in [
            ("a.py::caller", "caller", "a.py"),
            ("b.py::callee", "callee", "b.py"),
        ]:
            pg.add_node(GraphNode(
                id=nid, name=name,
                qualified_name=name, file_path=fp,
            ))
        pg.add_edge("a.py::caller", "b.py::callee")

        cg = pg.call_graph
        assert "callee" in cg
        assert cg["callee"] == {"caller"}

    def test_call_graph_empty(self) -> None:
        pg = ProgramGraph()
        assert pg.call_graph == {}

    def test_bfs_expand(self) -> None:
        """BFS from entry reaches callees."""
        pg = ProgramGraph()
        # Linear chain: entry → mid → leaf
        for nid, name, fp in [
            ("main.py::entry", "entry", "main.py"),
            ("main.py::mid", "mid", "main.py"),
            ("util.py::leaf", "leaf", "util.py"),
        ]:
            pg.add_node(GraphNode(
                id=nid, name=name,
                qualified_name=name, file_path=fp,
            ))
        pg.add_edge("main.py::entry", "main.py::mid")
        pg.add_edge("main.py::mid", "util.py::leaf")

        chain = pg.bfs_expand("entry", max_depth=8, max_nodes=10)
        names = [name for name, _gn, _depth in chain]
        assert "entry" in names
        assert "mid" in names
        assert "leaf" in names

    def test_bfs_expand_depth_limit(self) -> None:
        pg = ProgramGraph()
        for i in range(6):
            name = f"f{i}"
            pg.add_node(GraphNode(
                id=f"a.py::{name}", name=name,
                qualified_name=name, file_path="a.py",
            ))
            if i > 0:
                pg.add_edge(f"a.py::f{i-1}", f"a.py::f{i}")

        chain = pg.bfs_expand("f0", max_depth=3, max_nodes=10)
        assert len(chain) <= 4  # depth 0, 1, 2, 3

    def test_bfs_expand_max_nodes(self) -> None:
        pg = ProgramGraph()
        for i in range(20):
            name = f"f{i}"
            pg.add_node(GraphNode(
                id=f"a.py::{name}", name=name,
                qualified_name=name, file_path="a.py",
            ))
            if i > 0:
                pg.add_edge(f"a.py::f{i-1}", f"a.py::f{i}")

        chain = pg.bfs_expand("f0", max_depth=100, max_nodes=5)
        assert len(chain) <= 5

    def test_to_networkx(self) -> None:
        pg = ProgramGraph()
        for nid, name in [("a.py::f", "f"), ("b.py::g", "g")]:
            pg.add_node(GraphNode(
                id=nid, name=name,
                qualified_name=name, file_path=nid.split("::")[0],
            ))
        pg.add_edge("a.py::f", "b.py::g")

        nx_g = pg.to_networkx()
        assert nx_g is not None
        assert nx_g.has_edge("a.py::f", "b.py::g")

    def test_to_networkx_cache(self) -> None:
        pg = ProgramGraph()
        pg.add_node(GraphNode(
            id="a.py::f", name="f",
            qualified_name="f", file_path="a.py",
        ))
        nx1 = pg.to_networkx()
        nx2 = pg.to_networkx()
        assert nx1 is nx2  # same cached object

    def test_summary(self) -> None:
        pg = ProgramGraph()
        for i in range(3):
            pg.add_node(GraphNode(
                id=f"a.py::f{i}", name=f"f{i}",
                qualified_name=f"a.f{i}", file_path="a.py",
            ))
        pg.add_edge("a.py::f0", "a.py::f1")
        pg.add_edge("a.py::f1", "a.py::f2")

        s = pg.summary()
        assert s["nodes"] == 3
        assert s["edges"] == 2
        assert s["files"] == 1
        assert s["unique_names"] == 3

    def test_from_components_empty(self) -> None:
        pg = ProgramGraph.from_components(
            funcs=[],
            forward_calls={},
            signals_map={},
            scores_map={},
        )
        assert pg.total_nodes == 0
        assert pg.total_edges == 0

    def test_from_components_with_data(self) -> None:
        """Build ProgramGraph from SourceFunction-like objects and calls."""
        from agies.engine.v2.sourcer.models import SourceFunction

        funcs = [
            SourceFunction(
                name="entry", fullname="entry",
                file_path="main.py", line_start=1, line_end=5,
                signature="def entry():", body="pass",
            ),
            SourceFunction(
                name="sink", fullname="sink",
                file_path="util.py", line_start=10, line_end=15,
                signature="def sink():", body="pass",
            ),
        ]
        calls = {"entry": {"sink"}}
        signals = {
            "main.py::entry": {"cmd_exec": 80},
        }
        scores = {
            "main.py::entry": 0.5,
        }

        pg = ProgramGraph.from_components(funcs, calls, signals, scores)
        assert pg.total_nodes == 2
        assert pg.total_edges == 1
        # Signals attached
        entry_nodes = pg.lookup("entry")
        assert len(entry_nodes) == 1
        assert entry_nodes[0].signals.get("cmd_exec") == 80
        assert entry_nodes[0].pagerank_score == 0.5


# ---------------------------------------------------------------------------
# ProgramSlice
# ---------------------------------------------------------------------------


class TestProgramSlice:
    def test_create_minimal(self) -> None:
        sl = ProgramSlice(entry_point="entry")
        assert sl.entry_point == "entry"
        assert sl.final_score == 0.0

    def test_final_score_property(self) -> None:
        sl = ProgramSlice(
            entry_point="entry",
            scores={"pagerank": 100, "attack_path": 200, "final": 170},
        )
        assert sl.final_score == 170

    def test_to_entry_analysis_card(self) -> None:
        """Verify backward-compat conversion preserves key fields."""
        node = GraphNode(
            id="main.py::entry", name="entry",
            qualified_name="entry", file_path="main.py",
            line_start=1, line_end=5,
            signals={"cmd_exec": 80},
            pagerank_score=0.5, attack_path_score=0.3,
        )
        sl = ProgramSlice(
            entry_point="entry",
            entry_type="function",
            entry_file_path="main.py",
            entry_line=1,
            path=[node],
            signals=[("cmd_exec", 1)],
            scores={"pagerank": 0.5, "attack_path": 0.3, "final": 0.36},
            symbol_link_table={"entry": "main.py:1"},
            call_chain_depth=0,
            function_count=1,
        )

        card = sl.to_entry_analysis_card()
        assert card.entry == "entry"
        assert card.entry_type == "function"
        assert card.file_path == "main.py"
        assert card.line_number == 1
        assert len(card.functions_involved) == 1
        assert card.functions_involved[0].name == "entry"
        assert card.functions_involved[0].signal_types == ["cmd_exec"]
        assert len(card.aggregated_signals) == 1
        assert card.aggregated_signals[0].tag == "cmd_exec"
        assert card.symbol_link_table["entry"] == "main.py:1"
        assert card.final_score == pytest.approx(0.36)

    def test_to_card_empty_path(self) -> None:
        sl = ProgramSlice(entry_point="entry")
        card = sl.to_entry_analysis_card()
        assert card.functions_involved == []

    def test_to_card_deduplicates(self) -> None:
        """functions_involved should dedup by name (keep first)."""
        n1 = GraphNode(
            id="a.py::dup", name="dup",
            qualified_name="a.dup", file_path="a.py",
            signals={"sql_sink": 80},
        )
        n2 = GraphNode(
            id="b.py::dup", name="dup",
            qualified_name="b.dup", file_path="b.py",
            signals={"cmd_exec": 80},
        )
        sl = ProgramSlice(
            entry_point="entry",
            path=[n1, n2],
            signals=[("sql_sink", 1), ("cmd_exec", 1)],
        )
        card = sl.to_entry_analysis_card()
        # Only first occurrence (n1 with sql_sink) should remain
        assert len(card.functions_involved) == 1
        assert card.functions_involved[0].signal_types == ["sql_sink"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestMakeNodeId:
    def test_basic(self) -> None:
        assert _make_node_id("src/main.py", "run") == "src/main.py::run"

    def test_with_class(self) -> None:
        assert (
            _make_node_id("app/controller.py", "UserController.get")
            == "app/controller.py::UserController.get"
        )
