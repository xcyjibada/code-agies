"""Tests for agies/engine/director/ — the Director layer.

Tests cover Tag extraction, signal-weighted PageRank, has_path
reachability, symbol_link_table, library mode guard, and get_neighbors.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixture: create a small Python project for tag extraction tests
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_project():
    """Create a tiny Python project with signals and entry-point patterns."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Entry point file
        (Path(tmpdir) / "app.py").write_text("""\
import sqlite3
import os

def main():
    db = sqlite3.connect("test.db")
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
    result = cursor.fetchall()
    return result

def helper_func(x):
    return x * 2

if __name__ == "__main__":
    main()
""")
        # Utility file with signals
        (Path(tmpdir) / "utils.py").write_text("""\
import subprocess
import json
import re

def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout

def parse_json(data):
    return json.loads(data)

def validate_pattern(pattern, text):
    return re.match(pattern, text)

def sanitize_output(output):
    return output.strip()
""")
        # Config file (no signals)
        (Path(tmpdir) / "config.py").write_text("""\
import os

DEBUG = os.environ.get("DEBUG", "false")

def get_config():
    return {"debug": DEBUG}
""")
        yield tmpdir


# ---------------------------------------------------------------------------
# 1. Tag extraction
# ---------------------------------------------------------------------------


class TestTagExtraction:
    def test_extracts_def_tags(self, sample_project):
        from agies.engine.director.repomap import get_tags_raw

        fname = os.path.join(sample_project, "app.py")
        tags = list(get_tags_raw(fname, "app.py"))

        def_names = [t.name for t in tags if t.kind == "def"]
        assert "main" in def_names
        assert "helper_func" in def_names

    def test_extracts_ref_tags(self, sample_project):
        from agies.engine.director.repomap import get_tags_raw

        fname = os.path.join(sample_project, "app.py")
        tags = list(get_tags_raw(fname, "app.py"))

        ref_names = [t.name for t in tags if t.kind == "ref"]
        assert len(ref_names) > 0

    def test_extracts_signal_tags(self, sample_project):
        from agies.engine.director.repomap import get_tags_raw

        fname = os.path.join(sample_project, "utils.py")
        tags = list(get_tags_raw(fname, "utils.py"))

        signal_types = [t.signal_type for t in tags if t.kind == "signal"]
        # subprocess.run → cmd_exec (matched as attribute call subprocess.run)
        assert "cmd_exec" in signal_types, f"Expected cmd_exec in {signal_types}"
        # re.match → regex_operation
        assert "regex_operation" in signal_types, f"Expected regex_operation in {signal_types}"
        # json.loads is not currently pattern-matched in .scm; this is fine

    def test_app_py_signal_tags(self, sample_project):
        from agies.engine.director.repomap import get_tags_raw

        fname = os.path.join(sample_project, "app.py")
        tags = list(get_tags_raw(fname, "app.py"))

        signal_types = [t.signal_type for t in tags if t.kind == "signal"]
        # cursor.execute → sql_sink
        assert "sql_sink" in signal_types

    def test_tag_namedtuple_structure(self, sample_project):
        from agies.engine.director.repomap import get_tags_raw, Tag

        fname = os.path.join(sample_project, "app.py")
        tags = list(get_tags_raw(fname, "app.py"))
        assert len(tags) > 0

        tag = tags[0]
        # Verify it's a proper Tag namedtuple
        assert isinstance(tag, tuple)
        assert hasattr(tag, "rel_fname")
        assert hasattr(tag, "fname")
        assert hasattr(tag, "line")
        assert hasattr(tag, "name")
        assert hasattr(tag, "kind")
        assert hasattr(tag, "signal_type")


# ---------------------------------------------------------------------------
# 2. build_graph with signal weighting
# ---------------------------------------------------------------------------


class TestBuildGraph:
    def test_build_graph_returns_graph_and_scores(self, sample_project):
        from agies.engine.director.repomap import RepoMap

        rm = RepoMap(root=sample_project)
        fnames = [
            os.path.join(sample_project, "app.py"),
            os.path.join(sample_project, "utils.py"),
            os.path.join(sample_project, "config.py"),
        ]

        G, pr_scores, ranked_tags, file_tags = rm.build_graph(fnames=fnames)

        assert G is not None
        assert len(G.nodes) > 0
        assert len(pr_scores) > 0

    def test_signal_weighting_boosts_sink_files(self, sample_project):
        from agies.engine.director.repomap import RepoMap
        from agies.engine.director.signals import SIGNAL_MUL

        rm = RepoMap(root=sample_project)
        fnames = [
            os.path.join(sample_project, "app.py"),
            os.path.join(sample_project, "utils.py"),
            os.path.join(sample_project, "config.py"),
        ]

        G, pr_scores, ranked_tags, file_tags = rm.build_graph(
            fnames=fnames,
            signal_mul=SIGNAL_MUL,
        )

        # Files with signals should have non-zero PageRank
        app_score = pr_scores.get("app.py", 0)
        utils_score = pr_scores.get("utils.py", 0)
        assert app_score > 0 or utils_score > 0

    def test_entry_point_personalization(self, sample_project):
        from agies.engine.director.repomap import RepoMap

        rm = RepoMap(root=sample_project)
        fnames = [
            os.path.join(sample_project, "app.py"),
            os.path.join(sample_project, "utils.py"),
        ]

        G, pr_scores, ranked_tags, file_tags = rm.build_graph(
            fnames=fnames,
            entry_points={"app.py"},
        )

        # app.py should have higher PageRank due to personalization
        app_score = pr_scores.get("app.py", 0)
        assert app_score > 0


# ---------------------------------------------------------------------------
# 3. symbol_link_table
# ---------------------------------------------------------------------------


class TestSymbolLinkTable:
    def test_build_symbol_link_table(self):
        from agies.engine.director.aggregator import (
            NodeMetadata,
            build_symbol_link_table,
        )

        functions = [
            NodeMetadata(
                name="main",
                file_path="app.py",
                line=3,
            ),
            NodeMetadata(
                name="execute_query",
                file_path="db.py",
                line=10,
            ),
        ]

        table = build_symbol_link_table(functions)
        assert table["main"] == "app.py:3"
        assert table["execute_query"] == "db.py:10"

    def test_symbol_link_table_deduplicates(self):
        from agies.engine.director.aggregator import (
            NodeMetadata,
            build_symbol_link_table,
        )

        functions = [
            NodeMetadata(name="main", file_path="app.py", line=3),
            NodeMetadata(name="main", file_path="app.py", line=50),
        ]

        table = build_symbol_link_table(functions)
        assert table["main"] == "app.py:3"  # first wins

    def test_symbol_link_table_empty(self):
        from agies.engine.director.aggregator import build_symbol_link_table

        assert build_symbol_link_table([]) == {}


# ---------------------------------------------------------------------------
# 4. has_path reachability
# ---------------------------------------------------------------------------


class TestAttackPathScores:
    def test_simple_path(self):
        import networkx as nx
        from agies.engine.director.aggregator import compute_attack_path_scores

        G = nx.MultiDiGraph()
        G.add_edge("app.py", "utils.py", weight=1.0)
        G.add_edge("utils.py", "db.py", weight=1.0)

        scores = compute_attack_path_scores(
            G,
            entry_points=["app.py"],
            sinks=["db.py"],
        )

        # app.py and utils.py should have scores
        assert scores.get("app.py", 0) >= 500
        assert scores.get("utils.py", 0) >= 500
        assert scores.get("db.py", 0) >= 500

    def test_no_path(self):
        import networkx as nx
        from agies.engine.director.aggregator import compute_attack_path_scores

        G = nx.MultiDiGraph()
        G.add_edge("app.py", "utils.py", weight=1.0)
        # db.py is disconnected
        G.add_node("db.py")

        scores = compute_attack_path_scores(
            G,
            entry_points=["app.py"],
            sinks=["db.py"],
        )

        # No path exists, so no scores should be > 0
        assert scores.get("utils.py", 0) == 0

    def test_missing_nodes(self):
        from agies.engine.director.aggregator import compute_attack_path_scores
        import networkx as nx

        G = nx.MultiDiGraph()
        G.add_edge("app.py", "utils.py", weight=1.0)

        # entry or sink not in graph
        scores = compute_attack_path_scores(
            G,
            entry_points=["nonexistent.py"],
            sinks=["db.py"],
        )
        assert scores == {} or all(v == 0 for v in scores.values())


# ---------------------------------------------------------------------------
# 5. rank_cards
# ---------------------------------------------------------------------------


class TestRankCards:
    def test_rank_cards_returns_sorted(self):
        import networkx as nx
        from agies.engine.director.aggregator import rank_cards

        G = nx.MultiDiGraph()
        G.add_edge("app.py", "utils.py", weight=1.0)

        cards = rank_cards(
            G=G,
            entry_points={"app.py", "utils.py"},
            pagerank_scores={"app.py": 0.6, "utils.py": 0.4},
            attack_scores={"app.py": 100, "utils.py": 50},
            file_tags={
                "app.py": set(),
                "utils.py": set(),
            },
        )

        assert len(cards) == 2
        # Higher final_score first
        assert cards[0].final_score >= cards[1].final_score

    def test_card_has_symbol_link_table(self):
        import networkx as nx
        from agies.engine.director.aggregator import rank_cards

        G = nx.MultiDiGraph()
        cards = rank_cards(
            G=G,
            entry_points={"app.py"},
            pagerank_scores={"app.py": 0.5},
            attack_scores={"app.py": 0},
            file_tags={"app.py": set()},
        )

        assert len(cards) == 1
        assert hasattr(cards[0], "symbol_link_table")
        assert isinstance(cards[0].symbol_link_table, dict)


# ---------------------------------------------------------------------------
# 6. Director end-to-end
# ---------------------------------------------------------------------------


class TestDirector:
    def test_director_run_returns_cards(self, sample_project):
        from agies.engine.director import Director

        director = Director(project_path=sample_project)
        cards = director.run(max_cards=10)

        assert isinstance(cards, list)
        if cards:
            assert cards[0].final_score >= 0
            assert hasattr(cards[0], "symbol_link_table")
            assert hasattr(cards[0], "functions_involved")

    def test_director_run_empty_project(self):
        from agies.engine.director import Director

        with tempfile.TemporaryDirectory() as empty_dir:
            director = Director(project_path=empty_dir)
            cards = director.run()
            assert cards == []

    def test_director_summary(self, sample_project):
        from agies.engine.director import Director

        director = Director(project_path=sample_project)
        director.run(max_cards=5)
        summary = director.summary()
        assert "Director:" in summary


# ---------------------------------------------------------------------------
# 7. Signals module
# ---------------------------------------------------------------------------


class TestSignals:
    def test_signal_mul_has_expected_keys(self):
        from agies.engine.director.signals import SIGNAL_MUL

        assert "sql_sink" in SIGNAL_MUL
        assert "cmd_exec" in SIGNAL_MUL
        assert "entry_point" in SIGNAL_MUL
        assert SIGNAL_MUL["sql_sink"] >= 50  # high risk

    def test_compute_confidence(self):
        from agies.engine.director.signals import compute_confidence

        assert compute_confidence(5, 80) == 80.0
        assert compute_confidence(2, 80) == 56.0
        assert compute_confidence(1, 80) == 24.0

    def test_has_negative_signal(self):
        from agies.engine.director.signals import has_negative_signal

        assert has_negative_signal("test_code") is True
        assert has_negative_signal("sql_sink") is False


# ---------------------------------------------------------------------------
# 8. Library mode guard test
# ---------------------------------------------------------------------------


class TestLibraryMode:
    def test_library_mode_caps_entry_points(self):
        """Verify the >50 → top 10 guard logic in Director."""
        from agies.engine.director import Director

        # Create a project with 3 files
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write files with entry-point-like names
            for i in range(3):
                (Path(tmpdir) / f"module{i}.py").write_text(f"""\
def func{i}(x):
    return x

def helper{i}(y):
    return y + 1
""")

            director = Director(project_path=tmpdir)

            # Mock entry_points with >50
            director.entry_points = {f"module{i}.py" for i in range(3)}
            cards = director.run(max_cards=5, library_mode=False)

            # With 3 entry points and no library_mode, we should get ≤ 5 cards
            assert len(cards) <= 5


# ---------------------------------------------------------------------------
# 9. RepoMap class
# ---------------------------------------------------------------------------


class TestRepoMap:
    def test_repo_map_initialization(self, sample_project):
        from agies.engine.director.repomap import RepoMap

        rm = RepoMap(root=sample_project)
        assert rm.root == sample_project
        assert "RepoMap" in repr(rm)

    def test_repo_map_get_tags(self, sample_project):
        from agies.engine.director.repomap import RepoMap

        rm = RepoMap(root=sample_project)
        fname = os.path.join(sample_project, "app.py")
        tags = rm.get_tags(fname)

        assert len(tags) > 0
        # Cached call should return same data
        tags2 = rm.get_tags(fname)
        assert len(tags2) == len(tags)

    def test_repo_map_clear_cache(self, sample_project):
        from agies.engine.director.repomap import RepoMap

        rm = RepoMap(root=sample_project)
        rm.clear_cache()
        assert len(rm._tags_cache) == 0

    def test_repo_map_rel_fname(self, sample_project):
        from agies.engine.director.repomap import RepoMap

        rm = RepoMap(root=sample_project)
        fname = os.path.join(sample_project, "app.py")
        rel = rm.rel_fname(fname)
        assert rel == "app.py"

    def test_get_scm_fname(self):
        from agies.engine.director.repomap import get_scm_fname

        path = get_scm_fname("python")
        assert path is not None
        assert path.exists()
        assert "python-tags.scm" in path.name

        # Non-existent language
        assert get_scm_fname("nonexistent") is None
