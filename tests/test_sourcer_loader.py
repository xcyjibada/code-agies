"""Tests for agies.engine.sourcer.loader — card-aware function indexing."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from agies.engine.v2.sourcer.extractor import extract_functions
from agies.engine.v2.sourcer.loader import build_index
from agies.engine.v2.sourcer.models import SourceFile


def _write_py_file(tmpdir: str, name: str, code: str) -> str:
    p = Path(tmpdir) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code)
    return str(p)


class TestBuildIndexFullIndexPaths:
    """build_index() with full_index_paths parameter."""

    def test_no_full_index_paths_indexes_all(self) -> None:
        """Without full_index_paths, all files get full function extraction."""
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_py_file(tmpdir, "a.py", "def foo():\n    return 1\n")
            _write_py_file(tmpdir, "b.py", "def bar():\n    return 2\n")

            index = build_index(tmpdir)
            assert index.total_files == 2
            assert index.total_functions == 2

    def test_full_index_paths_filters_functions(self) -> None:
        """Only files in full_index_paths get function extraction."""
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_py_file(tmpdir, "hot.py", "def foo():\n    return 1\n")
            _write_py_file(tmpdir, "cold.py", "def bar():\n    return 2\n")

            hot_path = os.path.normpath(os.path.join(tmpdir, "hot.py"))
            index = build_index(tmpdir, full_index_paths={hot_path})

            assert index.total_files == 2
            assert index.total_functions == 1
            # Only foo (from hot.py) should be extracted
            assert index.lookup("foo")
            assert not index.lookup("bar")

    def test_full_index_paths_with_relative(self) -> None:
        """Relative paths in full_index_paths are resolved correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_py_file(tmpdir, "src/a.py", "def foo():\n    return 1\n")
            _write_py_file(tmpdir, "src/b.py", "def bar():\n    return 2\n")

            index = build_index(tmpdir, full_index_paths={"src/a.py"})

            assert index.total_files == 2
            assert index.total_functions == 1
            assert index.lookup("foo")
            assert not index.lookup("bar")

    def test_empty_full_index_paths_no_extraction(self) -> None:
        """Empty full_index_paths means no function extraction at all."""
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_py_file(tmpdir, "a.py", "def foo():\n    return 1\n")

            index = build_index(tmpdir, full_index_paths=set())
            assert index.total_files == 1
            assert index.total_functions == 0

    def test_call_graph_only_for_full_index_files(self) -> None:
        """Call graph is only built for files in full_index_paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_py_file(
                tmpdir, "hot.py",
                "def foo():\n    return bar()\ndef bar():\n    return 1\n",
            )
            _write_py_file(
                tmpdir, "cold.py",
                "def baz():\n    return qux()\ndef qux():\n    return 2\n",
            )

            hot_path = os.path.normpath(os.path.join(tmpdir, "hot.py"))
            index = build_index(tmpdir, full_index_paths={hot_path})

            # Functions from hot.py exist
            assert index.lookup("foo")
            assert index.lookup("bar")
            # Functions from cold.py don't
            assert not index.lookup("baz")

            # Call graph should have bar→foo (from hot.py) but not qux→baz
            # build_call_graph_from_calls stores callee→{callers}
            # bar is called by foo, so call_graph["bar"] == {"foo"}
            callers_of_bar = index.call_graph.get("bar", set())
            assert "foo" in callers_of_bar
