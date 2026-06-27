"""CpgBuilder — lightweight, query-callback-based Code Property Graph builder.

Uses tree-sitter ``.scm`` queries + Python callback registry (GRAPH_TRANSFORMERS)
to build a NetworkX DiGraph with ``WRITES_TO``, ``CALLS``, ``ATTRIBUTE_OF`` edges.

Usage::

    from agies.engine.v3.graph.builder import CpgBuilder

    builder = CpgBuilder("/path/to/project")
    builder.build()
    G = builder.graph  # nx.DiGraph

    # Query: does data flow from node A to node B?
    if builder.has_data_flow_path(source_id, sink_id):
        ...

    # Find full data flow chain from sink backwards
    chain = builder.find_backward_chain(sink_id)
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import networkx as nx

from agies.engine.v3.graph.models import (
    WRITES_TO,
    READS,
    CALLS,
    ATTRIBUTE_OF,
    ATTR_FILE,
    ATTR_LINE,
    ATTR_COL,
    ATTR_TEXT,
    ATTR_KIND,
    make_node_id,
)

from agies.engine.v3.graph.transformers import (
    GRAPH_TRANSFORMERS,
    _query_filename,
)

logger = logging.getLogger(__name__)

# Supported language → file extension
_LANG_EXT: dict[str, set[str]] = {
    "python": {".py"},
    "java": {".java"},
    "js": {".js", ".jsx", ".ts", ".tsx"},
}


def _get_parser(language: str) -> Any | None:
    """Get a tree-sitter parser for the given language.

    Returns a tuple ``(parser, language_obj)`` where ``parser`` is
    a ``tree_sitter.Parser`` and ``language_obj`` is a
    ``tree_sitter.Language`` suitable for constructing queries.
    """
    try:
        from agies.engine.v2.sourcer.extractor import _get_parser as _get_ts_parser
        return _get_ts_parser(language)
    except Exception:
        return None


def _iter_project_files(project_path: str, excluded_dirs: set[str] | None = None) -> list[str]:
    """Walk the project tree and yield all source files by language."""
    excluded = excluded_dirs or {
        ".git", "__pycache__", "node_modules", "venv", ".venv",
        "dist", "build", ".tox", ".eggs", "egg-info",
        ".mypy_cache", ".pytest_cache", ".git",
    }
    ext_to_lang: dict[str, str] = {}
    for lang, exts in _LANG_EXT.items():
        for ext in exts:
            ext_to_lang[ext] = lang

    files: list[str] = []
    for root, dirs, fnames in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in excluded]
        for fname in fnames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in ext_to_lang:
                files.append(os.path.join(root, fname))
    return files


class CpgBuilder:
    """Build a Code Property Graph (NetworkX DiGraph) from source code.

    The graph captures:
    - ``WRITES_TO``: variable assignment (``val → var``)
    - ``READS``: variable reads in expressions
    - ``CALLS``: function/method calls
    - ``ATTRIBUTE_OF``: attribute access (``obj → attr``)

    The builder uses a query-callback registration pattern:
    ``.scm`` query files define AST capture patterns, and
    ``GRAPH_TRANSFORMERS`` registry maps captured tags to Python
    callbacks that add edges to the NetworkX graph.
    """

    def __init__(
        self,
        project_path: str,
        *,
        excluded_dirs: set[str] | None = None,
        max_files: int = 0,
    ) -> None:
        self._project_path = os.path.abspath(project_path)
        self._excluded_dirs = excluded_dirs
        self._max_files = max_files
        self._graph: nx.DiGraph = nx.DiGraph()
        self._parsers: dict[str, Any] = {}  # language → (parser, language_obj)
        self._queries: dict[str, Any] = {}  # query_file_path → compiled tree-sitter Query
        self._built = False

    # ── Public API ──

    @property
    def graph(self) -> nx.DiGraph:
        """The built NetworkX DiGraph."""
        return self._graph

    @property
    def built(self) -> bool:
        """Whether the graph has been built."""
        return self._built

    def build(self) -> nx.DiGraph:
        """Build the CPG by scanning all project source files.

        Returns the built NetworkX DiGraph.
        """
        start = time.time()
        files = _iter_project_files(self._project_path, self._excluded_dirs)
        if self._max_files > 0:
            files = files[: self._max_files]

        # Preload queries for each language based on actual files present
        languages_needed = set()
        ext_map: dict[str, str] = {ext: lang for lang, exts in _LANG_EXT.items() for ext in exts}
        for fp in files:
            ext = os.path.splitext(fp)[1].lower()
            lang = ext_map.get(ext)
            if lang:
                languages_needed.add(lang)

        for lang in languages_needed:
            self._ensure_parser(lang)
            self._load_queries(lang)

        if not self._queries:
            logger.warning("CpgBuilder: no queries loaded for languages %s", languages_needed)
            return self._graph

        file_count = 0
        graph_lock = threading.Lock()
        workers = min(8, (os.cpu_count() or 1) + 4)

        def _process_file(
            fp: str, lang: str, parser_info: Any,
        ) -> tuple[str, Any, bytes] | None:
            """Parse one file with tree-sitter — releases GIL during parse."""
            _lang_obj, _parser = parser_info
            try:
                with open(fp, "rb") as f:
                    source_bytes = f.read()
            except OSError:
                return None

            try:
                tree = _parser.parse(source_bytes)
            except Exception:
                return None

            if tree is None or tree.root_node is None:
                return None

            rel_path = os.path.relpath(fp, self._project_path)
            return rel_path, tree, source_bytes

        with ThreadPoolExecutor(max_workers=workers) as executor:
            fut_to_meta: dict[Any, tuple[str, str]] = {}
            for fp in files:
                ext = os.path.splitext(fp)[1].lower()
                lang = ext_map.get(ext)
                if not lang:
                    continue
                parser_info = self._parsers.get(lang)
                if parser_info is None:
                    continue
                fut = executor.submit(_process_file, fp, lang, parser_info)
                fut_to_meta[fut] = (fp, lang)

            for future in as_completed(fut_to_meta):
                fp, lang = fut_to_meta[future]
                try:
                    result = future.result()
                except Exception:
                    continue
                if result is None:
                    continue
                rel_path, tree, source_bytes = result

                # Run queries and apply to graph (locked — graph is not thread-safe)
                with graph_lock:
                    for qf_path, qf_queries in self._queries.items():
                        if not self._is_query_for_lang(qf_path, lang):
                            continue
                        for query in qf_queries:
                            self._apply_query(
                                query, qf_path, tree.root_node, source_bytes, rel_path,
                            )

                file_count += 1

        elapsed = time.time() - start
        self._built = True
        logger.info(
            "CpgBuilder: %d files → %d nodes, %d edges (%.2fs)",
            file_count,
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
            elapsed,
        )
        return self._graph

    def has_data_flow_path(self, source_node_id: str, sink_node_id: str) -> bool:
        """Check if there is a data flow path (WRITES_TO + READS) between two nodes."""
        try:
            return nx.has_path(self._graph, source_node_id, sink_node_id)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return False

    def find_backward_chain(
        self,
        sink_node_id: str,
        max_hops: int = 20,
    ) -> list[dict[str, Any]]:
        """Trace backwards from a sink node through WRITES_TO edges.

        Returns a list of node attribute dicts from sink back to source,
        or empty list if no chain found.
        """
        if sink_node_id not in self._graph:
            return []

        visited: set[str] = set()
        chain: list[dict[str, Any]] = []
        current = sink_node_id

        for _ in range(max_hops):
            if current in visited:
                break
            visited.add(current)

            node_data = self._graph.nodes.get(current)
            if node_data:
                chain.append(dict(node_data))

            # Follow WRITES_TO edges backwards (predecessors)
            found = False
            for pred in self._graph.predecessors(current):
                edge_data = self._graph.get_edge_data(pred, current)
                if edge_data and edge_data.get("relationship") in (WRITES_TO, READS):
                    current = pred
                    found = True
                    break

            if not found:
                break

        return chain

    def find_call_chain(
        self,
        func_name: str,
        max_hops: int = 10,
    ) -> list[str]:
        """Find all callers of a function through CALLS edges.

        Returns a list of caller node IDs.
        """
        matches = [
            n for n, d in self._graph.nodes(data=True)
            if d.get(ATTR_KIND) in ("call", "func_def")
            and func_name in d.get(ATTR_TEXT, "")
        ]
        if not matches:
            return []

        # BFS backwards through CALLS edges (find who calls this)
        visited: set[str] = set()
        queue: list[str] = list(matches)
        callers: list[str] = []

        for _ in range(max_hops):
            if not queue:
                break
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            for pred in self._graph.predecessors(current):
                edge_data = self._graph.get_edge_data(pred, current)
                if edge_data and edge_data.get("relationship") == CALLS:
                    if pred not in visited:
                        queue.append(pred)
                        callers.append(pred)

        return callers

    def get_data_flow_summary(self, function_name: str, max_items: int = 5) -> list[str]:
        """Get a human-readable summary of data flowing into a function's parameters."""
        summaries: list[str] = []
        # Find function definition nodes by name
        for n, d in self._graph.nodes(data=True):
            if function_name in d.get(ATTR_TEXT, "") and d.get(ATTR_KIND) in ("call", KIND_FUNC_DEF):
                chain = self.find_backward_chain(n, max_hops=max_items * 4)
                if chain:
                    parts = [c.get(ATTR_TEXT, "?") for c in chain[:max_items]]
                    summaries.append(f"{function_name} ← {' ← '.join(parts)}")
                if len(summaries) >= max_items:
                    break
        return summaries

    # ── Internal helpers ──

    def _ensure_parser(self, language: str) -> None:
        """Get or create a tree-sitter parser for the given language."""
        if language in self._parsers:
            return
        result = _get_parser(language)
        if result is not None:
            self._parsers[language] = result

    @staticmethod
    def _split_query_patterns(query_text: str) -> list[str]:
        """Split a .scm file into individual patterns (blank-line separated),
        skipping comment-only blocks."""
        patterns: list[str] = []
        for block in query_text.split("\n\n"):
            block = block.strip()
            if not block:
                continue
            # Skip blocks that are entirely comments
            if all(line.strip().startswith(";") or not line.strip()
                    for line in block.split("\n")):
                continue
            patterns.append(block)
        return patterns

    def _load_queries(self, language: str) -> None:
        """Load all registered .scm query files for the given language."""
        query_dir = os.path.join(
            os.path.dirname(__file__), "queries", language,
        )
        if not os.path.isdir(query_dir):
            return

        from agies.engine.v3.graph.transformers import list_registered_queries

        for qf_path in list_registered_queries(query_dir):
            if qf_path in self._queries:
                continue
            try:
                with open(qf_path, encoding="utf-8") as f:
                    query_text = f.read()
            except OSError:
                continue

            # Compile each pattern separately to avoid "Impossible pattern"
            # errors on overlapping patterns (newer tree-sitter).
            parser_info = self._parsers.get(language)
            if parser_info is None:
                continue
            lang_obj, _parser = parser_info
            if lang_obj is None:
                continue

            from tree_sitter import Query

            for pattern in self._split_query_patterns(query_text):
                try:
                    query = Query(lang_obj, pattern)
                    self._queries.setdefault(qf_path, []).append(query)
                except Exception as exc:
                    logger.debug(
                        "CpgBuilder: failed to compile pattern in %s: %s",
                        qf_path, exc,
                    )

    @staticmethod
    def _is_query_for_lang(query_path: str, language: str) -> bool:
        """Check if a query file path belongs to the given language."""
        rel = _query_filename(query_path)
        return rel.startswith(f"{language}/") or rel.startswith(f"{language}_")

    def _apply_query(
        self,
        query: Any,
        qf_path: str,
        root_node: Any,
        source_bytes: bytes,
        rel_path: str,
    ) -> None:
        """Execute a tree-sitter query and run all registered transformers."""
        try:
            from tree_sitter import QueryCursor
            cursor = QueryCursor(query)
            matches = list(cursor.matches(root_node))
        except Exception:
            return

        qf_rel = _query_filename(qf_path)

        # Each match is a tuple of (pattern_index, {capture_name: [Node, ...]})
        for _pattern_index, capture_dict in matches:
            # capture_dict is already {name: [Node, ...]}
            for tag_name, nodes in capture_dict.items():
                handler_key = (qf_rel, tag_name)
                handler = GRAPH_TRANSFORMERS.get(handler_key)
                if handler is not None:
                    try:
                        handler(self._graph, capture_dict, source_bytes, rel_path)
                    except Exception as exc:
                        logger.debug(
                            "CpgBuilder: transformer %s failed: %s", handler_key, exc,
                        )
