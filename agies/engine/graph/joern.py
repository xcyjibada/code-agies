"""Joern-based graph generator — uses Joern's Code Property Graph (CPG)
for cross-language call graph resolution.

Supports: Java, JavaScript/TypeScript, C/C++, Go, Ruby, Python (via
tree-sitter fallback), and other JVM languages.

Requires the ``agies/joern`` Docker image (build with
``scripts/build_joern_docker.sh``).

Usage::

    from agies.engine.graph import JoernGraphGenerator

    gen = JoernGraphGenerator()
    pg = gen.build_program_graph("/path/to/java_project")
    slices = gen.create_slices(pg, entry_points={...})
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import subprocess
import tempfile
from typing import Any

from agies.engine.graph.base import GraphGenerator
from agies.engine.graph.joern_docker import JoernDocker
from agies.engine.graph.models import (
    GraphNode,
    ProgramGraph,
    _make_node_id,
)

logger = logging.getLogger(__name__)

# Languages where Joern is the preferred engine (over tree-sitter)
JOERN_PREFERRED_LANGS = frozenset({
    ".java", ".class", ".jar",
    ".js", ".jsx", ".ts", ".tsx",
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx",
    ".go",
    ".kt", ".scala",
})

# Languages where tree-sitter is preferred (Joern also supports but tree-sitter is lighter)
JOERN_FALLBACK_LANGS = frozenset({
    ".py", ".rb", ".php", ".cs", ".swift",
})


class JoernGraphGenerator(GraphGenerator):
    """GraphGenerator implementation using Joern's Docker-based CPG.

    Parameters
    ----------
    docker_image : str
        Joern Docker image name/tag.  Default ``agies/joern:latest``.
    work_dir : str or None
        Temp directory for CPG files.  Auto-created when None.
    auto_pull : bool
        If True, call ``ensure_image()`` on first build.  Default True.
    """

    def __init__(
        self,
        docker_image: str = "agies/joern:latest",
        work_dir: str | None = None,
        auto_pull: bool = True,
    ) -> None:
        self._docker = JoernDocker(image=docker_image, work_dir=work_dir)
        self._docker_image = docker_image
        self._auto_pull = auto_pull
        self._source_cache: dict[str, str] = {}
        self._signal_cache: dict[str, dict[str, float]] = {}

    # ------------------------------------------------------------------
    # Public interface (GraphGenerator ABC)
    # ------------------------------------------------------------------

    def build_program_graph(
        self,
        project_path: str,
        entry_points: set[str] | None = None,
        signal_mul: dict[str, float] | None = None,
        feedback_store: Any = None,
        prescan_sinks: set[str] | None = None,
        mentioned_fnames: set[str] | None = None,
        mentioned_idents: set[str] | None = None,
        confirmed_idents: set[str] | None = None,
        suppressed_files: set[str] | None = None,
    ) -> ProgramGraph:
        """Build a ``ProgramGraph`` using Joern's CPG.

        Pipeline::

            1. Ensure Docker image is available
            2. ``joern-parse`` — create CPG from source
            3. ``joern-export --repr=all --format=json`` — export graph
            4. Parse JSON into ``ProgramGraph``
        """
        logger.info("JoernGraphGenerator: building CPG for %s", project_path)

        # Step 1: Ensure image
        if self._auto_pull and not self._docker.check_available():
            ok = self._docker.ensure_image()
            if not ok:
                logger.warning(
                    "Joern Docker image not available. "
                    "Run: bash scripts/build_joern_docker.sh --proxy"
                )
                return ProgramGraph()

        # Step 2: joern-parse
        try:
            cpg_path = self._docker.parse(project_path)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError):
            logger.exception("Joern parse failed for %s", project_path)
            return ProgramGraph()

        # Step 3: joern-export
        try:
            nodes_data, edges_data = self._docker.export_cpg(cpg_path)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            logger.exception("Joern export failed")
            return ProgramGraph()

        # Step 4: Build ProgramGraph
        pg = self._build_graph(nodes_data, edges_data, project_path)

        # Step 5: Cache source code
        self._cache_source_codes(project_path, pg)

        logger.info(
            "JoernGraphGenerator: %d nodes, %d edges",
            pg.total_nodes, pg.total_edges,
        )
        return pg

    def get_source_code(self, node_id: str) -> str | None:
        """Return the full source text for a function by node ID."""
        return self._source_cache.get(node_id)

    def get_node_signals(self, node_id: str) -> dict[str, float]:
        """Return SAST signals (empty — signals come from tree-sitter SAST)."""
        return self._signal_cache.get(node_id, {})

    # ------------------------------------------------------------------
    # CPG → ProgramGraph conversion
    # ------------------------------------------------------------------

    @staticmethod
    def _gprop(props: dict, key: str, default: Any = None) -> Any:
        """Extract a property from GraphSON vertex format.

        GraphSON nests values as::

            props["KEY"]["@value"]["@value"][0]["@value"]
        """
        if key not in props:
            return default
        try:
            lst = props[key]["@value"]["@value"]
            if isinstance(lst, list) and len(lst) > 0:
                val = lst[0]
                return val.get("@value", val) if isinstance(val, dict) else val
            return lst
        except (KeyError, TypeError, IndexError):
            return default

    def _build_graph(
        self,
        nodes_data: list[dict[str, Any]],
        edges_data: list[dict[str, Any]],
        project_path: str,
    ) -> ProgramGraph:
        """Convert Joern CPG GraphSON into ProgramGraph.

        CPG structure::

            METHOD vertices → function definitions (GraphNode)
            CALL vertices → call sites
            Edges of type "CALL" connect CALL → callee METHOD
            Edges of type "CONTAINS" show containment (CALL inside METHOD)
        """
        pg = ProgramGraph()

        # Normalize vertex IDs (GraphSON wraps them in {"@type": ..., "@value": ...})
        def _vid(v: Any) -> int:
            if isinstance(v, dict):
                return int(v.get("@value", 0))
            return int(v) if v else 0

        # --- Step 1: Index vertices & edges ---
        vertex_map: dict[int, dict[str, Any]] = {}
        for nd in nodes_data:
            vid = _vid(nd.get("id"))
            vertex_map[vid] = nd

        # Edge lists by type
        call_edges: list[tuple[int, int]] = []  # (call_vid, callee_mid)
        contains_map: dict[int, int] = {}        # child_vid → parent_vid
        for edge in edges_data:
            label = edge.get("label", "")
            out_v = _vid(edge.get("outV"))
            in_v = _vid(edge.get("inV"))
            if not out_v or not in_v:
                continue
            if label == "CALL":
                call_edges.append((out_v, in_v))
            elif label == "CONTAINS":
                contains_map[in_v] = out_v

        # --- Step 2: METHOD vertices → GraphNode ---
        is_external_set: set[int] = set()
        for vid, v in vertex_map.items():
            label = v.get("label", "")
            if label != "METHOD":
                continue
            is_ext = self._gprop(v.get("properties", {}), "IS_EXTERNAL", "false")
            if str(is_ext).lower() == "true":
                is_external_set.add(vid)
                continue  # skip external methods

            props = v.get("properties", {})
            name = self._gprop(props, "NAME", "unknown")
            full_name = self._gprop(props, "FULL_NAME", name)
            file_name = self._gprop(props, "FILENAME", "")
            line_start = self._gprop(props, "LINE_NUMBER", 0)
            line_end = self._gprop(props, "LINE_NUMBER_END", line_start)
            signature = self._gprop(props, "SIGNATURE", "")

            try:
                line_start = int(line_start) if line_start else 0
            except (ValueError, TypeError):
                line_start = 0
            try:
                line_end = int(line_end) if line_end else 0
            except (ValueError, TypeError):
                line_end = line_start

            if file_name:
                abs_path = (
                    file_name
                    if os.path.isabs(file_name)
                    else os.path.normpath(os.path.join(project_path, file_name))
                )
            else:
                abs_path = project_path

            node_id = _make_node_id(abs_path, name)
            node = GraphNode(
                id=node_id,
                name=name,
                qualified_name=full_name,
                file_path=abs_path,
                line_start=line_start,
                line_end=line_end,
                signature=signature,
            )
            pg.add_node(node)

        logger.info("Joern: parsed %d method nodes from CPG", pg.total_nodes)

        # --- Step 3: Build method_id → node_id mapping ---
        # Key: vid → node_id (for internal methods only)
        vid_to_nid: dict[int, str] = {}
        for vid, v in vertex_map.items():
            if v.get("label") != "METHOD" or vid in is_external_set:
                continue
            props = v.get("properties", {})
            name = self._gprop(props, "NAME", "unknown")
            file_name = self._gprop(props, "FILENAME", "")
            abs_path = (
                file_name
                if os.path.isabs(file_name)
                else os.path.normpath(os.path.join(project_path, file_name))
            )
            vid_to_nid[vid] = _make_node_id(abs_path, name)

        # Build callee_name → node_id lookup for name-based resolution
        name_to_nid: dict[str, str] = {}
        for nid, node in pg.nodes.items():
            name_to_nid[node.name] = nid

        # --- Step 4: Resolve call edges ---
        edge_count = 0
        for call_vid, callee_mid in call_edges:
            # Find the CALL vertex to get caller information
            call_vertex = vertex_map.get(call_vid)
            if not call_vertex:
                continue

            # Walk CONTAINS edges up from CALL to find caller METHOD
            caller_vid = call_vid
            visited: set[int] = set()
            while caller_vid in contains_map and caller_vid not in visited:
                visited.add(caller_vid)
                caller_vid = contains_map[caller_vid]
                if caller_vid in vid_to_nid:
                    break
            else:
                # No enclosing method found
                continue

            caller_id = vid_to_nid.get(caller_vid)
            if not caller_id or caller_id not in pg.nodes:
                continue

            # Callee may be a user-defined method
            callee_id = vid_to_nid.get(callee_mid)
            if not callee_id or callee_id not in pg.nodes:
                # Try name-based resolution
                callee_props = vertex_map.get(callee_mid, {}).get("properties", {})
                callee_name = self._gprop(callee_props, "NAME", "")
                if callee_name and callee_name in name_to_nid:
                    callee_id = name_to_nid[callee_name]
                else:
                    continue

            pg.add_edge(caller_id, callee_id)
            edge_count += 1

        logger.info("Joern: parsed %d call edges from CPG", edge_count)
        return pg

    def _cache_source_codes(
        self,
        project_path: str,
        pg: ProgramGraph,
    ) -> None:
        """Read source files from disk and cache by node ID."""
        for nid, node in pg.nodes.items():
            if node.file_path and os.path.isfile(node.file_path):
                try:
                    with open(node.file_path) as f:
                        src = f.read()
                    self._source_cache[nid] = src
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Language detection
    # ------------------------------------------------------------------

    @staticmethod
    def prefers_language(project_path: str) -> bool:
        """Return True if the project has Joern-preferred source files.

        Scans the project root (first 3 levels) for file extensions that
        Joern handles better than tree-sitter: Java, JS/TS, C/C++, Go.
        """
        import fnmatch

        preferred_exts = JOERN_PREFERRED_LANGS
        for root, dirs, files in os.walk(project_path):
            # Limit depth to 3 levels
            depth = root.replace(project_path, "").count(os.sep)
            if depth > 3:
                dirs[:] = []
                continue
            # Skip hidden dirs
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in preferred_exts:
                    return True
        return False

    @staticmethod
    def check_docker_available() -> bool:
        """Return True if Docker and the Joern image are available."""
        try:
            jd = JoernDocker()
            return jd.check_available()
        except RuntimeError:
            return False

    @staticmethod
    def check_available() -> bool:
        """Return True if Joern (via Docker) is available."""
        return JoernGraphGenerator.check_docker_available()
