"""CodeQL-based graph generator — resolves **cross-file** call graphs via
CodeQL's static analysis engine.

Replaces the tree-sitter approach for languages CodeQL supports (Python,
JavaScript, TypeScript, Java, Go, C/C++, C#, Ruby, Swift).  Falls back to
tree-sitter when CodeQL is not available.

Usage::

    from agies.engine.graph import CodeQLGraphGenerator

    gen = CodeQLGraphGenerator()
    pg = gen.build_program_graph("/path/to/project")
    slices = gen.create_slices(pg, entry_points={...})

CodeQL Installation
-------------------
The generator auto-detects the ``codeql`` CLI in PATH or common locations.
If not found, install from::

    https://github.com/github/codeql-cli-binaries/releases

Standard Query Library
----------------------
The first run downloads the ``codeql/python-all`` pack automatically (via
``codeql pack install``).  Subsequent runs use the cached copy.
"""

from __future__ import annotations

import csv
import logging
import os
import subprocess
import tempfile
from typing import Any

from agies.engine.graph.base import GraphGenerator
from agies.engine.graph.models import (
    GraphNode,
    ProgramGraph,
    _make_node_id,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# QL queries (embedded — also maintained in agies/engine/graph/codeql_queries/)
# ---------------------------------------------------------------------------

QLPACK_YML = """\
name: agies/codeql-graph
version: 0.0.1
dependencies:
  codeql/python-all: "*"
"""

FUNCTIONS_QL = """\
import python

from Function f
where not f.isExtern()
select
  f.getName(),
  f.getFile().getRelativePath(),
  f.getLocation().getStartLine(),
  f.getLocation().getEndLine()
"""

CALL_EDGES_QL = """\
import python

from Call c, Function caller, Function callee
where
  c.getEnclosingFunction() = caller and
  c.getTarget() = callee and
  caller != callee
select
  caller.getName(),
  caller.getFile().getRelativePath(),
  caller.getLocation().getStartLine(),
  callee.getName(),
  callee.getFile().getRelativePath(),
  callee.getLocation().getStartLine()
"""

SOURCE_QL = """\
import python

from Function f
where not f.isExtern()
select
  f.getName(),
  f.getFile().getRelativePath(),
  f.getLocation().getStartLine(),
  f.getLocation().getEndLine(),
  f.getSignature().toString()
"""


class CodeQLGraphGenerator(GraphGenerator):
    """GraphGenerator implementation backed by CodeQL CLI.

    Parameters
    ----------
    codeql_bin : str
        Path to the ``codeql`` CLI binary.  Auto-detected from PATH when
        empty.
    codeql_db : str
        Path to an existing CodeQL database directory.  When empty, a
        temporary database is created and discarded after analysis.
    query_dir : str or None
        Path to a directory containing ``qlpack.yml`` and the QL query
        files.  When None, queries are created in a temp directory.
    """

    def __init__(
        self,
        codeql_bin: str = "",
        codeql_db: str = "",
        query_dir: str | None = None,
    ) -> None:
        self._codeql_bin = codeql_bin or self._find_codeql()
        self._codeql_db = codeql_db
        self._query_dir = query_dir
        self._source_cache: dict[str, str] = {}
        self._signal_cache: dict[str, dict[str, float]] = {}

    # ------------------------------------------------------------------
    # Public interface (matches GraphGenerator ABC)
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
        """Build a ``ProgramGraph`` using CodeQL.

        Pipeline::

            1. ``codeql database create`` — index the project
            2. ``codeql pack install`` — ensure QL dependencies
            3. ``codeql query run functions.ql`` — extract function nodes
            4. ``codeql query run call_edges.ql`` — extract call edges
            5. Build ``ProgramGraph`` from extracted data
        """
        logger.info("CodeQLGraphGenerator: building graph for %s", project_path)

        # Step 1: Create or reuse CodeQL database
        db_dir = self._ensure_database(project_path)
        logger.info("CodeQLGraphGenerator: database at %s", db_dir)

        # Step 2: Set up QL pack and run queries
        with tempfile.TemporaryDirectory(suffix="-codeql-queries") as ql_dir:
            if self._query_dir and os.path.isdir(self._query_dir):
                # Use the pre-installed queries from package dir
                self._run_query_pack(self._query_dir, db_dir, ql_dir)
            else:
                # Write inline queries to temp dir
                self._write_queries(ql_dir)
                self._install_pack(ql_dir)
                self._run_all_queries(ql_dir, db_dir)

            # Step 3: Parse results
            funcs_csv = self._read_bqrs_csv(os.path.join(ql_dir, "funcs.bqrs"))
            edges_csv = self._read_bqrs_csv(os.path.join(ql_dir, "edges.bqrs"))

        # Step 4: Build ProgramGraph
        pg = self._build_graph(funcs_csv, edges_csv, project_path)

        # Step 5: Cache source code for get_source_code()
        self._cache_source_codes(project_path, pg)

        logger.info(
            "CodeQLGraphGenerator: %d nodes, %d edges",
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
    # Database management
    # ------------------------------------------------------------------

    def _ensure_database(self, project_path: str) -> str:
        """Create or verify a CodeQL database for *project_path*."""
        # If user provided an existing db path, use it
        if self._codeql_db:
            if os.path.isdir(os.path.join(self._codeql_db, "db-python")):
                logger.info("Using existing CodeQL database at %s", self._codeql_db)
                return self._codeql_db
            logger.info("CodeQL database dir exists but incomplete, rebuilding...")

        db_dir = self._codeql_db or tempfile.mkdtemp(prefix="codeql-db-")
        logger.info("Creating CodeQL database...")
        try:
            subprocess.run(
                [self._codeql_bin, "database", "create",
                 "--language=python",
                 "--source-root", project_path,
                 db_dir],
                check=True, capture_output=True, timeout=600,
            )
        except subprocess.TimeoutExpired:
            logger.warning("CodeQL database creation timed out for %s", project_path)
            raise
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode() if exc.stderr else ""
            logger.error("CodeQL database create failed: %s", stderr)
            raise

        return db_dir

    # ------------------------------------------------------------------
    # QL pack management
    # ------------------------------------------------------------------

    @staticmethod
    def _write_queries(ql_dir: str) -> None:
        """Write QL queries and pack config to *ql_dir*."""
        queries_dir = os.path.join(ql_dir, "queries")
        os.makedirs(queries_dir, exist_ok=True)

        with open(os.path.join(ql_dir, "qlpack.yml"), "w") as f:
            f.write(QLPACK_YML)

        queries = {
            "functions.ql": FUNCTIONS_QL,
            "call_edges.ql": CALL_EDGES_QL,
            "source_code.ql": SOURCE_QL,
        }
        for name, content in queries.items():
            with open(os.path.join(queries_dir, name), "w") as f:
                f.write(content)

    def _install_pack(self, ql_dir: str) -> None:
        """Run ``codeql pack install`` in *ql_dir* to resolve dependencies."""
        logger.info("CodeQLGraphGenerator: installing QL pack dependencies...")
        try:
            subprocess.run(
                [self._codeql_bin, "pack", "install"],
                cwd=ql_dir,
                check=True, capture_output=True, timeout=300,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            stderr = exc.stderr.decode() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
            logger.warning(
                "CodeQL pack install failed (will try --search-path fallback): %s",
                stderr[:200],
            )

    def _run_query_pack(self, query_dir: str, db_dir: str, out_dir: str) -> None:
        """Run queries from an existing query pack directory."""
        queries_dir = os.path.join(query_dir, "queries")

        for qname in ("functions", "call_edges", "source_code"):
            qfile = os.path.join(queries_dir, f"{qname}.ql")
            if not os.path.isfile(qfile):
                logger.warning("Query file not found: %s", qfile)
                continue
            out_path = os.path.join(out_dir, f"{qname}.bqrs")
            self._run_query(qfile, db_dir, out_path, search_path=query_dir)

    def _run_all_queries(self, ql_dir: str, db_dir: str) -> None:
        """Run all three QL queries against the database."""
        queries_dir = os.path.join(ql_dir, "queries")

        for qname in ("functions", "call_edges", "source_code"):
            qfile = os.path.join(queries_dir, f"{qname}.ql")
            out_path = os.path.join(ql_dir, f"{qname}.bqrs")
            self._run_query(qfile, db_dir, out_path, search_path=ql_dir)

    def _run_query(
        self,
        ql_file: str,
        db_dir: str,
        out_path: str,
        search_path: str = "",
    ) -> None:
        """Execute a single QL query against the database."""
        cmd = [self._codeql_bin, "query", "run", ql_file,
               "--database", db_dir,
               "--output", out_path]

        if search_path:
            cmd.extend(["--search-path", search_path])

        logger.debug("Running query: %s", os.path.basename(ql_file))
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=600)
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode() if exc.stderr else ""
            logger.error(
                "Query %s failed: %s",
                os.path.basename(ql_file), stderr[:500],
            )
            # Write empty bqrs marker so downstream doesn't hang
            with open(out_path, "w") as f:
                f.write("")

    # ------------------------------------------------------------------
    # Result parsing
    # ------------------------------------------------------------------

    def _read_bqrs_csv(self, bqrs_path: str) -> str:
        """Decode a .bqrs file to CSV text.

        Returns empty string on failure (so the CSV parser handles it
        gracefully).
        """
        if not os.path.isfile(bqrs_path) or os.path.getsize(bqrs_path) == 0:
            return ""

        try:
            result = subprocess.run(
                [self._codeql_bin, "bqrs", "decode", "--format=csv", bqrs_path],
                capture_output=True, check=True, timeout=60,
            )
            return result.stdout.decode()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            logger.warning("bqrs decode failed for %s: %s", bqrs_path, exc)
            return ""

    def _build_graph(
        self,
        funcs_csv: str,
        edges_csv: str,
        project_path: str,
    ) -> ProgramGraph:
        """Parse CSV results into a ProgramGraph."""
        pg = ProgramGraph()

        # -- Parse functions --
        if funcs_csv:
            for row in csv.reader(funcs_csv.splitlines()):
                if len(row) < 4:
                    continue
                name, rel_path, start_line_s, end_line_s = row[0], row[1], row[2], row[3]
                try:
                    start_line = int(start_line_s)
                    end_line = int(end_line_s)
                except (ValueError, TypeError):
                    continue

                # Resolve relative path to absolute
                abs_path = os.path.normpath(os.path.join(project_path, rel_path))
                node_id = _make_node_id(abs_path, name)

                node = GraphNode(
                    id=node_id,
                    name=name,
                    qualified_name=name,
                    file_path=abs_path,
                    line_start=start_line,
                    line_end=end_line,
                )
                pg.add_node(node)

        logger.info(
            "CodeQL: parsed %d function nodes",
            pg.total_nodes,
        )

        # -- Parse call edges --
        if edges_csv:
            edge_count = 0
            for row in csv.reader(edges_csv.splitlines()):
                if len(row) < 6:
                    continue
                caller_name, caller_file = row[0], row[1]
                # row[2] = caller line (unused)
                callee_name, callee_file = row[3], row[4]
                # row[5] = callee line (unused)

                caller_id = _make_node_id(
                    os.path.normpath(os.path.join(project_path, caller_file)),
                    caller_name,
                )
                callee_id = _make_node_id(
                    os.path.normpath(os.path.join(project_path, callee_file)),
                    callee_name,
                )

                if caller_id in pg.nodes and callee_id in pg.nodes:
                    pg.add_edge(caller_id, callee_id)
                    edge_count += 1

            logger.info("CodeQL: parsed %d call edges", edge_count)

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
    # CodeQL binary discovery
    # ------------------------------------------------------------------

    @staticmethod
    def _find_codeql() -> str:
        """Locate the ``codeql`` CLI binary.

        Searches PATH first, then common installation directories.
        Raises ``FileNotFoundError`` if not found.
        """
        import shutil

        codeql = shutil.which("codeql")
        if codeql:
            return codeql

        candidates = [
            os.path.expanduser("~/.local/share/codeql/codeql"),
            os.path.expanduser("~/.local/bin/codeql"),
            "/usr/local/bin/codeql",
            "/usr/local/share/codeql/codeql",
            "/opt/codeql/codeql",
            "/opt/homebrew/bin/codeql",
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c

        raise FileNotFoundError(
            "CodeQL CLI not found. "
            "Install from https://github.com/github/codeql-cli-binaries/releases\n"
            "Or ensure 'codeql' is in your PATH."
        )

    @staticmethod
    def check_available() -> bool:
        """Return True if the ``codeql`` CLI is available on this system."""
        try:
            CodeQLGraphGenerator._find_codeql()
            return True
        except FileNotFoundError:
            return False

    @staticmethod
    def ensure_installed(install_dir: str = "") -> str:
        """Download and install CodeQL CLI to *install_dir* (or ~/.local/share/codeql).

        Requires ``curl`` and ``unzip`` to be available.

        Returns the path to the ``codeql`` binary.
        """
        import stat
        import urllib.request
        import zipfile

        dest = install_dir or os.path.expanduser("~/.local/share/codeql")
        bin_path = os.path.join(dest, "codeql")

        if os.path.isfile(bin_path):
            logger.info("CodeQL already installed at %s", bin_path)
            return bin_path

        logger.info("Downloading CodeQL CLI...")
        url = (
            "https://github.com/github/codeql-cli-binaries/releases/"
            "download/v2.25.5/codeql-linux64.zip"
        )

        os.makedirs(dest, exist_ok=True)
        zip_path = os.path.join(dest, "codeql.zip")

        try:
            urllib.request.urlretrieve(url, zip_path)
        except Exception as exc:
            raise RuntimeError(f"Failed to download CodeQL: {exc}") from exc

        logger.info("Extracting CodeQL...")
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(dest)

        os.remove(zip_path)

        # Make binary executable
        if os.path.isfile(bin_path):
            st = os.stat(bin_path)
            os.chmod(bin_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

        logger.info("CodeQL installed at %s", bin_path)
        return bin_path
