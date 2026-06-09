"""CodeQL query runner — create DB, run QL queries, parse BQRS results.

Reuses and extends the infrastructure from ``engine/graph/codeql.py`` with
source→sink vulnerability query support.
"""

from __future__ import annotations

import csv
import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from agies.engine.v3.codeql.models import (
    CodeQlPath,
    PathNode,
    QueryResult,
    VulnType,
    VULN_LABELS,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# QL query definitions  —  each maps to a .ql file in queries/
# ---------------------------------------------------------------------------

QUERY_REGISTRY: dict[VulnType, str] = {
    VulnType.RCE: "rce.ql",
    VulnType.LFI: "lfi.ql",
    VulnType.SSRF: "ssrf.ql",
    VulnType.SQLI: "sqli.ql",
    VulnType.XSS: "xss.ql",
    VulnType.AFO: "afo.ql",
    VulnType.IDOR: "idor.ql",
    VulnType.REDOS: "redos.ql",
}

DATAFLOW_QUERIES: dict[VulnType, str] = {
    VulnType.RCE: "rce_dataflow.ql",
}


class CodeQLQueryRunner:
    """Run CodeQL source→sink queries against a project.

    Pipeline::

        1. Create/verify CodeQL database
        2. Install QL pack dependencies
        3. Run vulnerability queries (sink + dataflow)
        4. Parse BQRS → structured QueryResult
        5. Report results

    Parameters
    ----------
    project_path : str
        Path to the project to analyze.
    codeql_bin : str
        Path to the ``codeql`` CLI. Auto-detected when empty.
    query_dir : str or None
        Path to pre-installed query pack directory (default: built-in queries).
    db_dir : str or None
        Path to store/use CodeQL database. Temp dir when empty.
    """

    def __init__(
        self,
        project_path: str,
        codeql_bin: str = "",
        query_dir: str | None = None,
        db_dir: str | None = None,
    ) -> None:
        self.project_path = project_path
        self._codeql_bin = codeql_bin or self._find_codeql()
        self._query_dir = query_dir
        self._db_dir = db_dir
        self._db_created = False

        # Locate built-in queries relative to this file
        if not self._query_dir:
            self._query_dir = os.path.join(
                os.path.dirname(__file__), "queries",
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_all(self) -> list[QueryResult]:
        """Run all registered queries and return results."""
        results: list[QueryResult] = []

        if not self._codeql_bin:
            return [QueryResult(
                vuln_type=VulnType.UNKNOWN,
                label="CodeQL Not Found",
                total_sinks=0,
                error="CodeQL CLI not found. Install from github.com/github/codeql-cli-binaries",
            )]

        # Step 1: Create database
        db_dir = self._ensure_database()

        # Step 2: Install pack dependencies
        self._install_pack()

        # Step 3: Run sink queries
        for vuln_type, ql_file in QUERY_REGISTRY.items():
            result = self._run_sink_query(vuln_type, ql_file, db_dir)
            results.append(result)

        # Step 4: Run dataflow queries (best-effort)
        for vuln_type, ql_file in DATAFLOW_QUERIES.items():
            result = self._run_dataflow_query(vuln_type, ql_file, db_dir)
            results.append(result)

        return results

    def run_one(self, vuln_type: VulnType) -> QueryResult:
        """Run a single vulnerability query."""
        ql_file = QUERY_REGISTRY.get(vuln_type)
        if not ql_file:
            return QueryResult(
                vuln_type=vuln_type,
                label=VULN_LABELS.get(vuln_type, str(vuln_type)),
                total_sinks=0,
                error=f"No query registered for {vuln_type}",
            )

        db_dir = self._ensure_database()
        self._install_pack()
        return self._run_sink_query(vuln_type, ql_file, db_dir)

    # ------------------------------------------------------------------
    # Database management
    # ------------------------------------------------------------------

    def _ensure_database(self) -> str:
        """Create or verify CodeQL database."""
        if self._db_created and self._db_dir:
            return self._db_dir

        db_dir = self._db_dir or tempfile.mkdtemp(prefix="agies-codeql-db-")
        self._db_dir = db_dir

        logger.info("Creating CodeQL database for %s ...", self.project_path)
        try:
            subprocess.run(
                [self._codeql_bin, "database", "create",
                 "--language=python",
                 "--source-root", self.project_path,
                 db_dir],
                check=True, capture_output=True, timeout=600,
            )
        except subprocess.TimeoutExpired:
            logger.warning("CodeQL database creation timed out")
            raise
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode() if exc.stderr else ""
            logger.error("CodeQL database create failed: %s", stderr[:500])
            raise

        self._db_created = True
        return db_dir

    # ------------------------------------------------------------------
    # QL pack management
    # ------------------------------------------------------------------

    def _install_pack(self) -> None:
        """Run ``codeql pack install`` in the query directory."""
        try:
            subprocess.run(
                [self._codeql_bin, "pack", "install"],
                cwd=self._query_dir,
                check=True, capture_output=True, timeout=300,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            stderr = exc.stderr.decode() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
            logger.warning(
                "codeql pack install failed (queries may still work): %s",
                stderr[:200],
            )

    # ------------------------------------------------------------------
    # Sink queries (basic — no dataflow)
    # ------------------------------------------------------------------

    def _run_sink_query(
        self,
        vuln_type: VulnType,
        ql_file: str,
        db_dir: str,
    ) -> QueryResult:
        """Run a sink-detection query and parse results."""
        label = VULN_LABELS.get(vuln_type, str(vuln_type))
        ql_path = os.path.join(self._query_dir, ql_file)

        if not os.path.isfile(ql_path):
            return QueryResult(
                vuln_type=vuln_type, label=label, total_sinks=0,
                error=f"Query file not found: {ql_path}",
            )

        start = time.time()
        out_path = os.path.join(
            tempfile.mkdtemp(prefix="agies-cql-out-"),
            f"{vuln_type.value}.bqrs",
        )

        try:
            subprocess.run(
                [self._codeql_bin, "query", "run", ql_path,
                 "--database", db_dir,
                 "--output", out_path,
                 "--search-path", self._query_dir],
                check=True, capture_output=True, timeout=600,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode() if exc.stderr else ""
            return QueryResult(
                vuln_type=vuln_type, label=label, total_sinks=0,
                error=stderr[:300], duration_seconds=time.time() - start,
            )
        except subprocess.TimeoutExpired:
            return QueryResult(
                vuln_type=vuln_type, label=label, total_sinks=0,
                error="Query timed out", duration_seconds=time.time() - start,
            )

        # Parse BQRS → CSV → structured paths
        paths = self._parse_sink_csv(out_path, vuln_type)
        elapsed = time.time() - start

        return QueryResult(
            vuln_type=vuln_type, label=label,
            total_sinks=len(paths), paths=paths,
            duration_seconds=elapsed,
        )

    def _parse_sink_csv(
        self,
        bqrs_path: str,
        vuln_type: VulnType,
    ) -> list[CodeQlPath]:
        """Parse a sink-query BQRS → CSV output into CodeQlPath list."""
        if not os.path.isfile(bqrs_path) or os.path.getsize(bqrs_path) == 0:
            return []

        try:
            result = subprocess.run(
                [self._codeql_bin, "bqrs", "decode", "--format=csv", bqrs_path],
                capture_output=True, check=True, timeout=60,
            )
            csv_text = result.stdout.decode()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            logger.warning("bqrs decode failed for %s: %s", bqrs_path, exc)
            return []

        paths: list[CodeQlPath] = []
        seen: set[str] = set()

        # Expected CSV format (from sink queries):
        # sink_type, sink_file, sink_line, sink_name
        for row in csv.reader(csv_text.splitlines()):
            if len(row) < 4:
                continue

            sink_type_raw = row[0]
            sink_file = row[1]
            sink_line_raw = row[2]
            sink_name = row[3] if len(row) > 3 else ""

            try:
                sink_line = int(sink_line_raw)
            except (ValueError, TypeError):
                sink_line = 0

            path = CodeQlPath(
                vuln_type=vuln_type,
                source="<remote>",
                source_file="<unknown>",
                source_line=0,
                sink=sink_name,
                sink_file=sink_file,
                sink_line=sink_line,
                message=f"{vuln_type.value.upper()} sink: {sink_name} at {sink_file}:{sink_line}",
                confidence=0.6,
            )

            if path.key not in seen:
                seen.add(path.key)
                paths.append(path)

        return paths

    # ------------------------------------------------------------------
    # Dataflow path queries (best-effort)
    # ------------------------------------------------------------------

    def _run_dataflow_query(
        self,
        vuln_type: VulnType,
        ql_file: str,
        db_dir: str,
    ) -> QueryResult:
        """Run a path-problem dataflow query (best-effort).

        Returns an empty result gracefully on failure — this is a bonus
        enhancement over the sink queries.
        """
        label = f"{VULN_LABELS.get(vuln_type, str(vuln_type))} [dataflow]"
        ql_path = os.path.join(self._query_dir, ql_file)

        if not os.path.isfile(ql_path):
            return QueryResult(
                vuln_type=vuln_type, label=label, total_sinks=0,
            )

        start = time.time()
        out_path = os.path.join(
            tempfile.mkdtemp(prefix="agies-cql-df-"),
            f"{vuln_type.value}_dataflow.bqrs",
        )

        try:
            subprocess.run(
                [self._codeql_bin, "query", "run", ql_path,
                 "--database", db_dir,
                 "--output", out_path,
                 "--search-path", self._query_dir],
                check=True, capture_output=True, timeout=600,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            # Dataflow query failed — not critical, sink queries already ran
            return QueryResult(
                vuln_type=vuln_type, label=label, total_sinks=0,
                duration_seconds=time.time() - start,
            )

        paths = self._parse_dataflow_csv(out_path, vuln_type)
        elapsed = time.time() - start

        return QueryResult(
            vuln_type=vuln_type, label=label,
            total_sinks=len(paths), paths=paths,
            duration_seconds=elapsed,
        )

    def _parse_dataflow_csv(
        self,
        bqrs_path: str,
        vuln_type: VulnType,
    ) -> list[CodeQlPath]:
        """Parse dataflow problem-query BQRS → CSV.

        Expected CSV format (from simplified dataflow queries):
          sink_repr, source_file, source_line, sink_file, sink_line, message
        """
        if not os.path.isfile(bqrs_path) or os.path.getsize(bqrs_path) == 0:
            return []

        try:
            result = subprocess.run(
                [self._codeql_bin, "bqrs", "decode", "--format=csv", bqrs_path],
                capture_output=True, check=True, timeout=60,
            )
            csv_text = result.stdout.decode()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return []

        paths: list[CodeQlPath] = []
        seen: set[str] = set()

        # row[0] = sink repr (DataFlow::Node — may be empty in CSV),
        # row[1] = source_file, row[2] = source_line,
        # row[3] = sink_file, row[4] = sink_line,
        # row[5] = message (optional)
        for row in csv.reader(csv_text.splitlines()):
            if len(row) < 5:
                continue

            source_file = row[1].strip()
            source_line_raw = row[2].strip()
            sink_file = row[3].strip()
            sink_line_raw = row[4].strip()
            message = row[5] if len(row) > 5 else ""

            try:
                source_line = int(source_line_raw)
            except (ValueError, TypeError):
                source_line = 0
            try:
                sink_line = int(sink_line_raw)
            except (ValueError, TypeError):
                sink_line = 0

            path = CodeQlPath(
                vuln_type=vuln_type,
                source="<dataflow_source>",
                source_file=source_file,
                source_line=source_line,
                sink="<dataflow_sink>",
                sink_file=sink_file,
                sink_line=sink_line,
                message=message,
                is_full_path=True,
                confidence=0.8,
            )

            if path.key not in seen:
                seen.add(path.key)
                paths.append(path)

        return paths

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _split_loc(loc: str) -> tuple[str, str]:
        """Split ``"path/to/file.py:42"`` → ``("path/to/file.py", "42")``."""
        parts = loc.rsplit(":", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return loc, "0"

    @staticmethod
    def _find_codeql() -> str:
        """Locate the ``codeql`` CLI binary."""
        import shutil

        codeql = shutil.which("codeql")
        if codeql:
            return codeql

        candidates = [
            os.path.expanduser("~/.local/share/codeql/codeql"),
            os.path.expanduser("~/.local/bin/codeql"),
            "/usr/local/bin/codeql",
            "/opt/codeql/codeql",
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c

        return ""

    @staticmethod
    def check_available() -> bool:
        """Return True if CodeQL CLI is available."""
        return bool(CodeQLQueryRunner._find_codeql())

    def summary_text(self, results: list[QueryResult]) -> str:
        """Generate a human-readable summary of all query results."""
        lines: list[str] = []
        total_sinks = 0
        total_df = 0

        for r in results:
            if "dataflow" in r.label.lower():
                tag = "  DF"
                total_df += r.total_sinks
            else:
                tag = "  SNK"
                total_sinks += r.total_sinks

            if r.error:
                lines.append(f"{tag}  {r.label}: [ERROR] {r.error[:80]}")
            elif r.total_sinks == 0:
                lines.append(f"{tag}  {r.label}: 0 sinks  ({r.duration_seconds:.1f}s)")
            else:
                lines.append(f"{tag}  {r.label}: {r.total_sinks} sinks  ({r.duration_seconds:.1f}s)")

        lines.insert(0, f"CodeQL: {len(results)} queries, {total_sinks} sinks, {total_df} dataflow paths")
        return "\n".join(lines)
