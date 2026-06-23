"""Slice data models for v3 pipeline.

A ``PathSlice`` represents one scorable unit of analysis — a source→sink
path found by CodeQL, enriched with sorting metadata and Explore/Exploit
slot allocation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agies.engine.v3.codeql.models import VulnType, CodeQlPath, Reachability


@dataclass
class PathSlice:
    """A scorable, analyzable source→sink path slice.

    Unlike ``CodeQlPath`` (raw output from CodeQL), a ``PathSlice`` has
    been scored, deduplicated, and optionally tagged for the Explore or
    Exploit slot.
    """

    id: str
    """Unique ID like ``"rce-001"``, ``"lfi-003"``."""

    vuln_type: VulnType
    """Vulnerability type (RCE, LFI, SSRF, …)."""

    source: str
    """Source description, e.g. ``"request.getParameter"``."""

    source_file: str
    """Source file and line, e.g. ``"Controller.java:42"``."""

    sink: str
    """Sink function name, e.g. ``"exec"``."""

    sink_file: str
    """Sink file and line, e.g. ``"Util.java:120"``."""

    nodes: list[dict[str, Any]] = field(default_factory=list)
    """Path nodes: ``[{function_name, file_path, line_number}, …]``."""

    code_block: str = ""
    """Concatenated source code of all path functions."""

    score: float = 0.0
    """Static sort score from ``score_path()`` (0-1)."""

    is_full_path: bool = False
    """Whether CodeQL produced a complete source→sink path."""

    has_validation: bool = False
    """Whether path passes through sanitize/validate/escape functions."""

    assigned_slot: str = ""
    """``"exploit"``, ``"explore"``, or ``""`` if unassigned."""

    anomaly_reasons: list[str] = field(default_factory=list)
    """If in explore slot, why this path was flagged as anomalous."""

    source_controllability_proof: str = ""
    """Evidence that the source is an externally controllable entry point.
    Set by TreeSitterPathFinder when the entry function is an HTTP controller.
    Injected into prompt context so downstream agents cannot rebut with
    'no external input'."""

    reachability: Reachability = Reachability.CHAIN
    """How this path was established — affects scoring and slot allocation."""

    # Phase 0: Deterministic data flow fields (populated by dataflow.py / runner.py)
    cpg_data_flow_evidence: str = ""
    """CPG WRITES_TO trace from param to sink call argument (intra-procedural)."""

    cross_file_flow: str = ""
    """Cross-file parameter-level flow annotation (inter-procedural).
    e.g. ``handle_request(request.path -> path) -> lookup_path(path -> filename)``"""

    body_detected: bool = False
    """True when this path was found via body regex matching."""

    body_sink_call: str = ""
    """The exact dangerous call matched in the function body (e.g. ``pickle.loads``)."""

    reachability_context: str = ""
    """Human-readable reachability info from the matrix, e.g.
    ``Source "handle_request" can reach 3 sinks. Sink "exec" reachable from 2 sources.``"""

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_codeql_path(
        cls,
        path: CodeQlPath,
        *,
        idx: int = 0,
        code_block: str = "",
    ) -> PathSlice:
        """Convert a raw CodeQL path to a scorable slice."""
        return cls(
            id=f"{path.vuln_type.value}-{idx:03d}",
            vuln_type=path.vuln_type,
            source=path.source,
            source_file=f"{path.source_file}:{path.source_line}",
            sink=path.sink,
            sink_file=f"{path.sink_file}:{path.sink_line}",
            nodes=[n.__dict__ for n in path.nodes] if path.nodes else [],
            code_block=code_block,
            is_full_path=path.is_full_path,
            score=path.confidence,
            source_controllability_proof=path.source_controllability_proof,
            reachability=path.reachability,
            cpg_data_flow_evidence=path.cpg_data_flow_evidence,
            cross_file_flow=path.cross_file_flow,
            body_detected=path.body_detected,
            body_sink_call=path.body_sink_call,
        )


@dataclass
class SortResult:
    """Result of sorting a batch of paths."""

    exploit: list[PathSlice]
    """High-confidence paths in the exploit slot."""

    explore: list[PathSlice]
    """Anomalous paths in the explore slot."""

    total_input: int = 0
    """Number of paths before sorting."""

    total_output: int = 0
    """Number of paths after sorting (exploit + explore)."""

    @property
    def all_slices(self) -> list[PathSlice]:
        return self.exploit + self.explore
