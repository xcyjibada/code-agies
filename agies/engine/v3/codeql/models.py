"""Data models for CodeQL source→sink paths."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Reachability(str, enum.Enum):
    """How a source→sink path was established — confidence in reachability.

    CHAIN
        Full call chain traced from a project-internal caller through to the sink.
        Standard case — highest confidence.

    BODY_ONLY
        Body regex matching (``classify_sensitive_body``) found a dangerous API
        call inside a function, but ``_backtrack`` found no callers inside the
        project.  The function may be a library public API called from external
        code.  Lower confidence — goes to Explore slot by default.

    EXTERNAL_API
        Body-detected function that is also a confirmed public API of the library
        (``__all__``, public class method, etc.).  A virtual ``[EXTERNAL_CALLER]``
        node is injected into the path.  Medium confidence — still Explore slot
        but gets higher scoring than BODY_ONLY.
    """

    CHAIN = "chain"
    BODY_ONLY = "body_only"
    EXTERNAL_API = "external_api"


class VulnType(str, enum.Enum):
    """Vulnerability types detected by CodeQL source→sink queries."""

    RCE = "rce"
    LFI = "lfi"
    SSRF = "ssrf"
    SQLI = "sqli"
    XSS = "xss"
    AFO = "afo"
    IDOR = "idor"
    REDOS = "redos"
    XXE = "xxe"
    SSTI = "ssti"
    SUSPICIOUS = "suspicious"
    LANGGRAPH = "langgraph"  # LangGraph-specific architecture-level vulnerabilities (gRPC no-auth, admin truncate, msgpack ext_hook RCE, etc.)
    UNKNOWN = "unknown"


VULN_LABELS: dict[VulnType, str] = {
    VulnType.RCE: "Remote Code Execution",
    VulnType.LFI: "Local File Inclusion",
    VulnType.SSRF: "Server-Side Request Forgery",
    VulnType.SQLI: "SQL Injection",
    VulnType.XSS: "Cross-Site Scripting",
    VulnType.AFO: "Arbitrary File Overwrite",
    VulnType.IDOR: "Insecure Direct Object Reference",
    VulnType.REDOS: "ReDoS (Regular Expression DoS)",
    VulnType.XXE: "XML External Entity (XXE) — XML parser with insecure defaults",
    VulnType.SSTI: "Server-Side Template Injection (SSTI) — template engine with user input",
    VulnType.SUSPICIOUS: "Suspicious — requires analysis (path constructor / logic pattern)",
    VulnType.LANGGRAPH: "LangGraph Architecture — gRPC/gRPC no-auth, admin truncate, msgpack ext_hook RCE, template injection",
    VulnType.UNKNOWN: "Unknown",
}


@dataclass
class PathNode:
    """A single step along a source→sink path."""

    function_name: str
    file_path: str
    line_number: int
    snippet: str = ""


@dataclass
class CodeQlPath:
    """A single source→sink path found by a CodeQL query."""

    vuln_type: VulnType
    source: str
    source_file: str
    source_line: int
    sink: str
    sink_file: str
    sink_line: int
    message: str = ""
    is_full_path: bool = False
    nodes: list[PathNode] = field(default_factory=list)
    confidence: float = 0.5

    source_controllability_proof: str = ""
    """If non-empty, provides evidence that the source function is an
    externally controllable entry point (e.g. HTTP controller route handler).
    Overrides AdversaryAgent's 'no external input' rebuttal by making the
    controllability irrefutable to downstream LLM agents."""

    body_detected: bool = False
    """True when this path was found via body regex matching (``classify_sensitive_body``)
    rather than by function name.  Body-detected sinks have no telltale function name
    (e.g. ``dequeue`` whose body contains ``pickle.loads``) and warrant different scoring
    and exclusion treatment in the sorter."""

    body_sink_call: str = ""
    """The exact dangerous call matched in the function body (e.g. ``pickle.loads(``).
    Used by the sorter to look up severity weight instead of the parent function name."""

    reachability: Reachability = Reachability.CHAIN
    """How this path was established — full call chain, body-only detection,
    or public API inference.  Controls scoring and slot allocation downstream."""

    cpg_data_flow_evidence: str = ""
    """CPG data flow trace from source to sink (e.g. "param → x (L42) → y
    (L43) → sink(arg) (L44)").  Populated by TreeSitterPathFinder when CPG
    builder is enabled.  Empty string means no CPG evidence."""

    cross_file_flow: str = ""
    """Cross-file parameter-level flow annotation.
    Populated by ``dataflow.annotate_paths()`` after path discovery.
    Example: ``handle_request(request) → lookup_path(path) → open_file(filename)``
    Shows which parameter carries taint at each hop in the path."""

    reachability_score_bonus: float = 0.0
    """Score bonus from reachability matrix (Phase 3).
    Added to the path's static score when source is known in the matrix."""

    @property
    def key(self) -> str:
        """Deduplication key."""
        return f"{self.vuln_type.value}:{self.sink_file}:{self.sink_line}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_type": self.vuln_type.value,
            "source": self.source,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "sink": self.sink,
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "message": self.message,
            "is_full_path": self.is_full_path,
            "confidence": self.confidence,
            "reachability": self.reachability.value,
            "cpg_data_flow_evidence": self.cpg_data_flow_evidence,
            "cross_file_flow": self.cross_file_flow,
        }


@dataclass
class QueryResult:
    """Result of running one CodeQL vulnerability query."""

    vuln_type: VulnType
    label: str
    total_sinks: int
    paths: list[CodeQlPath] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: str = ""
