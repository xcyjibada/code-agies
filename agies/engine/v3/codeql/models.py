"""Data models for CodeQL source→sink paths."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


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
    SUSPICIOUS = "suspicious"
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
    VulnType.SUSPICIOUS: "Suspicious — requires analysis (path constructor / logic pattern)",
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
