"""SAST pattern matching engine — model definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SASTRule:
    """A single SAST pattern rule loaded from YAML.

    The rule uses a tree-sitter query to locate patterns in source code.
    When *capture_group* + *match_any* are specified, only captures whose
    text appears in *match_any* are reported.  When *match_any* is absent,
    every capture of *capture_group* is a hit.
    """

    id: str
    """Unique rule identifier, e.g. ``py-eval-exec``."""

    name: str
    """Human-readable name."""

    language: str
    """Target language: ``python``, ``java``, ``javascript``, ``typescript``."""

    severity: str = "medium"
    """Severity: ``critical``, ``high``, ``medium``, ``low``, ``info``."""

    cwe: list[int] = field(default_factory=list)
    """Relevant CWE identifiers."""

    message: str = ""
    """Description of why this pattern is dangerous."""

    query: str = ""
    """Tree-sitter query string."""

    capture_group: str = "match"
    """Which capture group to check for hits."""

    match_any: list[str] | None = None
    """Optional whitelist — only report when captured text is in this list."""


@dataclass
class MatchResult:
    """A single pattern match from the SAST engine."""

    rule_id: str
    rule_name: str
    severity: str
    language: str
    file_path: str
    line_number: int
    column: int = 0
    matched_text: str = ""
    message: str = ""
    cwe: list[int] = field(default_factory=list)


def confidence_from_severity(severity: str) -> str:
    """Map a match severity to a confidence boost level."""
    return {
        "critical": "high",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "low",
    }.get(severity, "medium")
