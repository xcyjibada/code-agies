"""Data models for Phase D+E — Intent caching and blackboard aggregation."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any


def compute_body_hash(code: str) -> str:
    """Normalize function body and compute MD5 hash for cache key.

    Strips comments and whitespace, then hashes the first 200 characters.
    Using the first 200 chars keeps cache and lookup hashes consistent
    (both operate on the same prefix).
    """
    raw = code[:200]
    normalized = re.sub(r'#.*$', '', raw, flags=re.MULTILINE)
    normalized = re.sub(r'\s+', '', normalized)
    return hashlib.md5(normalized.encode()).hexdigest()


@dataclass
class IntentResult:
    """Result of an Intent Agent analysis for a single function.

    This is the key unit cached in the blackboard — when the same function
    appears in multiple paths, the Intent result is computed once and reused.
    """

    func_name: str
    file_path: str

    # Human-readable analysis
    intent: str = ""
    """'这个函数在做什么？' — one-sentence description."""

    inputs: str = ""
    """What data does this function receive and from whom?"""

    outputs: str = ""
    """What does it return and to whom?"""

    key_logic: str = ""
    """Core logic — replace/regex/if-check/permission check/data transform."""

    suspicious: list[str] = field(default_factory=list)
    """Anything that looks odd (no conclusions, just observations)."""

    security_contract: str = ""
    """Security contract: what security property does this function claim
    to enforce?  E.g. 'Validates that the path does not escape BASE_DIR'
    or 'Ensures only admin users can access this resource.'

    This is the ``specification`` half of spec-falsification analysis.
    The Logic Agent compares the contract against the actual implementation
    to find violations (falsifications).

    Empty string means no security contract was extracted (normal for
    pure helper functions).
    """

    confidence: float = 1.0
    """How confident the Intent Agent is in this analysis (0-1)."""

    pass_through: bool = False
    """If True, emit raw source code instead of pseudo-code in merged chain.

    Set by Intent Agent when the function has dangerous/suspicious operations
    that need precise source-level analysis by Logic Agent, not just pseudo-code.
    """

    code: str = ""
    """Original source code (set when pass_through=True, for merge layer use)."""

    fn_body_hash: str = ""
    """MD5 hash of the normalized function body.

    Used as the primary cache key in BlackboardAggregator so the same
    function always produces the same cache key regardless of the
    absolute/relative path used to reach it.
    """


@dataclass
class KnowledgeEntry:
    """A piece of discovered logic recorded during agent analysis.

    Maps to v2's ``state.discovered_logic[key] = value`` but is
    collected in parallel from all agents.
    """

    key: str
    """Knowledge key — typically ``function_name`` or ``"file.py::func"``."""

    value: str
    """Knowledge value — human-readable observation."""

    source_path_id: str = ""
    """Which path slice this knowledge came from."""


@dataclass
class AgentPhaseResult:
    """Aggregated result from all agents in Phase D.

    Collected after Intent Agent pool + Logic Agent pool complete,
    then fed to Phase E (blackboard aggregation) and Phase F (verification).
    """

    path_id: str
    vuln_type: str
    score: float

    contradictions: list[dict[str, Any]] = field(default_factory=list)
    """Contradictions found by the Logic Agent."""

    confidence: int = 0
    """0-10 confidence score from Logic Agent."""

    analysis: str = ""
    """Free-text analysis from Logic Agent."""

    is_vulnerable: bool = False
    """Whether this path is flagged as potentially vulnerable."""

    actual_vuln_type: str = ""
    """Vulnerability type reclassified by Logic Agent (overrides static sink
    classification). Empty string means the original sink type stands."""

    poc_path: str = ""
    """Path to generated PoC script (empty if not generated)."""

    rebutted: bool = False
    """Whether the Adversary Agent successfully rebutted this finding."""

    rebuttal: str = ""
    """Why the Adversary Agent rebutted this (if rebutted)."""


@dataclass
class CachedIntent:
    """Persistent cache entry for a function intent analysis.

    Stored in the BlackboardAggregator and reused across paths.
    """

    result: IntentResult
    hit_count: int = 0
    """Number of times this cached result was reused (for metrics)."""
