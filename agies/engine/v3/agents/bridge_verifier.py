"""BridgeVerifier — deep analysis of attribute taint bridge paths.

Runs after Logic Agent for paths with ``[attr bridge]`` annotations.
Where the Logic Agent judges individual sink calls, the BridgeVerifier
evaluates the *composition*: does storing untrusted data in ``self.ATTR``
create an exploitable path when another function reads that attribute
and passes it to a dangerous API?

Phase 1: Parse bridge annotation from path nodes → extract storer/reader/attr.
Phase 2: Pattern scan — does the reader's attribute flow reach a real sink?
Phase 3: LLM deep analysis — trace the full taint chain, write PoC if real.
Phase 4: Record to blackboard.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from agies.engine.v3.aggregator.models import AgentPhaseResult

logger = logging.getLogger(__name__)

# Pattern to parse [attr bridge: ...] annotations
_BRIDGE_ANNOTATION_RE = re.compile(
    r"\[attr bridge:\s*self\.(\w+)\s+stored by\s+(\w+)\s*→\s*read by\s+(\w+)\]"
)

# Dangerous patterns in reader functions — check if self.ATTR reaches these
_BRIDGE_SINK_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Path traversal via PurePosixPath / PureWindowsPath
    (re.compile(r"PurePosixPath|PureWindowsPath"), "path_traversal", "path manipulation"),
    # Path join with stored attr → filesystem escape
    (re.compile(r"posixpath\.join|ntpath\.join|os\.path\.join"), "path_traversal", "path join"),
    # File I/O where self.ATTR is used
    (re.compile(r"\bopen\s*\("), "lfi", "file open"),
    (re.compile(r"\.read\s*\("), "lfi", "file read"),
    (re.compile(r"Path\(.*\)\.joinpath"), "path_traversal", "pathlib joinpath"),
    # ZipFile operations with tainted name
    (re.compile(r"self\.root\.(open|extract)"), "zip_entry_traversal", "zipfile operation"),
    # Path resolution
    (re.compile(r"pathlib\.Path\b"), "path_traversal", "pathlib Path"),
    (re.compile(r"\.resolve\s*\("), "path_traversal", "path resolve"),
]

# Patterns in STORER functions that indicate external/untrusted data source
_STORER_SOURCE_PATTERNS: list[re.Pattern] = [
    re.compile(r"namelist|iterdir|glob|rglob", re.IGNORECASE),
    re.compile(r"user\s*input|request|query|param", re.IGNORECASE),
    re.compile(r"\.get\s*\(|\.post\s*\(|\.put\s*\(|\.delete\s*\(", re.IGNORECASE),
    re.compile(r"input\s*\(|sys\.argv|os\.environ", re.IGNORECASE),
    re.compile(r"open\s*\(|read\s*\(", re.IGNORECASE),
]

# Path-bridge patterns: scanner for builder + consumer composition analysis.
# Builder patterns: constructs or manipulates a POSIX/Windows path.
_PATH_BUILDER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"PurePosixPath|PureWindowsPath"), "PurePath construction"),
    (re.compile(r"posixpath\.join|ntpath\.join|os\.path\.join"), "path join"),
    (re.compile(r"Path\(.*\)\.joinpath"), "pathlib joinpath"),
    (re.compile(r"pathlib\.Path\b"), "pathlib Path"),
    (re.compile(r"\.resolve\s*\("), "path resolution"),
    (re.compile(r"\.parent\b"), "path parent"),
]

# Consumer patterns: file I/O or regex operations that consume a path / pattern.
_PATH_CONSUMER_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\bopen\s*\("), "lfi", "file open"),
    (re.compile(r"\.read_text\s*\("), "lfi", "read_text"),
    (re.compile(r"\.read_bytes\s*\("), "lfi", "read_bytes"),
    (re.compile(r"\.write_text\s*\("), "lfi", "write_text"),
    (re.compile(r"\.write_bytes\s*\("), "lfi", "write_bytes"),
    (re.compile(r"\.extractall?\s*\("), "zip_entry_traversal", "zipfile extract"),
    (re.compile(r"self\.root\.(open|extract)"), "zip_entry_traversal", "zipfile root operation"),
    (re.compile(r"zopen|ZipFile"), "zip_entry_traversal", "zipfile open"),
    (re.compile(r"re\.compile|re\.search|re\.match|re\.fullmatch|re\.sub|re\.findall"), "redos", "regex operation"),
]


def scan_path_bridge_evidence(code_block: str) -> dict:
    """Scan code block for path-bridge composition patterns.

    Looks for both path-builder calls (posixpath.join, PurePosixPath, etc.)
    AND path-consumer calls (open, read_text, extract, regex ops) in the
    same code region.  When both exist, the library may have a composition
    vulnerability where a consumer uses an unsanitized path built earlier.

    Returns a dict:
      ``path_bridge_found`` -- True when both builder and consumer patterns match
      ``builder_patterns``  -- list of (desc, pattern) tuples matched
      ``consumer_patterns`` -- list of (desc, sink_type, pattern) tuples matched
      ``sink_type``         -- first consumer's sink type (or "unknown")
    """
    result: dict = {
        "path_bridge_found": False,
        "builder_patterns": [],
        "consumer_patterns": [],
        "sink_type": "unknown",
    }

    for pat, desc in _PATH_BUILDER_PATTERNS:
        if pat.search(code_block):
            result["builder_patterns"].append((desc, pat.pattern[:40]))

    for pat, sink_type, desc in _PATH_CONSUMER_PATTERNS:
        if pat.search(code_block):
            result["consumer_patterns"].append((desc, sink_type, pat.pattern[:40]))
            if result["sink_type"] == "unknown":
                result["sink_type"] = sink_type

    if result["builder_patterns"] and result["consumer_patterns"]:
        result["path_bridge_found"] = True

    return result


BRIDGE_VERIFIER_PROMPT = """You are analyzing an attribute taint bridge for a security vulnerability.

The static analysis pipeline detected that function `{storer}` stores a
parameter into `self.{attr}`, and function `{reader}` reads `self.{attr}`
and passes it to a potentially dangerous API call.

Call Chain Context
----
{backtrack_chain}

Source Code — {storer} (stores value into self.{attr})
----
```python
{storer_code}
```

Source Code — {reader} (reads self.{attr} and calls sink)
----
```python
{reader_code}
```

Full Path Nodes:
----
{path_nodes}

Analysis Task:
1. Does `{storer}` receive its parameter from untrusted/external data?
   (Look at the call chain — is the data coming from user input, file iteration, etc.?)
2. Does `{reader}` actually use `self.{attr}` in a filesystem operation,
   path traversal, or other dangerous context?
3. Can `self.{attr}` contain path traversal sequences like `../` that would
   escape the intended directory/zip scope?
4. Is there any validation or sanitization between the store and the read?

Be SPECIFIC. Cite exact function names and line behavior.

Output JSON:
```json
{{
  "confirmed": true/false,
  "vuln_type": "path_traversal|rce|lfi|...",
  "confidence": 1-10,
  "analysis": "Step-by-step flow analysis. Cite exact function behavior.",
  "poc": "If confirmed: concrete steps, payload, and expected behavior."
}}
```
"""


@dataclass
class BridgeAnnotation:
    """Parsed ``[attr bridge: ...]`` annotation."""
    attr: str
    storer: str
    reader: str
    raw_text: str = ""

    @classmethod
    def parse(cls, text: str) -> BridgeAnnotation | None:
        m = _BRIDGE_ANNOTATION_RE.search(text)
        if m:
            return cls(attr=m.group(1), storer=m.group(2), reader=m.group(3), raw_text=text)
        return None


def scan_bridge_evidence(storer_code: str, reader_code: str) -> dict[str, Any]:
    """Pattern scan for bridge-level evidence.

    Returns a dict with evidence findings (no LLM cost).
    """
    result: dict[str, Any] = {
        "storer_external_source": False,
        "reader_dangerous_sink": False,
        "sink_type": "unknown",
        "patterns_matched": [],
    }

    # Check storer: does it receive data from external sources?
    for pat in _STORER_SOURCE_PATTERNS:
        if pat.search(storer_code):
            result["storer_external_source"] = True
            result.setdefault("patterns_matched", []).append(
                f"storer_source:{pat.pattern[:30]}"
            )
            break

    # Check reader: does it pass self.ATTR to dangerous APIs?
    for pat, sink_type, desc in _BRIDGE_SINK_PATTERNS:
        if pat.search(reader_code):
            result["reader_dangerous_sink"] = True
            result["sink_type"] = sink_type
            result.setdefault("patterns_matched", []).append(
                f"reader_sink:{desc} ({pat.pattern[:30]})"
            )

    return result


class BridgeVerifier:
    """Deep analysis of attribute taint bridge paths.

    Usage::

        verifier = BridgeVerifier(llm_call_fn)
        result = verifier.verify(path_nodes, storer_code, reader_code, bridge)
        if result.confirmed:
            print(result.poc)
    """

    def __init__(
        self,
        llm_call_fn: Callable[[str], str | None] | None = None,
    ) -> None:
        self._llm_call = llm_call_fn

    def verify(
        self,
        logic_result: AgentPhaseResult | None,
        path_nodes: list[dict[str, Any]],
        storer_code: str,
        reader_code: str,
        bridge: BridgeAnnotation,
        backtrack_chain: str = "",
    ) -> AgentPhaseResult:
        """Run bridge verification.

        Phase 1: Pattern scan (free).
        Phase 2: LLM deep analysis (only if patterns match).
        Phase 3: Return updated result.

        Returns an ``AgentPhaseResult`` — if confirmed, ``is_vulnerable=True``
        and ``analysis`` contains the full explanation.
        """
        # Phase 1: pattern scan
        evidence = scan_bridge_evidence(storer_code, reader_code)

        if not evidence["reader_dangerous_sink"] and not evidence["storer_external_source"]:
            logger.info(
                "BridgeVerifier: no pattern evidence for %s→%s (self.%s)",
                bridge.storer, bridge.reader, bridge.attr,
            )
            return AgentPhaseResult(
                path_id=logic_result.path_id if logic_result else "bridge-unknown",
                vuln_type=logic_result.vuln_type if logic_result else "unknown",
                score=logic_result.score if logic_result else 0.3,
                contradictions=[],
                confidence=2,
                analysis="BridgeVerifier: no pattern-level evidence found.",
                is_vulnerable=False,
            )

        logger.info(
            "BridgeVerifier: pattern evidence found (%s) for %s→%s",
            evidence["sink_type"], bridge.storer, bridge.reader,
        )

        if not self._llm_call:
            return AgentPhaseResult(
                path_id=logic_result.path_id if logic_result else "bridge-unknown",
                vuln_type=logic_result.vuln_type if logic_result else evidence["sink_type"],
                score=logic_result.score if logic_result else 0.5,
                contradictions=[{
                    "bridge_verifier": "Pattern evidence found",
                    "sink_type": evidence["sink_type"],
                    "patterns": evidence["patterns_matched"],
                }],
                confidence=5,
                analysis="BridgeVerifier: pattern evidence, LLM unavailable for full analysis.",
                is_vulnerable=True,
            )

        # Phase 2: LLM deep analysis
        path_nodes_text = "\n".join(
            f"  [{i}] {n.get('function_name', '?')} ({n.get('file_path', '?')}:{n.get('line_number', '?')})"
            for i, n in enumerate(path_nodes[:10])
        )

        prompt = BRIDGE_VERIFIER_PROMPT.format(
            storer=bridge.storer,
            reader=bridge.reader,
            attr=bridge.attr,
            backtrack_chain=backtrack_chain or "(no chain)",
            storer_code=storer_code or "(code not loaded)",
            reader_code=reader_code or "(code not loaded)",
            path_nodes=path_nodes_text,
        )

        response = self._llm_call(prompt)

        if not response:
            return AgentPhaseResult(
                path_id=logic_result.path_id if logic_result else "bridge-unknown",
                vuln_type=logic_result.vuln_type if logic_result else evidence["sink_type"],
                score=logic_result.score if logic_result else 0.5,
                contradictions=[{
                    "bridge_verifier": "Pattern evidence, LLM call failed",
                    "sink_type": evidence["sink_type"],
                }],
                confidence=4,
                analysis="BridgeVerifier: LLM unavailable, pattern evidence only.",
                is_vulnerable=True,
            )

        # Parse JSON from response
        import json
        data = {}
        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            m = re.search(r"```(?:json)?\s*\n(.*?)\n```", response, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group(1))
                except json.JSONDecodeError:
                    data = {"confirmed": False, "analysis": "Failed to parse LLM response"}

        confirmed = data.get("confirmed", False)
        vuln_type = data.get("vuln_type", evidence["sink_type"])
        confidence = data.get("confidence", 6) if confirmed else 2
        analysis = data.get("analysis", response[:500])
        poc = data.get("poc", "")

        contradictions = []
        if confirmed:
            contradictions.append({
                "bridge_verifier": "confirmed",
                "storer": bridge.storer,
                "reader": bridge.reader,
                "attr": bridge.attr,
                "sink_type": vuln_type,
                "poc": poc[:200] if poc else "",
            })

        return AgentPhaseResult(
            path_id=logic_result.path_id if logic_result else "bridge-unknown",
            vuln_type=vuln_type,
            score=logic_result.score if logic_result else 0.6,
            contradictions=contradictions,
            confidence=confidence,
            analysis=analysis,
            is_vulnerable=confirmed,
        )
