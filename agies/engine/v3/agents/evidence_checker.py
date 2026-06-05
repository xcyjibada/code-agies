"""EvidenceChecker — code-level evidence verification for Logic Agent findings.

Phase 1: Pattern-based scan (no LLM) — does the claimed dangerous operation
         actually exist in the source code?
Phase 2: If evidence found — LLM deep analysis with full code + blackboard
         context, writes PoC.
Phase 3: Record to blackboard.

Fits into pipeline after Logic Agent, before verification:
    Logic Agent → Evidence Checker → (optional) Verify → Blackboard
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from agies.engine.v3.aggregator.blackboard import BlackboardAggregator
from agies.engine.v3.aggregator.models import AgentPhaseResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Evidence patterns: per-vuln-type, checked against raw source code.
# The checker must find at least one match for the finding to be credible.
# ---------------------------------------------------------------------------

EVIDENCE_PATTERNS: dict[str, list[re.Pattern]] = {
    "lfi": [
        re.compile(r"\bopen\s*\(", re.IGNORECASE),
        re.compile(r"\.read\s*\(", re.IGNORECASE),
        re.compile(r"pathlib\.Path"),
        re.compile(r"PurePosixPath|PureWindowsPath"),
        re.compile(r"os\.path\.join|posixpath\.join|ntpath\.join"),
        re.compile(r"read_text|read_bytes"),
    ],
    "rce": [
        re.compile(r"\bexec\b", re.IGNORECASE),
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        re.compile(r"subprocess\.", re.IGNORECASE),
        re.compile(r"os\.system|os\.popen", re.IGNORECASE),
        re.compile(r"pickle\.loads|pickle\.load|cloudpickle", re.IGNORECASE),
        re.compile(r"yaml\.load(?!s)", re.IGNORECASE),
        re.compile(r"__import__"),
        re.compile(r"\bcompile\s*\(", re.IGNORECASE),
    ],
    "redos": [
        re.compile(r"re\.(match|search|sub|compile|findall|fullmatch|split)", re.IGNORECASE),
        re.compile(r"fnmatch\.(translate|filter)", re.IGNORECASE),
        re.compile(r"\bglob\b", re.IGNORECASE),
    ],
    "afo": [
        re.compile(r"\.write\s*\(", re.IGNORECASE),
        re.compile(r"shutil\.\w+", re.IGNORECASE),
        re.compile(r"os\.remove|os\.unlink|os\.rmdir", re.IGNORECASE),
        re.compile(r"extractall|extract\s*\(", re.IGNORECASE),
    ],
    "ssrf": [
        re.compile(r"urlopen|urlretrieve", re.IGNORECASE),
        re.compile(r"httpx\.", re.IGNORECASE),
        re.compile(r"aiohttp\.", re.IGNORECASE),
        re.compile(r"requests\.", re.IGNORECASE),
    ],
    "sqli": [
        re.compile(r"\bexecute\b", re.IGNORECASE),
        re.compile(r"executemany|executescript", re.IGNORECASE),
    ],
    "idor": [
        re.compile(r"\.get\s*\(", re.IGNORECASE),
        re.compile(r"\.filter\s*\(", re.IGNORECASE),
        re.compile(r"objects\.|queryset", re.IGNORECASE),
        re.compile(r"get_object_or_404", re.IGNORECASE),
    ],
}


@dataclass
class EvidenceMatch:
    """A single piece of code-level evidence."""
    pattern: str
    line_number: int | None
    line_content: str
    function_name: str | None = None


@dataclass
class EvidenceResult:
    """Result of evidence checking + analysis."""
    evidence_found: bool = False
    matches: list[EvidenceMatch] = field(default_factory=list)
    poc: str = ""
    analysis: str = ""


EVIDENCE_PROMPT = """You are verifying whether a claimed vulnerability has actual code-level evidence.

Logic Agent Claim
----
Vulnerability Type: {vuln_type}
Analysis: {analysis}
Claimed Contradiction: {contradiction_desc}
Suggested PoC: {poc_claim}

Code Context
----
{code_block}

{blackboard_context}

Your job: Trace the actual data flow in the code above and determine if the
claimed vulnerability can actually be exploited. Be skeptical — the Logic Agent
may have hallucinated a code path that doesn't exist.

If the vulnerability IS confirmed:
- Explain step-by-step how data flows from source to sink (cite exact lines)
- Write a working, concrete PoC
- Note any preconditions or limitations

If NOT confirmed:
- Explain exactly why (e.g., "function reads request body not filesystem",
  "regex pattern is linear, no backtracking possible")

Output:
```json
{{
  "confirmed": true/false,
  "confidence": 0-10,
  "evidence_lines": ["web_request.py:655: chunk = await self._payload.readany()", ...],
  "analysis": "Step-by-step data flow analysis...",
  "poc": "If confirmed, the concrete PoC. If not, empty string.",
  "why_rejected": "If not confirmed, explanation."
}}
```
"""


def scan_evidence(code_block: str, vuln_type: str) -> list[EvidenceMatch]:
    """Phase 1: pattern-based scan of source code.

    Returns all matches — empty list = no evidence.
    """
    patterns = EVIDENCE_PATTERNS.get(vuln_type.lower(), [])
    if not patterns:
        return []

    matches: list[EvidenceMatch] = []
    lines = code_block.split("\n")
    for lineno, line in enumerate(lines, 1):
        for pat in patterns:
            if pat.search(line):
                pat_str = pat.pattern[:60]
                matches.append(EvidenceMatch(
                    pattern=pat_str,
                    line_number=lineno,
                    line_content=line.strip()[:120],
                ))
    return matches


def build_blackboard_context(
    blackboard: BlackboardAggregator,
    nodes: list[dict[str, Any]],
) -> str:
    """Build a context block from blackboard cached intents for these path functions."""
    blocks: list[str] = []
    for node in nodes:
        func_name = node.get("function_name", "")
        file_path = node.get("file_path", "")
        if not func_name:
            continue
        intent = blackboard.get_intent(func_name, file_path)
        if intent and intent.intent:
            blocks.append(
                f"[{func_name}] intent: {intent.intent}\n"
                f"  inputs: {intent.inputs}\n"
                f"  outputs: {intent.outputs}\n"
                f"  key_logic: {intent.key_logic}"
            )
    if not blocks:
        return ""
    return "[Blackboard Intent Context]\n" + "\n\n".join(blocks)


class EvidenceChecker:
    """Code-level evidence verification + deep analysis.

    Usage::

        checker = EvidenceChecker(llm_call_fn=llm_call, blackboard=bb)
        result = checker.run(logic_result, code_block, nodes)
        if result.evidence_found:
            # confirmed with PoC
    """

    def __init__(
        self,
        llm_call_fn: Callable[[str], str | None] | None = None,
        blackboard: BlackboardAggregator | None = None,
    ) -> None:
        self._llm_call = llm_call_fn
        self._blackboard = blackboard

    def run(
        self,
        logic_result: AgentPhaseResult,
        code_block: str,
        nodes: list[dict[str, Any]],
    ) -> EvidenceResult:
        """Run evidence checking on a Logic Agent finding.

        Phase 1: pattern scan (no LLM cost).
        Phase 2: LLM deep analysis + PoC (only if Phase 1 finds evidence).
        Phase 3: record to blackboard.
        """
        # Phase 1: Pattern scan
        matches = scan_evidence(code_block, logic_result.vuln_type)
        if not matches:
            logger.info(
                "EvidenceChecker: no code-level evidence for %s (%s)",
                logic_result.path_id, logic_result.vuln_type,
            )
            return EvidenceResult(evidence_found=False)

        logger.info(
            "EvidenceChecker: %d evidence matches for %s",
            len(matches), logic_result.path_id,
        )

        if not self._llm_call:
            return EvidenceResult(evidence_found=True, matches=matches)

        # Phase 2: LLM deep analysis with code + blackboard context
        contradiction_desc = ""
        poc_claim = ""
        if logic_result.contradictions:
            c = logic_result.contradictions[0]
            contradiction_desc = c.get("contradiction_type", "") + ": " + c.get("actual", "")
            poc_claim = c.get("bypass_poc", "")

        bb_context = ""
        if self._blackboard and nodes:
            bb_context = build_blackboard_context(self._blackboard, nodes)

        prompt = EVIDENCE_PROMPT.format(
            vuln_type=logic_result.vuln_type.upper(),
            analysis=logic_result.analysis or "(no analysis)",
            contradiction_desc=contradiction_desc,
            poc_claim=poc_claim,
            code_block=code_block or "(code not loaded)",
            blackboard_context=bb_context or "(no prior context)",
        )

        response = self._llm_call(prompt)

        evidence_result = EvidenceResult(evidence_found=True, matches=matches)

        if response:
            import json
            try:
                data = json.loads(response)
            except json.JSONDecodeError:
                # Try to extract JSON from code fence
                m = re.search(r"```(?:json)?\s*\n(.*?)\n```", response, re.DOTALL)
                if m:
                    try:
                        data = json.loads(m.group(1))
                    except json.JSONDecodeError:
                        data = {"confirmed": False, "analysis": "Failed to parse response"}
                else:
                    data = {"confirmed": True, "analysis": response[:500]}

            if data.get("confirmed", False):
                evidence_result.poc = data.get("poc", "")
                evidence_result.analysis = data.get("analysis", "")
            else:
                evidence_result.evidence_found = False
                evidence_result.analysis = data.get("why_rejected", data.get("analysis", ""))

        # Phase 3: Record to blackboard
        if self._blackboard:
            status = "confirmed" if evidence_result.evidence_found else "rejected"
            self._blackboard.record_knowledge(
                f"evidence:{logic_result.path_id}",
                f"[{status}] {evidence_result.analysis[:200]}"
                + (f"\nPoC: {evidence_result.poc[:300]}" if evidence_result.poc else ""),
                source_path_id=logic_result.path_id,
            )

        return evidence_result
