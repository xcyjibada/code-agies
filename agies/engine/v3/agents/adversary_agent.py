"""Adversary Agent — devil's advocate that tries to rebut findings.

Placed after Logic Agent, before PoC Agent.  Attempts to disprove the
finding.  If it finds a valid rebuttal → downgrade confidence.  If it
fails → greenlight for PoC generation.

This filters out fragile findings so only robust ones get PoCs.

Design note: vulnerability guidance is principle-level only (no specific
CVE numbers).  Hardcoding CVE IDs would leak answer context and make the
LLM pattern-match against known vulns rather than evaluate code independently.
"""

from __future__ import annotations

import json
import logging
import re

logger = logging.getLogger(__name__)

# Per-type guidance for the adversary — principle-level only, NO specific CVE
# numbers.  Injecting concrete CVE IDs would leak answer context and make the
# LLM pattern-match against known vulnerabilities rather than evaluate the code
# independently.
_VULN_GUIDANCE: dict[str, str] = {
    "LFI": (
        "Path traversal in path-builder functions (joinpath, os.path.join) is a "
        "real, exploitable vulnerability class — do NOT dismiss it simply because "
        "the sink is a 'utility function'. Multiple real-world CVEs involve "
        "path construction utilities used with untrusted input."
    ),
    "RCE": (
        "Unsafe deserialization (pickle, yaml, eval) and command execution "
        "(subprocess, os.system) in tooling and libraries are an active "
        "vulnerability class with multiple real-world CVEs."
    ),
    "SQLI": (
        "F-string/format-based SQL queries and dynamic filtering bypasses "
        "are recurring vulnerabilities in real-world CVEs."
    ),
    "SSRF": (
        "User-controlled URLs passed to HTTP clients (requests, httpx, urllib) "
        "are a well-established attack class with real-world CVEs."
    ),
    "AFO": (
        "Archive extraction (zipfile, tarfile) without output path validation "
        "is a real attack surface with multiple documented CVEs."
    ),
    "REDOS": (
        "User-supplied or attacker-controlled regex patterns with nested "
        "quantifiers are a real DoS vector documented in multiple CVEs."
    ),
    "IDOR": (
        "Direct object reference without ownership check is a well-known "
        "weakness class documented in many real-world CVEs."
    ),
    "SUSPICIOUS": (
        "Path-constructor functions (joinpath, PurePosixPath, posixpath.join) "
        "are frequently involved in real vulnerabilities — do NOT dismiss them "
        "as 'not a sink.' The actual vulnerability may be DoS/infinite loop, "
        "path traversal, logic error, or zip slip. Let the code analysis "
        "determine the actual vulnerability class rather than assuming one."
    ),
}

ADVERSARY_PROMPT = """You are a security reviewer evaluating a finding. Your job is to determine if the reported vulnerability is authentically exploitable — not to disprove at all costs.

{vuln_guidance}

Finding
-------
- Vulnerability Type: {vuln_type}
- Analysis: {analysis}
- Contradiction: {contradiction}

Source Code
```
{code_block}
```

Evaluate honestly. Consider:
1. **Input validation** — Is there sanitization that blocks the attack, or is it absent?
2. **Access control** — Can an attacker reach this code path, or is it gated behind auth?
3. **Data flow** — Does untrusted data actually reach the sink?
4. **Real-world context** — Even if the code IS vulnerable, is exploitation practical?

IMPORTANT: Do NOT dismiss a finding simply because "this is library utility code"
or "the sink is a path constructor." These patterns ARE used in real CVEs.

If the finding is genuinely not exploitable → rebut it with specific line-level evidence.
If the finding has merit (even with caveats) → do NOT rebut. The finding should survive.

Output:
```json
{{
  "rebutted": true/false,
  "confidence_downgrade": 0-10,
  "rebuttal": "If rebutted, explain exactly why the finding is wrong. Be specific, cite line numbers. If NOT rebutted, leave empty.",
  "weakness": "If NOT rebutted, what makes this finding hard to disprove? If rebutted, what was the deciding factor?"
}}
```
"""


def parse_adversary_response(response: str) -> dict:
    """Parse the JSON response from the adversary LLM call."""
    json_match = re.search(
        r"```(?:json)?\s*\n(.*?)\n```",
        response,
        re.DOTALL,
    )
    if json_match:
        raw = json_match.group(1)
    else:
        raw = response.strip()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        brace_match = re.search(r"\{.*\}", raw, re.DOTALL)
        if brace_match:
            try:
                data = json.loads(brace_match.group())
            except json.JSONDecodeError:
                return {"rebutted": False, "confidence_downgrade": 0}
        else:
            return {"rebutted": False, "confidence_downgrade": 0}

    if not isinstance(data, dict):
        return {"rebutted": False, "confidence_downgrade": 0}

    return data


class AdversaryAgent:
    """Try to rebut a Logic Agent finding before PoC generation."""

    def prepare_prompt(
        self,
        vuln_type: str,
        analysis: str,
        contradiction: str,
        code_block: str,
        rebuttal_history: str = "",
    ) -> str:
        """Build the adversarial review prompt with vulnerability guidance."""
        vuln_guidance = _VULN_GUIDANCE.get(vuln_type.upper(), "")
        return ADVERSARY_PROMPT.format(
            vuln_type=vuln_type.upper(),
            vuln_guidance=vuln_guidance,
            analysis=analysis or "(no analysis)",
            contradiction=contradiction or "(no contradiction)",
            code_block=code_block or "(code not loaded)",
            rebuttal_history=rebuttal_history,
        )

    def run(
        self,
        vuln_type: str,
        analysis: str,
        contradiction: str,
        code_block: str,
        llm_response: str | None = None,
        llm_call=None,
        rebuttal_history: str = "",
    ) -> dict:
        """Run adversarial review.

        Returns a dict with keys:
          - rebutted: bool
          - confidence_downgrade: 0-10
          - rebuttal: str (if rebutted)
          - weakness: str (if not rebutted)
        """
        if llm_response is not None:
            data = parse_adversary_response(llm_response)
        elif llm_call:
            prompt = self.prepare_prompt(
                vuln_type, analysis, contradiction, code_block, rebuttal_history,
            )
            response = llm_call(prompt)
            data = parse_adversary_response(response) if response else {}
        else:
            data = {}

        rebutted = data.get("rebutted", False)
        downgrade = data.get("confidence_downgrade", 0)

        if not isinstance(downgrade, int):
            try:
                downgrade = int(downgrade)
            except (ValueError, TypeError):
                downgrade = 0
        downgrade = max(0, min(10, downgrade))

        return {
            "rebutted": bool(rebutted),
            "confidence_downgrade": downgrade,
            "rebuttal": data.get("rebuttal", ""),
            "weakness": data.get("weakness", ""),
        }
