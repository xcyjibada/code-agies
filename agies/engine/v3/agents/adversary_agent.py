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

from agies.engine.v3.agents.structured_evidence import extract_structured_evidence

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
{structured_evidence}

Source Code (with data flow annotations)
```
{code_block}
```

The ``[DATA FLOW]`` section in the source marks which entry parameters are UNTRUSTED (attacker-controlled) and traces propagation through the call chain. The ``[INTENT EVIDENCE]`` section shows each function's purpose, data flow (inputs/outputs), and suspicious observations from per-function analysis.

**Confidence guidance (read carefully)**:
The annotations above are HELPFUL HINTS, not ground truth. Static data flow analysis is ~60-70% accurate for Python — *args/**kwargs, dynamic dispatch, and callbacks all cause missed or incorrect traces. The ``[STRUCTURED EVIDENCE]`` section above (when present) is the Logic Agent's best-effort analysis, which may also be incomplete. Use all of this as a starting point, but ALWAYS verify against the actual source code. If you find evidence that the data flow differs from what the annotations claim, trust your own analysis and explain the discrepancy.

Evaluate honestly. Consider:
1. **Input validation** — Is there sanitization that blocks the attack, or is it absent?
2. **Access control** — Can an attacker reach this code path, or is it gated behind auth?
3. **Data flow** — Does untrusted data actually reach the sink? (Use the annotations as a starting point, but verify against the source code.)
4. **Real-world context** — Even if the code IS vulnerable, is exploitation practical?

**⚠ RED-FLAG RULES — Read these before evaluating (op.md Item ③):**
- If the source code header contains ``[REACHABILITY: BODY_ONLY]`` or ``[REACHABILITY: EXTERNAL_API]``: the path was detected by *body presence* of a dangerous API, not by a project-internal call chain. You must be **extremely skeptical**. Unless you can derive a realistic execution scenario (e.g. the function is a library public API called from external code with attacker-controlled input), **rebut the finding**.
- Check the ``taint_path`` in ``[STRUCTURED EVIDENCE]`` for **logical jumps**: are there steps where data passes from one variable to another without explanation? If the trace is incomplete or relies on unstated assumptions, **rebut**.

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

    @staticmethod
    def _format_structured_evidence(analysis: str) -> str:
        """Extract and format ``[STRUCTURED_EVIDENCE]`` for prompt injection.

        Returns a formatted section with taint_path, reasoning_steps,
        exploitability_verdict, and guards_detected.  Returns an empty string
        when no structured evidence is available in the analysis text.
        """
        ev = extract_structured_evidence(analysis)
        if not ev:
            return ""

        lines: list[str] = []

        tp = ev.get("taint_path", [])
        if tp and isinstance(tp, list):
            lines.append("\n[STRUCTURED EVIDENCE — Data Flow Trace]")
            for step in tp:
                lines.append(
                    f"  [{step.get('action', '?')}] {step.get('function', '?')} "
                    f"→ param: {step.get('param', '?')}"
                )

        rs = ev.get("reasoning_steps", [])
        if rs and isinstance(rs, list):
            lines.append("\n[STRUCTURED EVIDENCE — Logic Agent Reasoning]")
            for i, s in enumerate(rs, 1):
                lines.append(f"  {i}. {s}")

        verdict = ev.get("exploitability_verdict", "")
        if verdict:
            lines.append(f"\n[STRUCTURED EVIDENCE — Verdict] {verdict}")

        gd = ev.get("guards_detected", [])
        if gd and isinstance(gd, list):
            lines.append("\n[STRUCTURED EVIDENCE — Guards Detected]")
            for g in gd:
                lines.append(f"  - {g}")

        return "\n".join(lines)

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
        structured_section = self._format_structured_evidence(analysis)
        return ADVERSARY_PROMPT.format(
            vuln_type=vuln_type.upper(),
            vuln_guidance=vuln_guidance,
            analysis=analysis or "(no analysis)",
            contradiction=contradiction or "(no contradiction)",
            code_block=code_block or "(code not loaded)",
            rebuttal_history=rebuttal_history,
            structured_evidence=structured_section,
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
