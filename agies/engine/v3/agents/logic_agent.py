"""Logic Agent — Phase D Step 4.

Reads pseudocode call chain (from merge layer) and finds contradictions between
"developer intent" and actual implementation.

Uses the VulnHuntr-style prompts from ``v3/prompts/`` for vulnerability-specific
analysis checklists and bypass techniques.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from agies.engine.v3.aggregator.models import AgentPhaseResult
from agies.engine.v3.agents.structured_evidence import (
    format_structured_evidence_block,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_logic_response(response: str) -> list[dict[str, Any]]:
    """Extract contradictions JSON from the LLM response.

    Handles code-fenced JSON, bare JSON, and partial failures.
    """
    # Try to find ```json ... ``` block
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
        # Try to extract just the JSON object
        brace_match = re.search(r"\{.*\}", raw, re.DOTALL)
        if brace_match:
            try:
                data = json.loads(brace_match.group())
            except json.JSONDecodeError:
                return []
        else:
            return []

    if not isinstance(data, dict):
        return {}

    # Handle VulnHuntr-style output (vulnerable + bypass_poc)
    contradictions = data.get("contradictions")
    if contradictions is None:
        # Convert vulnerable/bypass_poc to a contradictions entry
        is_vuln = data.get("vulnerable", False)
        if is_vuln:
            data["contradictions"] = [{
                "func": data.get("sink_function", "?"),
                "claimed": "developer intent",
                "actual": data.get("analysis", ""),
                "contradiction_type": "logic_gap",
                "bypass_poc": data.get("bypass_poc", ""),
                "exploit_potential": data.get("analysis", ""),
            }]
        else:
            data["contradictions"] = []

        # Map vulnerable/confidence
        if "vulnerable" in data and "confidence" not in data:
            data["confidence"] = 8 if data["vulnerable"] else 0

    if not isinstance(data.get("contradictions"), list):
        data["contradictions"] = []

    return data


VERIFY_PROMPT_TEMPLATE = """You are verifying a claimed vulnerability. Focus on **technical feasibility**: can the described exploit be executed?

Claimed Finding
----
- Vulnerability Type: {vuln_type}
- Analysis: {analysis}
- Exploit POC: {bypass_poc}

Source Code
```
{code_block}
```
{call_context}
Checklist:
- [ ] Is the POC technically correct? (would the described input reach the described sink?)
- [ ] Are there any guards, validation, or sanitization that block the POC?
- [ ] Is the function missing validation that SHOULD be there (path traversal protection, input sanitization)?
- [ ] Is the described bypass practical or is there a logical gap?

Your verdict:
```json
{{
  "confirmed": true/false,
  "confidence": 0-10,
  "exploit_steps": "If confirmed, describe step-by-step how to trigger the exploit",
  "blockers": "If not confirmed, explain exactly what prevents exploitation"
}}
```
"""


# ---------------------------------------------------------------------------
# Logic Agent
# ---------------------------------------------------------------------------


class LogicAgent:
    """Finds contradictions in a pseudo-code call chain.

    One LogicAgent per path slice — analyzes the merged intent chain
    for a single source→sink path.
    """

    def __init__(self, llm_call_fn=None) -> None:
        self._llm_call = llm_call_fn

    def prepare_prompt(
        self,
        path_id: str,
        intent_chain: str = "",
        vuln_type: str = "",
        readme_summary: str = "",
        code_block: str = "",
        project_type: str = "app",
        blackboard_knowledge: str = "",
    ) -> str:
        """Build the logic analysis prompt using VulnHuntr-style prompts.

        Frames the analysis as contradiction detection: prepends the developer
        intent pseudocode so the LLM compares "what the developer intended"
        against "what the code actually does".  Without this frame the prompt
        is just a traditional single-shot vulnerability scan, which suffers
        from library bias and non-determinism.

        Parameters
        ----------
        blackboard_knowledge : str
            Prior knowledge from other analyzed paths that reference the same
            functions.  Injected after the intent chain so the LLM has cross-path
            context before reading the base prompt.
        """
        from agies.engine.v3.prompts import get_prompt

        base_prompt = get_prompt(
            vuln_type,
            code_block=code_block or intent_chain,
            readme_summary=readme_summary,
        )

        if not intent_chain.strip():
            return base_prompt

        # ── Blackboard cross-path knowledge ──
        if blackboard_knowledge and blackboard_knowledge.strip():
            bb_section = (
                "\n\n"
                "[PRIOR KNOWLEDGE FROM OTHER PATHS]\n"
                "The following observations were recorded by earlier analysis paths "
                "that share functions with this call chain. These are supplementary "
                "signals — use them as additional evidence, not ground truth.\n"
                f"{blackboard_knowledge.strip()}\n"
                "[/PRIOR KNOWLEDGE]\n"
            )
        else:
            bb_section = ""

        # Library-mode bias injection — force LLM out of "library code is safe" mode.
        # Only activate for lib projects; app projects get a neutral prompt.
        if project_type == "lib":
            lib_mission = (
                "CRITICAL MISSION: You are auditing a LIBRARY for security vulnerabilities.\n"
                "Library CVEs are real and high-impact — they affect ALL downstream consumers.\n"
                "Do NOT dismiss code as 'safe library utility code'. Instead, examine:\n"
                "1) What happens when external/untrusted input reaches this function?\n"
                "2) Is there a path-builder (joinpath, __truediv__) that could construct malicious paths?\n"
                "3) Are there missing validation steps that a caller could bypass?\n"
                "4) Does this function have side effects that could be abused?\n"
                "REMEMBER: Saying 'this library code, not vulnerable' is NOT an option.\n\n"
            )
        else:
            lib_mission = ""

        # ── Dual-brain CoT reasoning (op.md Item ④) ──
        dual_brain_cot = (
            "\n\n"
            "Your reasoning_steps output MUST follow a three-perspective structure:\n"
            '\n'
            '1. "[DEVELOPER_SPEC]" — What security contract did the developer intend?\n'
            '   What defenses are ostensibly in place and what were they supposed to do?\n'
            '\n'
            '2. "[HACKER_REALITY]" — Looking at the actual code (not the pseudocode),\n'
            '   what does it *really* do? Is there a gap between the intent and the\n'
            '   mathematical/data-flow logic? Focus on what the runtime will actually\n'
            '   execute, not what the developer meant.\n'
            '\n'
            '3. "[CONTRADICTION]" — What specific, fatal contradiction exists between\n'
            '   the developer spec and the hacker reality? This is the vulnerability.\n'
            '   If none exists, state "no contradiction found".\n'
            '\n'
            "This forced perspective-splitting prevents you from deferring to "
            "developer comments or function names — you must read the actual source."
        )

        # ── Structured Evidence output instructions ──
        # These are appended after the base prompt so the LLM knows to
        # include machine-readable data flow evidence alongside its
        # free-text analysis.  Downstream agents (Adversary, PoC) parse
        # these fields programmatically.
        structured_ev_instructions = (
            "\n\n"
            "IMPORTANT — Your JSON output MUST include ALL of these additional fields:\n"
            '\n'
            '1. "taint_path": Array of objects tracing how untrusted/attacker-controlled\n'
            '   data flows from the entry function through each intermediate function\n'
            '   to the sink. Each object has:\n'
            '     - "function": function name at this step\n'
            '     - "param": the parameter/variable that carries tainted data\n'
            '     - "action": "entry" | "propagate" | "sink"\n'
            '\n'
            '2. "reasoning_steps": Array of strings — your step-by-step reasoning.\n'
            f'{dual_brain_cot.strip()}\n'
            '\n'
            '3. "exploitability_verdict": One of:\n'
            '     - "EXPLOITABLE" — untrusted data reaches the sink with no effective guard\n'
            '     - "NOT_EXPLOITABLE" — a guard or sanitization definitively blocks it\n'
            '     - "UNCERTAIN" — cannot determine conclusively\n'
            '\n'
            '4. "guards_detected": Array of strings describing any security controls,\n'
            '   sanitization, or validation between the entry and sink. Empty array if none.\n'
            '\n'
            'Example taint_path:\n'
            '[\n'
            '  {"function": "add_texts", "param": "texts", "action": "entry"},\n'
            '  {"function": "add_embeddings", "param": "texts", "action": "propagate"},\n'
            '  {"function": "_embed", "param": "text", "action": "propagate"},\n'
            '  {"function": "pickle.loads", "param": "text.encoded", "action": "sink"}\n'
            ']\n'
            '\n'
            "These fields are critical — they enable downstream agents "
            "(adversary reviewer, PoC generator) to accurately understand "
            "your analysis without re-reading the source code."
        )

        return (
            "Developer Intent (pseudocode)\n"
            "---\n"
            f"{intent_chain}\n\n"
            "Your task: Find contradictions between the developer intent above "
            "and the actual source code below. Does the implementation "
            "introduce security risks that the intent summary doesn't mention?\n"
            f"{bb_section}"
            f"{lib_mission}"
            f"{base_prompt}"
            f"{structured_ev_instructions}"
        )

    def run(
        self,
        path_id: str,
        score: float,
        vuln_type: str,
        intent_chain: str,
        readme_summary: str = "",
        bypasses: str = "",
        llm_response: str | None = None,
    ) -> AgentPhaseResult:
        """Run the Logic Agent on a single path.

        Returns an ``AgentPhaseResult`` with contradictions (if any).
        """
        if llm_response is not None:
            data = parse_logic_response(llm_response)
        elif self._llm_call:
            prompt = self.prepare_prompt(
                path_id, intent_chain, vuln_type=vuln_type, readme_summary=readme_summary,
            )
            response = self._llm_call(prompt)
            data = parse_logic_response(response)
        else:
            data = {}

        contradictions = data.get("contradictions", []) if isinstance(data, dict) else []
        confidence = data.get("confidence", 0) if isinstance(data, dict) else 0
        analysis = data.get("analysis", "") if isinstance(data, dict) else ""

        # ── Build [STRUCTURED_EVIDENCE] block from LLM fields ──
        # Appended to the analysis string so downstream agents (Adversary,
        # PoC) can extract it programmatically.  The analysis field remains
        # backward-compatible: consumers that don't understand the embedded
        # JSON block simply ignore it as part of the markdown text.
        if isinstance(data, dict):
            taint_path = data.get("taint_path", [])
            reasoning_steps = data.get("reasoning_steps", [])
            exploitability_verdict = data.get("exploitability_verdict", "")
            guards_detected = data.get("guards_detected", [])

            evidence_block = format_structured_evidence_block(
                taint_path=taint_path if isinstance(taint_path, list) else None,
                reasoning_steps=reasoning_steps if isinstance(reasoning_steps, list) else None,
                exploitability_verdict=str(exploitability_verdict) if exploitability_verdict else "",
                guards_detected=guards_detected if isinstance(guards_detected, list) else None,
            )
            if evidence_block:
                analysis = (analysis + "\n\n" + evidence_block) if analysis else evidence_block

        llm_vuln_type = data.get("vuln_type", "") if isinstance(data, dict) else ""

        if not isinstance(confidence, int):
            try:
                confidence = int(confidence)
            except (ValueError, TypeError):
                confidence = 0
        confidence = max(0, min(10, confidence))

        # Use the LLM's reclassified vuln_type as actual_vuln_type,
        # but only when it differs from the original sink type
        # (the vulnhuntr prompts and SUSPICIOUS prompt both output vuln_type).
        actual_vuln_type = llm_vuln_type if llm_vuln_type and llm_vuln_type != vuln_type else ""

        is_vulnerable = confidence >= 7 and len(contradictions) > 0

        return AgentPhaseResult(
            path_id=path_id,
            vuln_type=vuln_type,
            actual_vuln_type=actual_vuln_type,
            score=score,
            contradictions=contradictions,
            confidence=confidence,
            analysis=analysis,
            is_vulnerable=is_vulnerable,
        )

    def create_verify_prompt(
        self,
        result: AgentPhaseResult,
        code_block: str = "",
        call_context: str = "",
    ) -> str:
        """Build the verification prompt for a finding."""
        return VERIFY_PROMPT_TEMPLATE.format(
            vuln_type=result.vuln_type,
            analysis=result.analysis or "(no analysis)",
            bypass_poc=(result.contradictions[0].get("bypass_poc", "")
                        if result.contradictions else ""),
            code_block=code_block or "(code not loaded)",
            call_context=call_context,
        )

    def verify(
        self,
        result: AgentPhaseResult,
        code_block: str = "",
        llm_response: str | None = None,
    ) -> AgentPhaseResult:
        """Verify a high-confidence finding with a skeptical reviewer.

        Returns the original result unchanged if confirmed,
        or a downgraded copy if the reviewer rejects it.
        """
        if llm_response is not None:
            data = parse_logic_response(llm_response)
        elif self._llm_call:
            prompt = self.create_verify_prompt(result, code_block)
            response = self._llm_call(prompt)
            data = parse_logic_response(response)
        else:
            return result  # no LLM, can't verify

        confirmed = data.get("confirmed", False) if isinstance(data, dict) else False
        v_confidence = data.get("confidence", 0) if isinstance(data, dict) else 0
        if not isinstance(v_confidence, int):
            try:
                v_confidence = int(v_confidence)
            except (ValueError, TypeError):
                v_confidence = 0

        # Only downgrade if reviewer clearly rejects (both says no AND low confidence)
        if not confirmed and v_confidence < 4:
            return AgentPhaseResult(
                path_id=result.path_id,
                vuln_type=result.vuln_type,
                score=result.score,
                contradictions=result.contradictions,
                confidence=min(result.confidence, max(v_confidence, 2)),
                analysis=result.analysis + (
                    f"\n[Verification rejected: {data.get('blockers', 'not confirmed')}]"
                    if isinstance(data, dict) else ""
                ),
                is_vulnerable=False,
            )

        # Confirmed or uncertain but still plausible — keep
        effective_conf = v_confidence if confirmed else min(v_confidence, result.confidence)
        return AgentPhaseResult(
            path_id=result.path_id,
            vuln_type=result.vuln_type,
            score=result.score,
            contradictions=result.contradictions,
            confidence=effective_conf,
            analysis=result.analysis + (
                f"\n[Verified: {data.get('exploit_steps', '')[:200]}]"
                if isinstance(data, dict) and data.get('exploit_steps')
                else ""
            ),
            is_vulnerable=effective_conf >= 7,
        )
