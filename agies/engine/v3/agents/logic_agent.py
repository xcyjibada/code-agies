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
    ) -> str:
        """Build the logic analysis prompt using VulnHuntr-style prompts.

        Uses raw source code (``code_block``) when available, falling back
        to the merged intent chain.
        """
        from agies.engine.v3.prompts import get_prompt

        return get_prompt(
            vuln_type,
            code_block=code_block or intent_chain,
            readme_summary=readme_summary,
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

        if not isinstance(confidence, int):
            try:
                confidence = int(confidence)
            except (ValueError, TypeError):
                confidence = 0
        confidence = max(0, min(10, confidence))

        is_vulnerable = confidence >= 7 and len(contradictions) > 0

        return AgentPhaseResult(
            path_id=path_id,
            vuln_type=vuln_type,
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
    ) -> str:
        """Build the verification prompt for a finding."""
        return VERIFY_PROMPT_TEMPLATE.format(
            vuln_type=result.vuln_type,
            analysis=result.analysis or "(no analysis)",
            bypass_poc=(result.contradictions[0].get("bypass_poc", "")
                        if result.contradictions else ""),
            code_block=code_block or "(code not loaded)",
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
