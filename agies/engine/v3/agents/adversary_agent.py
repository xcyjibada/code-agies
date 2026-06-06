"""Adversary Agent — devil's advocate that tries to rebut findings.

Placed after Logic Agent, before PoC Agent.  Attempts to disprove the
finding.  If it finds a valid rebuttal → downgrade confidence.  If it
fails → greenlight for PoC generation.

This filters out fragile findings so only robust ones get PoCs.
"""

from __future__ import annotations

import json
import logging
import re

logger = logging.getLogger(__name__)

ADVERSARY_PROMPT = """You are an adversarial security reviewer. Your **only job** is to disprove the finding below. Be as skeptical as possible — look for ANY reason the vulnerability might NOT be exploitable.

Finding
-------
- Vulnerability Type: {vuln_type}
- Analysis: {analysis}
- Contradiction: {contradiction}

Source Code
```
{code_block}
```

Challenge the finding on these dimensions:
1. **Input validation** — Is there sanitization, escaping, or type checking that blocks the attack?
2. **Access control** — Can an attacker actually reach this code path?
3. **Data flow** — Does untrusted data actually reach the sink, or is there an intermediate clean step?
4. **Version/context** — Is this code only reachable in a specific configuration that mitigates the risk?
5. **Practicality** — Even if technically vulnerable, is there a practical constraint that makes exploitation impossible (rate limiting, network isolation, authentication)?

{rebuttal_history}

Be aggressive. If the finding is solid you should still struggle to find a real rebuttal — that's the point. But if you CAN find a genuine blocker, explain it.

Output:
```json
{{
  "rebutted": true/false,
  "confidence_downgrade": 0-10,
  "rebuttal": "If rebutted, explain exactly why the finding is wrong or impractical. Be specific, cite line numbers.",
  "weakness": "If NOT rebutted, what is the strongest dimension of this finding? What makes it hard to disprove?"
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
        """Build the adversarial review prompt."""
        return ADVERSARY_PROMPT.format(
            vuln_type=vuln_type.upper(),
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
