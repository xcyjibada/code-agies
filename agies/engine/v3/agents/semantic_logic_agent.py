"""SemanticLogicAgent — spec falsification for semantic anchor code.

Unlike the sink-oriented LogicAgent (which finds contradictions between
pseudocode and source), this agent performs **spec falsification**:

1. Receives security contracts from SemanticIntentAgent
2. Reads the actual source code implementation
3. Determines whether the code upholds or violates each contract

The output uses the same ``AgentPhaseResult`` format so semantic findings
merge cleanly into the Phase E results pipeline.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from agies.engine.v3.aggregator.models import AgentPhaseResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

SPEC_FALSIFICATION_PROMPT = """You are performing **Security Contract Falsification**.

A Security Contract is a claim that a specific method makes about the security
property it enforces.  Your job: read the actual code and find **falsifications**
— code paths where the implementation violates the contract.

## Security Contracts

{contracts_block}

## Source Code

```python
{code_block}
```

## Methodology

For EACH contract above, determine:

1. **Is the contract actually enforced?** — Trace every code path. If any path
   bypasses the enforcement, that's a falsification.

2. **Are there edge cases?** — Error paths, configuration modes, optional
   parameters, or early returns that skip the check.

3. **Can the contract be violated by an attacker?** — Even if enforcement exists,
   can it be bypassed via type confusion, TOCTOU, encoding tricks,
   or parser differentials?

4. **State divergence** — Does the code cache or assume a security-relevant
   state that could become stale?

## Output Format

```json
{{
  "contradictions": [
    {{
      "func": "method_name",
      "contract": "The claimed security contract",
      "actual": "What the code actually does (the falsification)",
      "contradiction_type": "missing_guard|bypassable_guard|toctou|state_divergence",
      "evidence": "Line numbers or code snippet showing the violation",
      "bypass_poc": "Step-by-step: how an attacker would exploit this"
    }}
  ],
  "confidence": 0-10,
  "analysis": "Free-text summary of all findings",
  "guards_detected": ["guard1", "guard2"],
  "reasoning_steps": [
    "[DEVELOPER_SPEC] What the contract claims",
    "[HACKER_REALITY] What the code actually does",
    "[CONTRADICTION] The specific gap"
  ]
}}
```

If no contract is violated, output an empty contradictions array and low confidence.
"""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_falsification_response(response: str) -> dict[str, Any]:
    """Parse the LLM's spec falsification JSON response."""
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
                return {}
        else:
            return {}

    if not isinstance(data, dict):
        return {}

    if not isinstance(data.get("contradictions"), list):
        data["contradictions"] = []

    return data


# ---------------------------------------------------------------------------
# SemanticLogicAgent
# ---------------------------------------------------------------------------


class SemanticLogicAgent:
    """Performs spec falsification on semantic anchor code.

    Given security contracts + source code, finds code paths that violate
    the claimed security properties.
    """

    def __init__(self, llm_call_fn=None) -> None:
        self._llm_call = llm_call_fn

    def build_prompt(
        self,
        path_id: str,
        contracts: list[tuple[str, str]],
        code_block: str,
    ) -> str:
        """Build the spec falsification prompt."""
        formatted_contracts = "\n".join(
            f"  {i + 1}. **{fn}**: {contract}"
            for i, (fn, contract) in enumerate(contracts)
            if contract
        )
        if not formatted_contracts:
            formatted_contracts = "  (no contracts to verify)"

        return SPEC_FALSIFICATION_PROMPT.format(
            contracts_block=formatted_contracts,
            code_block=code_block,
        )

    def run(
        self,
        path_id: str,
        contracts: list[tuple[str, str]],
        code_block: str,
        llm_response: str | None = None,
    ) -> AgentPhaseResult:
        """Run spec falsification analysis.

        Parameters
        ----------
        path_id : str
            Semantic slice ID (e.g. ``"sem-auth-001"``).
        contracts : list[tuple[str, str]]
            List of (function_name, security_contract) pairs.
        code_block : str
            Full source code to analyze.
        llm_response : str, optional
            Pre-computed LLM response for replay/testing.

        Returns
        -------
        AgentPhaseResult
            Findings with contradictions = contract violations found.
        """
        if llm_response is not None:
            data = parse_falsification_response(llm_response)
        elif self._llm_call:
            prompt = self.build_prompt(path_id, contracts, code_block)
            response = self._llm_call(prompt)
            if response:
                data = parse_falsification_response(response)
            else:
                data = {}
        else:
            data = {}

        contradictions = data.get("contradictions", [])
        confidence = data.get("confidence", 0)
        if not isinstance(confidence, int):
            try:
                confidence = int(confidence)
            except (ValueError, TypeError):
                confidence = 0
        confidence = max(0, min(10, confidence))

        analysis = data.get("analysis", "")

        # A contract violation is a meaningful finding even at moderate confidence
        is_vulnerable = confidence >= 6 and len(contradictions) > 0

        return AgentPhaseResult(
            path_id=path_id,
            vuln_type="semantic",
            score=0.5,
            contradictions=contradictions,
            confidence=confidence,
            analysis=analysis,
            is_vulnerable=is_vulnerable,
        )
