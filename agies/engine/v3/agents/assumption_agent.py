"""Assumption Agent — extracts implicit system assumptions from code.

Placed after Logic Agent, before Adversary Agent.  Does *not* determine
whether a vulnerability exists — it identifies what the developer implicitly
assumed would be true, then classifies those assumptions by risk type.

Implements the op.md methodology (Item ① → ⑥):
  - Check-Time ≠ Use-Time (TOCTOU)
  - Parser Differential
  - State Divergence (cache vs reality)
  - Object Identity (same name ≠ same object)
  - Atomicity assumptions
"""

from __future__ import annotations

import json
import logging
import re

logger = logging.getLogger(__name__)

# Assumption type taxonomy (from op.md methodology)
# Each type maps directly to a pattern in the prompt that the LLM searches for.
_ASSUMPTION_TYPES = {
    "PATH_STABILITY": (
        "The code assumes a path/URL doesn't change between validation and use. "
        "Common: symlink swap, file renamed, directory replaced with symlink."
    ),
    "PARSER_UNIFORMITY": (
        "The code assumes all components parse the same input identically. "
        "Common: URL parser A vs parser B, os.path vs PurePosixPath, "
        "case-sensitive vs case-insensitive filesystem."
    ),
    "STATE_EXCLUSIVITY": (
        "The code assumes only one code path can modify a given state. "
        "Common: race conditions, concurrent requests sharing mutable state, "
        "non-atomic read-modify-write."
    ),
    "CACHE_CORRECTNESS": (
        "The code assumes cached/computed state equals ground truth. "
        "Common: dirCache, memoized permissions, stale ACLs, lazy-loaded "
        "properties that are never refreshed."
    ),
    "OBJECT_IDENTITY": (
        "The code assumes the same name always refers to the same object. "
        "Common: case-insensitive FS (A ≠ a), Unicode normalization, "
        "hard links, mount points."
    ),
    "CHECK_USE_ATOMICITY": (
        "The code assumes checking a condition and using the result happen "
        "atomically.  Common: TOCTOU race, validation at request start but "
        "resource access after middleware/controller processing."
    ),
    "TYPE_INVARIANT": (
        "The code assumes a value will always have a specific type/structure. "
        "Common: unchecked collection types, **kwargs filling object fields, "
        "deserialization without schema validation."
    ),
}

_ASSUMPTION_PROMPT = """You are analyzing source code to extract **implicit security assumptions** — things the developer believed to be true but never explicitly verified in a defense-in-depth sense.

Vulnerability Type: {vuln_type}

Source Code (with data flow annotations)
```
{code_block}
```

Developer Intent (pseudocode)
```
{intent_chain}
```

{blackboard_knowledge}

Task: Identify every implicit assumption this code makes about its operating environment or inputs.

For each assumption found, classify it into one of these types:

{assumption_type_definitions}

Output format:
```json
{{
  "assumptions": [
    {{
      "assumption_type": "PATH_STABILITY|PARSER_UNIFORMITY|STATE_EXCLUSIVITY|CACHE_CORRECTNESS|OBJECT_IDENTITY|CHECK_USE_ATOMICITY|TYPE_INVARIANT",
      "description": "What the developer implicitly assumed. One sentence.",
      "code_location": "Approximate location or function where the assumption is made",
      "evidence": "What code pattern signals this assumption (e.g. 'path validated in guard(), then used after a function call with potential symlink swap')",
      "confidence": 1-10,
      "can_be_violated": true/false,
      "violation_scenario": "If can_be_violated, describe how an attacker could break this assumption. Otherwise, explain why it's safe."
    }}
  ]
}}
"""


def parse_assumption_response(response: str) -> list[dict]:
    """Parse the JSON response from the assumption extraction LLM call."""
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
                return []
        else:
            return []

    if not isinstance(data, dict):
        return []

    assumptions = data.get("assumptions", [])
    if not isinstance(assumptions, list):
        return []

    valid_types = {"PATH_STABILITY", "PARSER_UNIFORMITY", "STATE_EXCLUSIVITY",
                   "CACHE_CORRECTNESS", "OBJECT_IDENTITY", "CHECK_USE_ATOMICITY",
                   "TYPE_INVARIANT"}

    cleaned = []
    for a in assumptions:
        if not isinstance(a, dict):
            continue
        atype = a.get("assumption_type", "")
        if atype not in valid_types:
            atype = "TYPE_INVARIANT"
        confidence = a.get("confidence", 0)
        if not isinstance(confidence, int):
            try:
                confidence = int(confidence)
            except (ValueError, TypeError):
                confidence = 0
        confidence = max(1, min(10, confidence))
        cleaned.append({
            "assumption_type": atype,
            "description": str(a.get("description", "")),
            "code_location": str(a.get("code_location", "")),
            "evidence": str(a.get("evidence", "")),
            "confidence": confidence,
            "can_be_violated": bool(a.get("can_be_violated", False)),
            "violation_scenario": str(a.get("violation_scenario", "")),
        })

    return cleaned


class AssumptionAgent:
    """Extract implicit system assumptions from code.

    Follows the AdversaryAgent pattern: takes the same inputs (code_block,
    intent_chain, vuln_type) but outputs assumption classifications rather
    than vulnerability rebuttals.
    """

    def __init__(self) -> None:
        self._last_result: list[dict] = []

    def prepare_prompt(
        self,
        code_block: str = "",
        intent_chain: str = "",
        vuln_type: str = "",
        blackboard_knowledge: str = "",
    ) -> str:
        """Build the assumption extraction prompt."""
        type_defs = "\n".join(
            f"- {k}: {v}" for k, v in _ASSUMPTION_TYPES.items()
        )
        bb_section = (
            f"\n[PRIOR KNOWLEDGE FROM OTHER PATHS]\n{blackboard_knowledge}\n[/PRIOR KNOWLEDGE]\n"
            if blackboard_knowledge.strip()
            else ""
        )
        return _ASSUMPTION_PROMPT.format(
            code_block=code_block or "(code not loaded)",
            intent_chain=intent_chain or "(no pseudocode)",
            vuln_type=vuln_type.upper(),
            assumption_type_definitions=type_defs,
            blackboard_knowledge=bb_section,
        )

    def run(
        self,
        code_block: str = "",
        intent_chain: str = "",
        vuln_type: str = "",
        blackboard_knowledge: str = "",
        llm_response: str | None = None,
        llm_call=None,
    ) -> list[dict]:
        """Run assumption extraction.

        Returns a list of assumption dicts, each with:
          - assumption_type: str
          - description: str
          - code_location: str
          - evidence: str
          - confidence: int (1-10)
          - can_be_violated: bool
          - violation_scenario: str
        """
        if llm_response is not None:
            data = parse_assumption_response(llm_response)
        elif llm_call:
            prompt = self.prepare_prompt(
                code_block=code_block,
                intent_chain=intent_chain,
                vuln_type=vuln_type,
                blackboard_knowledge=blackboard_knowledge,
            )
            response = llm_call(prompt)
            data = parse_assumption_response(response) if response else []
        else:
            data = []

        self._last_result = data
        return data

    @property
    def last_result(self) -> list[dict]:
        """Return the most recent assumption extraction result."""
        return self._last_result

    def format_for_blackboard(self, path_id: str) -> list[tuple[str, str]]:
        """Format assumptions as (function_name, knowledge_text) tuples.

        Used by the runner to record assumptions in the BlackboardAggregator
        for cross-path correlation in Phase D.5.
        """
        entries: list[tuple[str, str]] = []
        for a in self._last_result:
            # Use code_location as a rough function name for blackboard lookup
            fn = a.get("code_location", "?")[:60]
            text = (
                f"[ASSUMPTION {a.get('assumption_type', '?')}] "
                f"{a.get('description', '')} | "
                f"violable={a.get('can_be_violated', False)} | "
                f"scenario={a.get('violation_scenario', '')[:200]}"
            )
            entries.append((fn, text))
        return entries
