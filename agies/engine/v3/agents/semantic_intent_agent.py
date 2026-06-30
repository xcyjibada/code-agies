"""SemanticIntentAgent — extracts security contracts from semantic slices.

Unlike the sink-oriented IntentAgent (which asks "what does this function do?"),
this agent reads high-value business logic classes (auth, session, token, secret
managers) and answers: "what security property does this code CLAIM to enforce?"

The output security contracts feed into SemanticLogicAgent for spec falsification.
"""

from __future__ import annotations

import logging
from typing import Any

from agies.engine.v3.aggregator.models import IntentResult, compute_body_hash

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------

SEMANTIC_INTENT_PROMPT = """You are a security contract analyst. Your job is to read a
high-value business logic class and extract the SECURITY CONTRACT for each method.

A security contract is a one-sentence statement of what security property the
method CLAIMS to enforce.  Examples:
  - "Validates that the file path does not escape BASE_DIR"
  - "Ensures only the resource owner can access this resource"
  - "Verifies the JWT signature and checks expiration"
  - "Sanitizes user input to prevent XSS"
  - "Empty — no security relevance"

DO NOT make security judgments or say "vulnerable".  Only extract the contract.

**Anchor type**: {anchor_type}
**Domain guidance**:
{semantic_hint}

{code_block}

For each method in the class above, output:

```
func_{{idx}} ({{method_name}}):
  intent: [What does this method do? One sentence.]
  inputs: [What data does it receive?]
  outputs: [What does it return?]
  key_logic: [Core operation: validation/check/transform/delegate]
  security_contract: [The security property this method CLAIMS to enforce — empty string if none]
```

If a method has no security relevance (pure getter, pure transform, no validation),
set `security_contract` to an empty string.  Accuracy matters: false contracts
waste downstream analysis.
"""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_semantic_intent_response(
    response: str,
    functions: list[dict[str, Any]],
) -> list[IntentResult]:
    """Parse the LLM's security contract analysis into IntentResults.

    Same ``func_X (name):`` format as the sink IntentAgent parser,
    but ``security_contract`` is the primary field.
    """
    results: list[IntentResult] = []
    current: dict[str, Any] = {}
    lines = response.strip().split("\n")

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.startswith("func_") and "(" in line:
            if current and current.get("func_name"):
                results.append(_to_semantic_result(current))
            current = {"func_name": _extract_semantic_name(line)}

        elif line.startswith("intent:"):
            current["intent"] = line[len("intent:"):].strip()
        elif line.startswith("inputs:"):
            current["inputs"] = line[len("inputs:"):].strip()
        elif line.startswith("outputs:"):
            current["outputs"] = line[len("outputs:"):].strip()
        elif line.startswith("key_logic:"):
            current["key_logic"] = line[len("key_logic:"):].strip()
        elif line.startswith("security_contract:"):
            current["security_contract"] = line[len("security_contract:"):].strip()

    if current and current.get("func_name"):
        results.append(_to_semantic_result(current))

    # Fallback: create stub results if parsing failed
    if not results:
        for fn in functions:
            results.append(IntentResult(
                func_name=fn.get("function_name", "unknown"),
                file_path=fn.get("file_path", ""),
                intent=f"Method {fn.get('function_name', 'unknown')}",
            ))

    # Compute fn_body_hash for cache keys
    fn_body_map = {}
    for fn in functions:
        name = fn.get("function_name", "")
        code = fn.get("code") or fn.get("snippet", "")
        if name and code:
            fn_body_map[name] = code

    for r in results:
        source = fn_body_map.get(r.func_name, "")
        if source:
            r.fn_body_hash = compute_body_hash(source)

    return results


def _extract_semantic_name(header: str) -> str:
    """Extract method name from ``func_0 (my_method):``."""
    if "(" in header:
        return header.split("(")[1].split(")")[0].strip()
    return header


def _to_semantic_result(data: dict[str, Any]) -> IntentResult:
    """Convert parsed dict to IntentResult with security_contract."""
    return IntentResult(
        func_name=data.get("func_name", "unknown"),
        file_path=data.get("file_path", ""),
        intent=data.get("intent", ""),
        inputs=data.get("inputs", ""),
        outputs=data.get("outputs", ""),
        key_logic=data.get("key_logic", ""),
        security_contract=data.get("security_contract", ""),
    )


# ---------------------------------------------------------------------------
# SemanticIntentAgent
# ---------------------------------------------------------------------------


class SemanticIntentAgent:
    """Extracts security contracts from a SemanticSlice.

    Each method in the slice gets an IntentResult with a security_contract
    field.  Contracts feed into SemanticLogicAgent for spec falsification.
    """

    def __init__(self, llm_call_fn=None) -> None:
        self._llm_call = llm_call_fn

    def build_prompt(
        self,
        anchor_type: str,
        semantic_hint: str,
        code_block: str,
        functions: list[dict[str, Any]],
    ) -> str:
        """Build the security contract extraction prompt."""
        func_count = len(functions)

        return SEMANTIC_INTENT_PROMPT.format(
            anchor_type=anchor_type or "general",
            semantic_hint=semantic_hint or "(no domain guidance)",
            code_block=code_block,
            func_count=func_count,
        )

    def analyze(
        self,
        anchor_type: str,
        semantic_hint: str,
        code_block: str,
        functions: list[dict[str, Any]],
        file_path: str = "",
        llm_response: str | None = None,
    ) -> list[IntentResult]:
        """Analyze a semantic slice and extract security contracts.

        Parameters
        ----------
        anchor_type : str
            The semantic anchor category (e.g. ``"token_management"``).
        semantic_hint : str
            Domain guidance from the anchor engine's hint map.
        code_block : str
            Full source code of the class.
        functions : list[dict]
            Method definitions: ``[{function_name, file_path, code, ...}]``.
        llm_response : str, optional
            If provided, skip LLM call and parse this response directly.

        Returns
        -------
        list[IntentResult]
            Per-method IntentResults with ``security_contract`` filled.
        """
        if llm_response is not None:
            return parse_semantic_intent_response(llm_response, functions)

        if self._llm_call:
            prompt = self.build_prompt(
                anchor_type, semantic_hint, code_block, functions,
            )
            response = self._llm_call(prompt)
            if response:
                return parse_semantic_intent_response(response, functions)

        # Fill in file_path for stub results
        results: list[IntentResult] = []
        for fn in functions:
            fn_path = fn.get("file_path", file_path)
            results.append(IntentResult(
                func_name=fn.get("function_name", "unknown"),
                file_path=fn_path,
                intent=f"Method {fn.get('function_name', 'unknown')}",
            ))
        return results
