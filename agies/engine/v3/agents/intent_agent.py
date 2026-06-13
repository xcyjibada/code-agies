"""Intent Agent — Phase D Step 2.

Reads 4-5 functions and outputs "developer intent" pseudocode.
Does NOT make security judgments — only answers "what does this function do?".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from agies.engine.v3.aggregator.models import IntentResult, compute_body_hash

logger = logging.getLogger(__name__)


@dataclass
class IntentAgentTask:
    """One Intent Agent's workload — 4-5 functions to analyze."""

    batch_id: str
    """Unique ID for this batch, e.g. ``"path-001-batch-0"``."""

    path_id: str
    """Source path slice ID, e.g. ``"rce-001"``."""

    functions: list[dict[str, Any]] = field(default_factory=list)
    """Functions to analyze: ``[{func_name, file_path, line_start, line_end, code}, …]``."""

    readme_summary: str = ""
    """Project context from README summary."""


# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------

INTENT_PROMPT_TEMPLATE = """Project context: {readme_summary}

Analyze the following {count} functions in a call chain. Your job is ONLY to
describe "what the developer intended this function to do". Do NOT make
security judgments, do NOT say "vulnerable" or "safe".

For each function, output:

```
func_{{idx}} ({{func_name}}):
  intent: [What does this function do? One sentence.]
  inputs: [What data does it receive? Who calls it?]
  outputs: [What does it return? Who uses the result?]
  key_logic: [Core operation: replace/regex/if-check/permission check/transform]
  suspicious: [Anything odd — but DO NOT conclude anything]
  pass_through: [yes/no — if this function has suspicious operations (direct dangerous API calls, path construction without validation, etc.) set to "yes" so the raw source passes to the next stage for precise analysis]
```

{functions_block}
"""


def _format_functions_block(functions: list[dict[str, Any]]) -> str:
    """Format function list into the prompt block."""
    blocks: list[str] = []
    for i, fn in enumerate(functions):
        name = fn.get("func_name") or fn.get("function_name", f"func_{i}")
        code = fn.get("code") or fn.get("snippet", "")
        file_path = fn.get("file_path", "")
        line = fn.get("line_number", "?")
        blocks.append(
            f"[Function {i}: {name} ({file_path}:{line})]\n"
            f"```python\n{code}\n```"
        )
    return "\n\n".join(blocks)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_intent_response(
    response: str,
    functions: list[dict[str, Any]],
) -> list[IntentResult]:
    """Parse the LLM's intent analysis response into structured results.

    Handles the ``func_X (...)`` format from the prompt above.
    Falls back to creating minimal results if parsing fails.
    """
    results: list[IntentResult] = []
    current: dict[str, Any] = {}
    lines = response.strip().split("\n")

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Detect function header: func_0 (name):
        if line.startswith("func_") and "(" in line:
            if current and current.get("func_name"):
                results.append(_to_intent_result(current))
            current = {"func_name": _extract_name(line)}

        elif line.startswith("intent:"):
            current["intent"] = line[len("intent:"):].strip()
        elif line.startswith("inputs:"):
            current["inputs"] = line[len("inputs:"):].strip()
        elif line.startswith("outputs:"):
            current["outputs"] = line[len("outputs:"):].strip()
        elif line.startswith("key_logic:"):
            current["key_logic"] = line[len("key_logic:"):].strip()
        elif line.startswith("suspicious:"):
            current["suspicious"] = [line[len("suspicious:"):].strip()]
        elif line.startswith("pass_through:"):
            val = line[len("pass_through:"):].strip().lower()
            current["pass_through"] = val in ("yes", "true", "y")

    # Don't forget the last one
    if current and current.get("func_name"):
        results.append(_to_intent_result(current))

    # If we got nothing useful, create defaults from input functions
    if not results:
        for fn in functions:
            results.append(IntentResult(
                func_name=fn.get("func_name", "unknown"),
                file_path=fn.get("file_path", ""),
                intent=f"Function {fn.get('func_name', 'unknown')}",
            ))

    # Enrich with source code and compute fn_body_hash for cache key
    fn_map = {}
    for fn in functions:
        name = fn.get("func_name") or fn.get("function_name", "")
        if name:
            source = fn.get("code") or fn.get("snippet", "")
            fn_map[name] = source

    # Heuristic pass: force pass_through for functions with dangerous patterns
    # or validation/defense logic that should not be compressed to pseudocode.
    _DANGEROUS_PATTERNS = [
        "posixpath.join", "ntpath.join", "os.path.join",
        "PurePosixPath", "PureWindowsPath", "pathlib.PurePosixPath",
        "subprocess.", "popen", "os.system",
        "__import__", "compile",
        # ── Validation/defense patterns (may hide bypassable micro-defects) ──
        ".replace(",
        "re.match", "re.search", "re.compile", "re.fullmatch",
        "re.sub", "re.findall",
    ]

    for r in results:
        source = fn_map.get(r.func_name, "")
        # Force pass_through if LLM marked it OR source has dangerous patterns
        if not r.pass_through and source:
            for pat in _DANGEROUS_PATTERNS:
                if pat in source:
                    r.pass_through = True
                    break
        if r.pass_through and source:
            r.code = source

    # Compute fn_body_hash for each result (used as cache key in Blackboard)
    for r in results:
        source = fn_map.get(r.func_name, "")
        if source:
            r.fn_body_hash = compute_body_hash(source)

    return results


def _extract_name(header: str) -> str:
    """Extract function name from ``func_0 (my_func):``."""
    if "(" in header:
        return header.split("(")[1].split(")")[0].strip()
    return header


def _to_intent_result(data: dict[str, Any]) -> IntentResult:
    """Convert parsed dict to IntentResult."""
    suspicious = data.get("suspicious", [])
    if isinstance(suspicious, str):
        suspicious = [suspicious]
    return IntentResult(
        func_name=data.get("func_name", "unknown"),
        file_path=data.get("file_path", ""),
        intent=data.get("intent", ""),
        inputs=data.get("inputs", ""),
        outputs=data.get("outputs", ""),
        key_logic=data.get("key_logic", ""),
        suspicious=suspicious,
        pass_through=data.get("pass_through", False),
    )


# ---------------------------------------------------------------------------
# Intent Agent
# ---------------------------------------------------------------------------


class IntentAgent:
    """Processes a batch of 4-5 functions into developer intent pseudocode.

    In the v3 pipeline, multiple IntentAgent instances run in parallel
    (one per function group within a path).
    """

    def __init__(self, llm_call_fn=None):
        """Optional: provide an async LLM call function.
        When None, returns prompt + functions for external execution.
        """
        self._llm_call = llm_call_fn

    def prepare_prompt(self, task: IntentAgentTask) -> str:
        """Build the prompt for this task."""
        count = len(task.functions)
        functions_block = _format_functions_block(task.functions)

        return INTENT_PROMPT_TEMPLATE.format(
            readme_summary=task.readme_summary or "Not available.",
            count=count,
            functions_block=functions_block,
        )

    def run(
        self,
        task: IntentAgentTask,
        llm_response: str | None = None,
    ) -> list[IntentResult]:
        """Execute or parse an Intent Agent task.

        If ``llm_response`` is provided, just parse it.
        If ``llm_call_fn`` was set and no ``llm_response``, calls the LLM.
        """
        if llm_response is not None:
            return parse_intent_response(llm_response, task.functions)

        if self._llm_call:
            prompt = self.prepare_prompt(task)
            response = self._llm_call(prompt)
            return parse_intent_response(response, task.functions)

        # No LLM available — return stub results
        logger.warning(
            "IntentAgent: no LLM call function and no response provided "
            "for batch %s",
            task.batch_id,
        )
        return [
            IntentResult(
                func_name=fn.get("func_name", "unknown"),
                file_path=fn.get("file_path", ""),
                intent=f"Function {fn.get('func_name', 'unknown')}",
            )
            for fn in task.functions
        ]
