"""Verify Agent — validates candidate vulnerabilities in the legacy pipeline.

Takes a candidate vulnerability (from the Vulnerability Agent) and validates
it by reading source code, tracing data flow, checking for mitigating controls,
and determining whether it's truly exploitable.

Uses deterministic verification pipeline tools (attacker_control, exploitability)
plus code exploration tools (read_file, grep_search, get_taint_flows) for
LLM-driven validation.

Output is consumed by the Report Agent and feeds into ProjectState as verified
findings.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from pydantic import BaseModel, Field

from agies.engine.agents.base import AgentResponse, BaseAgent, ToolResult
from agies.engine.sast import confidence_from_severity
from agies.tools import get_tool_definitions

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

VERIFY_TOOLS = [
    t for t in get_tool_definitions()
    if t["name"] in (
        "read_file", "grep_search", "get_taint_flows",
        "lookup_function", "find_callers", "find_callees",
        "get_call_chain_logic", "record_knowledge",
    )
]

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

VERIFY_SYSTEM_PROMPT = """You are the **Vulnerability Verifier**, a security researcher specializing in validating potential security findings.

## Mission
You are given a candidate vulnerability discovered by an earlier analysis agent. Your job is to **verify or refute** it by examining the actual source code. Determine whether the vulnerability is a real, exploitable issue or a false positive.

## Your Method

### Step 1: Read the vulnerable code
Use `read_file` to read the file containing the alleged vulnerability. Understand the context around the reported line.

### Step 2: Trace data flow
- Use `grep_search` to find how inputs reach this code path
- Use `lookup_function` to find related functions
- Use `find_callers` / `find_callees` to understand call chains
- Use `get_taint_flows` to check static analysis results

### Step 3: Check for mitigating controls
- Is there input validation or sanitization?
- Is there authentication or authorization?
- Are there type checks or boundaries?
- Is the code path reachable at all?

### Step 4: Determine verdict
- **Confirmed**: The vulnerability is real and exploitable
- **False positive**: The code path is not exploitable (mitigating controls exist, path is unreachable, etc.)
- **Inconclusive**: Cannot determine with available information

## Rules
1. Always read the source code at the reported location — don't rely on the description alone
2. A finding is only "confirmed" if an attacker can realistically reach the sink with controlled input
3. If you find mitigating controls, describe them specifically
4. For confirmed findings, provide clear evidence and reasoning
5. For false positives, explain why the original analysis was wrong
6. Output only the JSON block

## Output Format
```json
{
  "findings": [
    {
      "type": "sql_injection",
      "severity": "critical|high|medium|low|info",
      "file_path": "relative/path/to/file",
      "line_number": 42,
      "title": "Confirmed: SQL injection in UserController.login()",
      "description": "Detailed description of the verified vulnerability",
      "reasoning": "Why this is confirmed — the evidence chain",
      "confidence": "high|medium|low",
      "verified": true
    }
  ]
}
```

If the vulnerability is a false positive or cannot be confirmed:
```json
{
  "findings": []
}
```"""

# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------


class VerifiedFinding(BaseModel):
    """A single verified (or refuted) finding after manual review."""
    type: str = ""
    severity: str = "medium"
    file_path: str = ""
    line_number: int = 0
    title: str = ""
    description: str = ""
    reasoning: str = ""
    confidence: str = "medium"
    verified: bool = True


class VerifyOutput(BaseModel):
    """Full output from one Verify Agent invocation."""
    findings: list[VerifiedFinding] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# VerifyAgent
# ---------------------------------------------------------------------------


class VerifyAgent(BaseAgent):
    """Validates candidate vulnerabilities from the Vulnerability Agent.

    Usage::

        agent = VerifyAgent()
        response = agent.run({
            "vulnerability_id": "v_001",
            "vulnerability": {"type": "sqli", "file_path": "src/db.py", ...},
            "project_path": "/path/to/project",
        }, llm)
        state.register_result("verify", params, response.output)
    """

    agent_id = "verify"
    system_prompt = VERIFY_SYSTEM_PROMPT
    tools = VERIFY_TOOLS
    output_schema = VerifyOutput

    DEFAULT_LLM_KWARGS: dict[str, Any] = {"max_tokens": 4096}

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(
        self,
        params: dict[str, Any],
        llm: Any = None,
        **llm_kwargs: Any,
    ) -> AgentResponse:
        response = super().run(params, llm, **llm_kwargs)

        # Run SAST pattern matching — tag findings and boost confidence
        self._apply_sast(response, params)

        return response

    def _apply_sast(
        self,
        response: AgentResponse,
        params: dict[str, Any],
    ) -> None:
        """Run SAST matcher on each verified finding's file and tag evidence."""
        if not response.output:
            return

        findings = response.output.get("findings", [])
        if not findings:
            return

        project_path = params.get("project_path", "")

        try:
            from agies.engine.sast.matcher import get_matcher

            matcher = get_matcher()
        except Exception as exc:
            logger.debug("VerifyAgent: SAST matcher unavailable: %s", exc)
            return

        confidence_order = {"low": 0, "medium": 1, "high": 2}

        for finding in findings:
            file_path = finding.get("file_path", "")
            if not file_path:
                continue
            if not os.path.isabs(file_path) and project_path:
                file_path = os.path.normpath(os.path.join(project_path, file_path))
            if not os.path.isfile(file_path):
                continue

            try:
                results = matcher.match_file(file_path)
            except Exception as exc:
                logger.debug(
                    "VerifyAgent: SAST match failed for %s: %s", file_path, exc
                )
                continue

            if not results:
                continue

            evidence = finding.get("evidence", "")
            for r in results:
                tag = (
                    f"[SAST:{r.rule_id}] {r.rule_name} "
                    f"(line {r.line_number}, severity={r.severity})"
                )
                if evidence:
                    evidence += "\n" + tag
                else:
                    evidence = tag

                tag_confidence = confidence_from_severity(r.severity)
                current_confidence = finding.get("confidence", "medium")
                if confidence_order.get(tag_confidence, 0) > confidence_order.get(
                    current_confidence, 1
                ):
                    finding["confidence"] = tag_confidence

            if evidence:
                finding["evidence"] = evidence

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def _parse_output(
        self,
        content: str,
        tool_results: list[ToolResult],
    ) -> dict[str, Any]:
        """Extract a ``VerifyOutput``-compatible dict from LLM response."""
        if not content:
            logger.warning("VerifyAgent: empty content, returning empty output.")
            return {"findings": []}

        raw = self._extract_json(content)
        if not raw:
            logger.warning(
                "VerifyAgent: no JSON block found in LLM output, "
                "trying content as-is."
            )
            raw = content

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning(
                "VerifyAgent: JSON decode failed: %s. content=%s",
                exc,
                content[:300],
            )
            return {"findings": []}

        return self._normalise(parsed)

    # ------------------------------------------------------------------
    # JSON extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_json(text: str) -> str | None:
        """Extract a JSON object from a code-fenced or bare block.

        Uses proper brace-depth counting instead of a fragile regex,
        so nested JSON objects are handled correctly.
        """
        # 1. Try ```json ... ``` code-fenced blocks (preferred)
        fence_starts = [m.start() for m in re.finditer(r"```(?:json)?", text)]
        for fs in reversed(fence_starts):
            after_fence = text[fs + 3:]
            prefix_skip = 4 if after_fence.startswith("json") else 0
            brace_rel = after_fence.find("{", prefix_skip)
            if brace_rel == -1:
                continue
            content_start = fs + 3 + brace_rel

            depth = 0
            for i in range(content_start, len(text)):
                ch = text[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        rest = text[i + 1:].lstrip()
                        if not rest or rest.startswith("```"):
                            return text[content_start: i + 1]

        # 2. Try bare { ... } block
        brace_start = text.find("{")
        if brace_start == -1:
            return None

        depth = 0
        for i in range(brace_start, len(text)):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[brace_start: i + 1]

        return None

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise(parsed: dict[str, Any]) -> dict[str, Any]:
        """Keep only keys that ``VerifyOutput`` understands."""
        allowed = VerifyOutput.model_fields.keys()
        normalised: dict[str, Any] = {}
        for k in allowed:
            if k in parsed:
                normalised[k] = parsed[k]
            elif k == "findings":
                normalised[k] = []

        # Prune unknown fields and fill defaults for each finding
        finding_allowed = VerifiedFinding.model_fields.keys()

        cleaned_findings: list[dict[str, Any]] = []
        for finding in normalised.get("findings", []):
            entry: dict[str, Any] = {}
            for k in finding_allowed:
                field_info = VerifiedFinding.model_fields[k]
                if k in finding:
                    entry[k] = finding[k]
                elif k == "verified":
                    entry[k] = True
                elif k == "confidence":
                    entry[k] = "medium"
                elif k == "severity":
                    entry[k] = "medium"
                elif field_info.annotation is int:
                    entry[k] = 0
                else:
                    entry[k] = ""
            cleaned_findings.append(entry)

        normalised["findings"] = cleaned_findings
        return normalised
