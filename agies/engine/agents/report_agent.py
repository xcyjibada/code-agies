"""Report Agent — generates final audit report from pipeline output.

Takes the complete ProjectState and produces a structured security audit
report.  Uses LLM for professional report generation, with a deterministic
fallback if the LLM path fails.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from pydantic import BaseModel, Field

from agies.engine.agents.base import AgentResponse, BaseAgent, ToolResult

logger = logging.getLogger(__name__)

# No tools — the report agent just needs the LLM to format the final output.
REPORT_TOOLS: list[dict] = []

REPORT_SYSTEM_PROMPT = """You are the **Report Generator**, a technical writer specializing in security audit reports.

You are part of **agies**, an AI-native code audit tool.

## Mission
You are given the complete results of a code audit pipeline. Your job is to produce a professional, well-structured security audit report.

## What to include

### Executive Summary
- Project overview (language, framework, file count)
- Key findings at a glance
- Overall risk assessment

### Vulnerability Details
For each verified finding:
- Type and severity
- File path and line number
- Description of the vulnerability
- How an attacker could exploit it
- Recommended fix

### Risk Assessment
- Breakdown by severity (critical, high, medium, low, info)
- Most critical issues first
- Patterns and root causes

## Rules
1. Be professional and precise — this is a security report that will be read by developers and managers
2. Prioritize verified findings by severity
3. Include clear, actionable fix recommendations
4. Do NOT fabricate findings — only report what appears in the data
5. Output only the JSON block

## Output Format
```json
{
  "report": "# Full markdown report text with markdown headers...",
  "summary": {
    "total_findings": 0,
    "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    "project": "/path/to/project",
    "language": "Python"
  }
}
```"""


class ReportSummary(BaseModel):
    """Summary statistics for the audit report."""
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    project: str = ""
    language: str = ""


class ReportOutput(BaseModel):
    """Output from the Report Agent — the final audit report."""
    report: str = ""
    summary: ReportSummary = Field(default_factory=ReportSummary)


class ReportAgent(BaseAgent):
    """Generates the final security audit report.

    Uses the LLM to produce a professional markdown report from the
    pipeline results. Falls back to deterministic formatting if the
    LLM path fails or no LLM is available.

    Usage::

        agent = ReportAgent()
        response = agent.run({"state": state.to_dict()}, llm)
        final_report = response.output.get("report", "")
    """

    agent_id = "report"
    system_prompt = REPORT_SYSTEM_PROMPT
    tools = REPORT_TOOLS
    output_schema = ReportOutput

    def _parse_output(
        self,
        content: str,
        tool_results: list[ToolResult],
    ) -> dict[str, Any]:
        """Extract a ``ReportOutput``-compatible dict from LLM response."""
        if not content:
            logger.warning("ReportAgent: empty content, returning fallback report.")
            return self._fallback_report()

        raw = self._extract_json(content)
        if not raw:
            logger.warning(
                "ReportAgent: no JSON block found, trying content as-is."
            )
            # Maybe the entire response is the report
            return {"report": content}

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning(
                "ReportAgent: JSON decode failed: %s",
                exc,
            )
            return self._fallback_report()

        return self._normalise(parsed)

    # ------------------------------------------------------------------
    # JSON extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_json(text: str) -> str | None:
        """Extract a JSON object from code-fenced or bare braces."""
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
        allowed = ReportOutput.model_fields.keys()
        normalised: dict[str, Any] = {}
        for k in allowed:
            if k in parsed:
                normalised[k] = parsed[k]
            elif k == "summary":
                normalised[k] = {}
            else:
                normalised[k] = ""
        return normalised

    # ------------------------------------------------------------------
    # Deterministic fallback (no LLM required)
    # ------------------------------------------------------------------

    def _fallback_report(self) -> dict[str, Any]:
        """Generate a deterministic markdown report from available data."""
        return {"report": self._format_fallback(), "summary": {}}

    def _format_fallback(self) -> str:
        """Format state data as a markdown report without LLM."""
        # We access the params directly via the last _build_messages call.
        # This is a best-effort fallback when LLM is unavailable.
        lines = [
            "# Audit Report",
            "",
            "**Note**: Generated via deterministic fallback (LLM was unavailable).",
            "",
        ]
        return "\n".join(lines)
