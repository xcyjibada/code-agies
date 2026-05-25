"""Mapping Agent — explores a project and builds a structured "map" of it.

The Mapping Agent is the first agent to run in the audit pipeline. It uses
deterministic tools (list_directory, read_file, grep_search) to explore the
project structure, language, framework, and key modules, then produces a
structured output consumed by ``ProjectState.register_result("mapping")``.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from pydantic import BaseModel, Field

from agies.engine.agents.base import AgentResponse, BaseAgent, ToolResult
from agies.tools import get_tool_definitions

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tools (subset of agies/tools that are useful for exploration)
# ---------------------------------------------------------------------------

MAPPING_TOOLS = [
    t for t in get_tool_definitions()
    if t["name"] in ("list_directory", "read_file", "grep_search")
]

# ---------------------------------------------------------------------------
# System prompt — tell the LLM to explore and produce a structured map
# ---------------------------------------------------------------------------

MAPPING_SYSTEM_PROMPT = """You are the **Cartographer**, a security architect specializing in automated codebase mapping.

## Mission
Explore the target repository and build a structured map. You must identify:
1. **Tech Stack** — language(s), framework(s), build system
2. **Project Structure** — modules, directories, key files
3. **Entry Points** — API routes, controllers, CLI commands
4. **Data Models** — schemas, ORM definitions, database config
5. **Security Controls** — auth, middleware, filters
6. **Trust Assumptions** — what is the developer implicitly trusting (see below)

## Trust Assumptions — why this matters
Every application has implicit trust assumptions that are the root cause of the most interesting bugs. For example:
- "The client sends the price, we just use it" → price tampering risk
- "We count coupon usage in a DB column" → race condition risk
- "Only admins can access this endpoint" → but is the check on every path?
- "User identity comes from the JWT" → but is the JWT validated on every call?
- "File paths are safe because we sanitized at the entry" → but did every entry?

You must identify these assumptions by reading config files, controllers, security middleware, and data models. **The goal is not to find bugs, but to identify what the developer is trusting** — the subsequent agents will try to break those trusts.

## Rules
1. Start broad: use `list_directory` on the root to understand the layout.
2. Drill down: read key config files (package.json, pom.xml, requirements.txt, etc.) and entry point files.
3. Don't read every file — focus on structure, not line-by-line analysis.
4. If a response is truncated, use `grep_search` to find specific patterns instead.

## Output
When you have a clear picture, output your analysis as a **valid JSON block**:

```json
{{
  "summary": "Brief description of the project and what it does",
  "language": "Main language",
  "framework": "Primary framework (or empty string if none)",
  "file_count": 0,
  "modules": [
    {{"name": "module_name", "path": "relative/path", "description": "what it does"}}
  ],
  "key_files": [
    {{"path": "relative/path", "role": "why this file matters"}}
  ],
  "trust_assumptions": [
    {{"assumption": "Prices arrive from the client-side shopping cart", "risk_category": "input_tampering"}},
    {{"assumption": "Coupon usage count is stored in a single DB column without locking", "risk_category": "race_condition"}}
  ]
}}
```

Do not add any text after the JSON block."""

# ---------------------------------------------------------------------------
# Output schema for validation
# ---------------------------------------------------------------------------


class ModuleEntry(BaseModel):
    name: str
    path: str = ""
    description: str = ""


class KeyFileEntry(BaseModel):
    path: str
    role: str = ""


class TrustAssumption(BaseModel):
    assumption: str
    risk_category: str = ""
    """Risk type: input_tampering, race_condition, auth_bypass, injection, disclosure, etc."""


class MappingOutput(BaseModel):
    summary: str
    language: str
    framework: str = ""
    file_count: int = 0
    modules: list[ModuleEntry] = Field(default_factory=list)
    key_files: list[KeyFileEntry] = Field(default_factory=list)
    trust_assumptions: list[TrustAssumption] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# MappingAgent
# ---------------------------------------------------------------------------


class MappingAgent(BaseAgent):
    """Project mapping agent — explores structure and produces a structured map.

    Usage::

        agent = MappingAgent()
        response = agent.run({"project_path": "/path/to/project"}, llm)
        state.register_result("mapping", {"project_path": ...}, response.output)
    """

    agent_id = "mapping"
    system_prompt = MAPPING_SYSTEM_PROMPT
    tools = MAPPING_TOOLS
    output_schema = MappingOutput
    MAX_ITERATIONS = 10

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def _parse_output(
        self,
        content: str,
        tool_results: list[ToolResult],
    ) -> dict[str, Any]:
        """Extract a ``MappingOutput``-compatible dict from the LLM's JSON.

        Strategy: find the last JSON block (`````json ... `````) in the
        content, parse it, and fall back to a heuristic search if no
        block is found.
        """
        if not content:
            logger.warning("MappingAgent: empty content, returning empty output.")
            return {}

        raw = self._extract_json(content)
        if not raw:
            logger.warning(
                "MappingAgent: no JSON block found in LLM output, "
                "trying content as-is."
            )
            raw = content

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning(
                "MappingAgent: JSON decode failed: %s. content=%s",
                exc,
                content[:300],
            )
            return {}

        # Normalise keys and prune unexpected fields
        return self._normalise(parsed)

    # ------------------------------------------------------------------
    # JSON extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_json(text: str) -> str | None:
        """Extract a JSON object from a code-fenced or bare block.

        Uses proper brace-depth counting instead of a fragile regex,
        so nested JSON objects are handled correctly.
        """
        # 1. Try ```json ... ``` code-fenced blocks (preferred)
        fence_starts = [m.start() for m in re.finditer(r"```(?:json)?", text)]
        for fs in reversed(fence_starts):  # last fence block wins
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
                            return text[content_start : i + 1]

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
                    return text[brace_start : i + 1]

        return None

    @staticmethod
    def _normalise(parsed: dict[str, Any]) -> dict[str, Any]:
        """Keep only keys that ``MappingOutput`` understands, filling defaults.

        Explicit defaults mirroring the model definition avoids fragile
        introspection of Pydantic's sentinel values.
        """
        allowed = MappingOutput.model_fields.keys()
        normalised: dict[str, Any] = {}
        for k in allowed:
            if k in parsed:
                normalised[k] = parsed[k]
            elif k == "framework":
                normalised[k] = ""
            elif k == "file_count":
                normalised[k] = 0
            elif k in ("modules", "key_files", "trust_assumptions"):
                normalised[k] = []
        return normalised
