"""Attack Surface Agent — discovers external entry points.

Finds HTTP endpoints, message listeners, CLI commands, and other
attacker-accessible entry points in the target project.  Provides
composable attack surfaces (e.g. "upload file + access file = arbitrary
file read").

Output is consumed by DataFlow and Vulnerability agents.
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
# Tools
# ---------------------------------------------------------------------------

ATTACK_SURFACE_TOOLS = [
    t for t in get_tool_definitions()
    if t["name"] in ("read_file", "grep_search", "list_directory")
]

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

ATTACK_SURFACE_SYSTEM_PROMPT = """You are the **Attack Surface Analyst**, a security architect specializing in identifying all attacker-reachable entry points in a codebase.

## Mission
Analyze the target project and produce a comprehensive inventory of entry points. Every item you find represents a potential attack vector.

## What to look for

### HTTP Endpoints (highest priority)
- Route annotations/decorators: `@RequestMapping`, `@GetMapping`, `@PostMapping`, `@app.route()`, `router.get()`, etc.
- URL patterns in config files (routes.php, urls.py, etc.)
- API gateway routes
- GraphQL endpoints

### Message / Event Listeners
- Message queue consumers (RabbitMQ, Kafka, SQS)
- Event handlers
- WebSocket handlers

### CLI Commands
- Console commands, CLI entry points
- Cron job handlers

### Library / SDK APIs
- Public classes and constructors that accept user-controlled data
- Functions that read files, parse data, or process untrusted input
- Deserialization entry points (pickle.loads, json.loads, yaml.load, etc.)

### File / Network I/O
- File upload endpoints
- Network listeners
- Named pipe listeners

## Method
1. Use `list_directory` to understand the project structure
2. Use `grep_search` with route patterns (`@RequestMapping`, `@app.route`, `router[.](get|post)`, etc.)
3. Drill down into controller/route files with `read_file`
4. For each route, identify: path, HTTP method, parameters, auth requirements

## Rules
1. Focus on **external** entry points — things an attacker could reach from outside
2. Don't report internal functions unless they're exposed via a route
3. Group related endpoints (e.g., same controller, same path prefix)
4. Identify **combined attack surfaces**: two+ endpoints that together create an exploitable chain
5. Output only the JSON block

## Output Format
```json
{
  "entry_points": [
    {
      "type": "http_endpoint",
      "path": "/api/users/{id}",
      "method": "GET",
      "file_path": "src/controllers/UserController.java",
      "line_number": 42,
      "description": "Get user by ID — no auth check before the handler",
      "parameters": [{"name": "id", "source": "path", "type": "int"}],
      "auth_required": true,
      "combined_attack_surface": []
    }
  ]
}
```

Do NOT add text after the JSON block."""


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------


class EntryPointParameter(BaseModel):
    name: str = ""
    source: str = "query"
    type: str = "string"


class EntryPoint(BaseModel):
    type: str = "http_endpoint"
    path: str = ""
    method: str = ""
    file_path: str = ""
    line_number: int = 0
    description: str = ""
    parameters: list[EntryPointParameter] = Field(default_factory=list)
    auth_required: bool = True
    combined_attack_surface: list[str] = Field(default_factory=list)


class AttackSurfaceOutput(BaseModel):
    entry_points: list[EntryPoint] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# AttackSurfaceAgent
# ---------------------------------------------------------------------------


class AttackSurfaceAgent(BaseAgent):
    """Identifies all attacker-reachable entry points in a project.

    Usage::

        agent = AttackSurfaceAgent()
        response = agent.run({"project_path": "/path/to/project"}, llm)
        state.register_result("attack_surface", params, response.output)
    """

    agent_id = "attack_surface"
    system_prompt = ATTACK_SURFACE_SYSTEM_PROMPT
    tools = ATTACK_SURFACE_TOOLS
    output_schema = AttackSurfaceOutput
    MAX_ITERATIONS = 10

    def _parse_output(
        self,
        content: str,
        tool_results: list[ToolResult],
    ) -> dict[str, Any]:
        """Extract an ``AttackSurfaceOutput``-compatible dict from LLM JSON."""
        if not content:
            logger.warning("AttackSurfaceAgent: empty content, returning empty output.")
            return {"entry_points": []}

        import json

        raw = self._extract_json(content)
        if raw:
            # Try raw first — _sanitize_json can mangle valid JSON that
            # contains // in string values (e.g., "https://example.com").
            parsed = None
            for candidate in (raw, self._sanitize_json(raw)):
                try:
                    parsed = json.loads(candidate)
                    break
                except json.JSONDecodeError:
                    continue
            if parsed is not None:
                return self._normalise(parsed)
        # Fallback: try sanitizing the whole content
        logger.warning(
            "AttackSurfaceAgent: no JSON block found, trying content as-is."
        )
        try:
            parsed = json.loads(self._sanitize_json(content))
            return self._normalise(parsed)
        except json.JSONDecodeError as exc:
            logger.warning(
                "AttackSurfaceAgent: JSON decode failed: %s",
                exc,
            )
            return {"entry_points": []}

    # ------------------------------------------------------------------
    # JSON extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _sanitize_json(raw: str) -> str:
        """Fix common LLM JSON output issues before parsing.
        Respects string boundaries so // in URLs isn't removed.

        - ``\\X`` invalid escape sequences (LLMs escape non-escape chars)
        - trailing commas before ``]`` or ``}``
        - ``//`` single-line comments (outside strings only)
        """
        def _fix_escapes(m: re.Match) -> str:
            c = m.group(1)
            if c == 'u':
                return m.group(0)  # keep \uXXXX intact
            if c in ('"', '\\', '/', 'b', 'f', 'n', 'r', 't'):
                return m.group(0)  # valid JSON escape
            return c  # invalid — remove leading backslash

        raw = re.sub(r'\\(.)', _fix_escapes, raw)
        raw = re.sub(r',\s*}', '}', raw)
        raw = re.sub(r',\s*]', ']', raw)
        # Remove // comments but respect string boundaries
        processed = []
        in_string = False
        escape = False
        i = 0
        while i < len(raw):
            ch = raw[i]
            if escape:
                escape = False
                processed.append(ch)
                i += 1
                continue
            if ch == '\\':
                escape = True
                processed.append(ch)
                i += 1
                continue
            if ch == '"':
                in_string = not in_string
                processed.append(ch)
                i += 1
                continue
            if in_string:
                processed.append(ch)
                i += 1
                continue
            if ch == '/' and i + 1 < len(raw) and raw[i + 1] == '/':
                while i < len(raw) and raw[i] != '\n':
                    i += 1
                continue
            processed.append(ch)
            i += 1
        return ''.join(processed)

    @staticmethod
    def _extract_json(text: str) -> str | None:
        """Extract JSON from code-fenced block or bare braces.

        Tries each ``{`` position in the text and returns the first
        that produces valid JSON.
        """
        import json

        # Phase 1: try fenced blocks first (most reliable)
        fence_starts = [m.start() for m in re.finditer(r"```(?:json)?", text)]
        for fs in reversed(fence_starts):
            after_fence = text[fs + 3:]
            prefix_skip = 4 if after_fence.startswith("json") else 0
            brace_rel = after_fence.find("{", prefix_skip)
            if brace_rel == -1:
                continue
            content_start = fs + 3 + brace_rel
            extracted = _balanced_braces(text, content_start)
            if extracted is not None:
                try:
                    json.loads(extracted)
                    return extracted
                except json.JSONDecodeError:
                    continue

        # Phase 2: try every { position and validate by parsing
        idx = 0
        while True:
            brace_start = text.find("{", idx)
            if brace_start == -1:
                return None
            extracted = _balanced_braces(text, brace_start)
            if extracted is not None:
                try:
                    json.loads(extracted)
                    return extracted
                except json.JSONDecodeError:
                    pass
            idx = brace_start + 1
        return None

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise(parsed: dict[str, Any]) -> dict[str, Any]:
        allowed = AttackSurfaceOutput.model_fields.keys()
        normalised: dict[str, Any] = {}
        for k in allowed:
            if k in parsed:
                normalised[k] = parsed[k]
            elif k == "entry_points":
                normalised[k] = []

        ep_allowed = EntryPoint.model_fields.keys()
        cleaned: list[dict[str, Any]] = []
        for ep in normalised.get("entry_points", []):
            entry: dict[str, Any] = {}
            for k in ep_allowed:
                if k in ep:
                    if k == "combined_attack_surface":
                        entry[k] = [str(x) if not isinstance(x, str) else x for x in ep[k]]
                    else:
                        entry[k] = ep[k]
                elif k == "parameters":
                    entry[k] = []
                elif k == "combined_attack_surface":
                    entry[k] = []
                elif k == "auth_required":
                    entry[k] = True
                else:
                    entry[k] = ""
            cleaned.append(entry)
        normalised["entry_points"] = cleaned

        return normalised


def _balanced_braces(text: str, start: int) -> str | None:
    """Extract brace-balanced JSON text starting at position *start*.

    Returns the substring from ``text[start]`` through the matching
    ``}`` at depth 0, or ``None`` if no balanced closing brace is found.
    Respects string boundaries so braces inside strings don't break counting.
    """
    if start >= len(text) or text[start] != "{":
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start: i + 1]
    return None
