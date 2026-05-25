"""DataFlow Agent — traces data flow from entry points to sinks.

Takes an entry point discovered by AttackSurface Agent and uses LLM-driven
exploration to trace how attacker-controlled input flows through the codebase.

Output is consumed by Vulnerability Agent (Mode 2) to focus analysis on
confirmed data-flow paths rather than blind file scanning.

Tools used:
- grep_search / read_file — code exploration
- lookup_function / find_callers / find_callees — call chain navigation
- get_taint_flows — structured static taint results
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

DATAFLOW_TOOLS = [
    t for t in get_tool_definitions()
    if t["name"] in (
        "read_file", "grep_search",
        "lookup_function", "find_callers", "find_callees",
        "get_taint_flows",
    )
]

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

DATAFLOW_SYSTEM_PROMPT = """You are the **DataFlow Analyst**, a security researcher specializing in tracing attacker-controlled data through source code.

## Mission
You are given an **entry point** — an attacker-accessible function or endpoint. Your job is to trace how data flows from this entry point to **security-sensitive sinks** (dangerous functions, file operations, database queries, etc.).

## Your Method

### Step 1: Read the entry point
Use `read_file` to read the source code at the entry point's location. Understand what parameters the function accepts.

### Step 2: Identify how input is used
- Use `grep_search` to find imports and references
- Use `lookup_function` to find related functions
- Use `find_callees` to see what the entry point calls
- Use `find_callers` to understand the broader call chain

### Step 3: Trace the data path
For each parameter/input at the entry point:
1. Where does it get stored or passed?
2. What transformations happen?
3. What functions does it flow into?
4. Does it reach a security-sensitive sink?

### Step 4: Check for validation
Along each path, note:
- Input validation or sanitization
- Type checking or casting
- Authentication/authorization checks
- Any guard that could block exploitation

### Step 5: Query static analysis
Use `get_taint_flows` to see if the static analyzer already found taint paths in related code.

## Security-sensitive sinks to watch for
- **Code execution**: eval(), exec(), os.system(), subprocess.Popen()
- **SQL**: execute(), query(), rawQuery(), cursor.execute()
- **Path traversal**: open(), read_file(), write_file(), os.path.join()
- **XSS**: innerHTML, dangerouslySetInnerHTML, document.write()
- **Command injection**: Runtime.exec(), ProcessBuilder, subprocess.call()
- **File upload**: save(), upload(), write()
- **Deserialization**: pickle.loads(), yaml.load(), unserialize()
- **Insecure crypto**: custom encryption, weak algorithms, hardcoded keys

## Rules
1. Trace paths thoroughly — an incomplete trace is worse than no trace
2. For each path, identify the exact file:line of the sink
3. Note intermediate processing steps (formatting, encoding, escaping)
4. If a path has validation, describe what it checks and whether it's sufficient
5. If no exploitable path exists, output an empty paths list — do not fabricate
6. Output only the JSON block

## Output Format
```json
{
  "entry_point_id": "id-of-the-entry-point",
  "paths": [
    {
      "sink_type": "sql_injection",
      "sink_file": "src/repository/UserRepo.java",
      "sink_line": 85,
      "sink_function": "findUser",
      "description": "Entry point parameter `username` flows unsanitized into SQL query",
      "path_steps": [
        {"file": "src/controller/AuthController.java", "line": 42, "detail": "Entry point receives `username` from request body"},
        {"file": "src/controller/AuthController.java", "line": 45, "detail": "Passed directly to authService.login(username, password)"},
        {"file": "src/service/AuthService.java", "line": 30, "detail": "Calls userRepo.findUser(username)"},
        {"file": "src/repository/UserRepo.java", "line": 85, "detail": "String concatenation into SQL query: SELECT * FROM users WHERE username='\" + username + \"'"}
      ],
      "has_validation": false,
      "confidence": "high"
    }
  ]
}
```

If no data flow paths were found, output:
```json
{"entry_point_id": "entry-id", "paths": []}
```"""


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------


class DataFlowPathStep(BaseModel):
    """A single step in a data flow path."""
    file: str = ""
    line: int = 0
    detail: str = ""


class DataFlowPath(BaseModel):
    """A complete data flow path from entry point to sink."""
    sink_type: str = ""
    sink_file: str = ""
    sink_line: int = 0
    sink_function: str = ""
    description: str = ""
    path_steps: list[DataFlowPathStep] = Field(default_factory=list)
    has_validation: bool = False
    confidence: str = "medium"


class DataFlowOutput(BaseModel):
    """Full output from one DataFlow Agent invocation."""
    entry_point_id: str = ""
    paths: list[DataFlowPath] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# DataFlowAgent
# ---------------------------------------------------------------------------


class DataFlowAgent(BaseAgent):
    """Traces data flow from an entry point to security-sensitive sinks.

    Usage::

        agent = DataFlowAgent()
        response = agent.run({
            "entry_point_id": "ep-001",
            "entry_point": {"type": "http_endpoint", "path": "/api/login", ...},
            "project_path": "/path/to/project",
        }, llm)
        state.register_result("dataflow", params, response.output)
    """

    agent_id = "dataflow"
    system_prompt = DATAFLOW_SYSTEM_PROMPT
    tools = DATAFLOW_TOOLS
    output_schema = DataFlowOutput

    DEFAULT_LLM_KWARGS: dict[str, Any] = {"max_tokens": 4096}

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def _parse_output(
        self,
        content: str,
        tool_results: list[ToolResult],
    ) -> dict[str, Any]:
        """Extract a ``DataFlowOutput``-compatible dict from LLM response."""
        if not content:
            logger.warning("DataFlowAgent: empty content, returning empty output.")
            return {"entry_point_id": "", "paths": []}

        raw = self._extract_json(content)
        if not raw:
            logger.warning(
                "DataFlowAgent: no JSON block found in LLM output, "
                "trying content as-is."
            )
            raw = content

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning(
                "DataFlowAgent: JSON decode failed: %s. content=%s",
                exc,
                content[:300],
            )
            return {"entry_point_id": "", "paths": []}

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
        """Keep only keys that ``DataFlowOutput`` understands."""
        allowed = DataFlowOutput.model_fields.keys()
        normalised: dict[str, Any] = {}
        for k in allowed:
            if k in parsed:
                normalised[k] = parsed[k]
            elif k == "paths":
                normalised[k] = []

        # Prune unknown fields and fill defaults for each path
        path_allowed = DataFlowPath.model_fields.keys()
        step_allowed = DataFlowPathStep.model_fields.keys()

        cleaned_paths: list[dict[str, Any]] = []
        for path in normalised.get("paths", []):
            entry: dict[str, Any] = {}
            for k in path_allowed:
                if k in path:
                    entry[k] = path[k]
                elif k == "path_steps":
                    entry[k] = []
                elif k == "has_validation":
                    entry[k] = False
                elif k == "confidence":
                    entry[k] = "medium"
                else:
                    entry[k] = ""

            # Clean path steps
            cleaned_steps: list[dict[str, Any]] = []
            for step in entry.get("path_steps", []):
                s: dict[str, Any] = {}
                for k in step_allowed:
                    if k in step:
                        s[k] = step[k]
                    else:
                        s[k] = ""
                cleaned_steps.append(s)
            entry["path_steps"] = cleaned_steps

            cleaned_paths.append(entry)

        normalised["paths"] = cleaned_paths
        return normalised
