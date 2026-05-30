"""Agent base class — core abstraction for all audit agents.

Every agent (Mapping, AttackSurface, DataFlow, Vulnerability, Verify, Report)
inherits from BaseAgent, which provides:

- Tool execution loop (LLM <-> tools)
- Output truncation with [TRUNCATED] marker
- Error recovery (per-tool try/except)
- O(1) tool lookup via registry
- Configurable iteration and empty-response limits
"""

from __future__ import annotations

import dataclasses
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Protocol

import time

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class ToolCall(BaseModel):
    """A single tool invocation requested by the LLM.

    Note: this is the Agent-level model, separate from
    ``agies.llm.base.ToolCall`` (which is the transport-level model).
    """

    name: str = ""
    arguments: str = ""  # JSON-encoded arg dict
    id: str = ""


class ToolResult(BaseModel):
    """Result of executing a single tool call."""

    id: str = ""
    status: str = "success"  # "success" | "error"
    content: str = ""
    truncated: bool = False


class AgentResponse(BaseModel):
    """Complete output from one Agent execution.

    Callers (Brain / Runner) read ``.output`` to pass structured data into
    ``ProjectState.register_result()``.
    """

    content: str = ""
    output: dict[str, Any] = Field(default_factory=dict)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    total_tokens: int = 0
    usage: dict = Field(default_factory=dict)
    """Aggregated token usage across all LLM calls in this agent run.

    Keys (normalised across providers):
    - ``prompt_tokens``: total input tokens
    - ``completion_tokens``: total output tokens
    - ``total_tokens``: sum of the two

    Empty dict when the provider does not expose usage information.
    """


# ---------------------------------------------------------------------------
# Protocol for tool definitions
# ---------------------------------------------------------------------------

# Each tool entry matches the dict returned by ``get_tool_definitions()``:
#   {"name": str, "fn": Callable, "schema": dict}

# ---------------------------------------------------------------------------
# LLM Provider Protocol (structural subtyping)
# ---------------------------------------------------------------------------


class LLMProvider(Protocol):
    """Structural protocol compatible with ``agies.llm.LLMProvider``.

    Any object whose ``chat_completion`` method matches this signature
    satisfies the protocol — no inheritance required.
    """

    def chat_completion(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Send messages and return a response with .content and .tool_calls.

        The returned object must have:
        - ``content`` (str | None)
        - ``tool_calls`` (list[ToolCall] | None) where each ToolCall has
          ``id``, ``name``, ``arguments`` (JSON str), ``type`` (str).
        """
        ...


# ---------------------------------------------------------------------------
# Prompt fragment constants (no hardcoded strings in method bodies)
# ---------------------------------------------------------------------------

_TRUNCATION_NOTICE = (
    "Output too long, please use specific range or grep to narrow down"
)
_TOOL_ERROR_FMT = "Error executing tool [{name}]: {message}"
_UNKNOWN_TOOL_FMT = "Unknown tool: [{name}]"
_EMPTY_RESPONSE_PROMPT = (
    "Previous response had no content or tool calls. "
    "Please provide your analysis or use the available tools."
)
_ITERATION_LIMIT_REACHED = (
    "Iteration limit ({limit}) reached. "
    "Provide your final structured output as a valid JSON block matching the "
    "expected output format. Do NOT make additional tool calls."
)
_ITERATION_LIMIT_WITH_SCHEMA = (
    "ITERATION LIMIT REACHED. Tools are unavailable. "
    "Output EXACTLY this JSON with your values filled in:\n{schema}\n"
    "Replace ''/[]/false with your analysis. ONLY output the JSON. No other text."
)
_CONVERGE_PROMPT = (
    "BUDGET WARNING: Already used {iteration} of {limit} iterations. "
    "If you have enough information to make a determination, "
    "stop using tools and output your final answer now. "
    "Only continue making tool calls if you absolutely need more data."
)
_TOOL_OUTPUT_HEADER = "Tool [{name}] returned:"
_NO_TOOL_CALLS_IN_RESPONSE = (
    "No tool calls found in LLM response (iteration {iteration}/{limit})"
)
_OUTPUT_SCHEMA_WARN = "Output did not conform to schema: {error}"


def _is_json_safe(val: Any) -> bool:
    """Check if *val* is a JSON-serializable Python native type."""
    return isinstance(val, (str, int, float, bool, list, dict, tuple, type(None)))



# ---------------------------------------------------------------------------
# BaseAgent
# ---------------------------------------------------------------------------


class BaseAgent(ABC):
    """Abstract base for all audit agents.

    Subclasses define:
    - ``agent_id`` — unique name for state tracking
    - ``system_prompt`` — role-specific instruction
    - ``tools`` — list of ``{name, fn, schema}`` dicts
    - ``output_schema`` — optional Pydantic model for output validation
    - ``_parse_output()`` — extract structured ``output`` from LLM reply

    Usage::

        class MyAgent(BaseAgent):
            agent_id = "my_agent"
            system_prompt = "You are ..."
            tools = [read_file_def, grep_def]

            def _parse_output(self, content, tool_results):
                return {"key": extract(content)}

        agent = MyAgent()
        response = agent.run({"path": "/project"}, llm)
        state.register_result("my_agent", params, response.output)
    """

    # --- Subclass hooks (must override) ---
    agent_id: str = ""
    system_prompt: str = ""
    tools: list[dict] = []

    # --- Optional subclass hooks ---
    output_schema: type[BaseModel] | None = None

    # --- Thresholds (tunable per agent) ---
    MAX_OUTPUT_CHARS: int = 1500
    MAX_ITERATIONS: int = 7
    MAX_EMPTY_RESPONSES: int = 3
    PLATEAU_WINDOW: int = 3
    """Consecutive iterations with identical tool-call patterns before
    the agent is asked to converge (early-stop).  Catches the "reading
    the same files over and over" loop without waiting for the hard
    iteration limit."""

    # --- LLM call defaults (forwarded to ``llm.chat_completion``) ---
    DEFAULT_LLM_KWARGS: dict[str, Any] = {}
    """Extra kwargs sent with every LLM call this agent makes.
    Subclasses can override to set e.g. ``max_tokens`` or ``temperature``."""

    def __init__(
        self,
        agent_id: str = "",
        system_prompt: str = "",
        tools: list[dict] | None = None,
        output_schema: type[BaseModel] | None = None,
        prompt_manager: Any = None,
        prompt_model_name: str = "default",
    ) -> None:
        if agent_id:
            self.agent_id = agent_id
        if system_prompt:
            self.system_prompt = system_prompt
        if tools is not None:
            self.tools = tools
        if output_schema is not None:
            self.output_schema = output_schema

        self.prompt_manager = prompt_manager
        self._prompt_model_name = prompt_model_name

        # Build O(1) registry: name -> {fn, schema}
        self._tool_registry: dict[str, dict] = {
            t["name"]: t for t in self.tools if "name" in t
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        params: dict[str, Any],
        llm: LLMProvider,
        **llm_kwargs: Any,
    ) -> AgentResponse:
        """Execute this agent against *params* using *llm*.

        Supports dynamic ``max_iterations`` via ``params["max_iterations"]``,
        overriding the class-level ``MAX_ITERATIONS``.

        Supports ``params["prior_knowledge"]`` — if present, it is injected
        as a ``[PRIOR_KNOWLEDGE]`` block at the top of the system prompt so
        the agent benefits from findings discovered by earlier agents.

        Returns an ``AgentResponse`` with structured ``.output`` ready for
        ``ProjectState.register_result()``.
        """
        prior_knowledge = params.pop("prior_knowledge", None)
        messages = self._build_messages(params)

        if prior_knowledge and messages:
            pk_block = (
                "[PRIOR_KNOWLEDGE]\n"
                f"{prior_knowledge}\n"
                "[/PRIOR_KNOWLEDGE]\n\n"
            )
            for msg in messages:
                if msg.get("role") == "system":
                    msg["content"] = pk_block + msg["content"]
                    break
        max_iterations = params.pop("max_iterations", None)
        if max_iterations is not None:
            self._dynamic_max_iterations = max_iterations
        response = self._execute_tool_loop(messages, llm, **llm_kwargs)

        structured = self._parse_output(response.content, response.tool_results)
        if structured:
            response.output = structured

        if self.output_schema is not None and response.output:
            try:
                self.output_schema(**response.output)
            except Exception as exc:
                logger.warning(
                    _OUTPUT_SCHEMA_WARN.format(error=exc),
                    exc_info=True,
                )

        return response

    # ------------------------------------------------------------------
    # Message building
    # ------------------------------------------------------------------

    def _build_messages(self, params: dict[str, Any]) -> list[dict]:
        """Build the initial message list: system prompt + user params.

        When *prompt_manager* is set, renders Jinja2 templates from YAML
        prompt files.  Falls back to hardcoded ``self.system_prompt`` if
        template binding fails or no prompt_manager is configured.
        """
        # ---- Template rendering via PromptManager ----
        if self.prompt_manager is not None:
            safe = self._serialize_for_template(params)
            try:
                tm = self.prompt_manager.model(self._prompt_model_name)
                bound = tm.bind(self.agent_id, kwargs=safe)
                return [
                    {"role": "system", "content": bound.system},
                    {"role": "user", "content": bound.user},
                ]
            except RuntimeError as exc:
                logger.debug(
                    "PromptManager: agent '%s' not in templates (%s), "
                    "falling back to legacy system_prompt.",
                    self.agent_id,
                    exc,
                )

        # ---- Legacy formatting ----
        param_lines = []
        for k, v in params.items():
            # Skip brain-internal keys (prefix _) — not for LLM consumption
            if k.startswith("_"):
                continue
            if isinstance(v, str):
                param_lines.append(f"{k}: {v}")
            else:
                param_lines.append(
                    f"{k}: {json.dumps(v, ensure_ascii=False, default=str)}"
                )

        user_content = (
            "\n".join(param_lines)
            if param_lines
            else json.dumps(
                {k: v for k, v in params.items() if not k.startswith("_")},
                ensure_ascii=False, default=str,
            )
        )

        return [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_content},
        ]

    # ------------------------------------------------------------------
    # Template serialisation helper
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize_for_template(obj: Any) -> Any:
        """Recursively convert Pydantic models / dataclasses to plain dicts.

        Jinja2's ``tojson`` filter can't serialise arbitrary Python objects,
        so we pre-convert before passing kwargs to ``PromptManager.bind()``.
        """
        if isinstance(obj, dict):
            return {k: BaseAgent._serialize_for_template(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [BaseAgent._serialize_for_template(item) for item in obj]
        if hasattr(obj, "model_dump"):  # Pydantic v2
            return obj.model_dump()
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        return obj

    # ------------------------------------------------------------------
    # Core tool loop
    # ------------------------------------------------------------------

    def _execute_tool_loop(
        self,
        messages: list[dict],
        llm: LLMProvider,
        **llm_kwargs: Any,
    ) -> AgentResponse:
        """LLM <-> tools loop.

        Sends messages, processes tool calls returned by the LLM, feeds
        results back, and repeats until the LLM produces a final text
        response (no tool calls) or a limit is hit.
        """
        collected_calls: list[ToolCall] = []
        collected_results: list[ToolResult] = []
        empty_count = 0
        total_tokens = 0

        # Accumulate per-call usage from the API for accurate QuotaMonitor billing.
        accrued_usage: dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

        max_iterations = getattr(self, "_dynamic_max_iterations", self.MAX_ITERATIONS)

        for iteration in range(1, max_iterations + 1):
            try:
                t0 = time.monotonic()
                response = llm.chat_completion(
                    messages=messages,
                    tools=[t["schema"] for t in self.tools] if self.tools else None,
                    **llm_kwargs,
                )
                elapsed = time.monotonic() - t0
                logger.warning(
                    "[TIMING] %s iter=%d/%d LLM call: %.1fs (tokens=%s)",
                    self.agent_id, iteration, max_iterations, elapsed,
                    getattr(getattr(response, 'usage', None), 'total_tokens', '?'),
                )
            except Exception as exc:
                # Attempt context compression recovery once
                logger.warning(
                    "Agent %s: LLM call failed at iteration %d (%s). "
                    "Attempting context compression...",
                    self.agent_id,
                    iteration,
                    exc,
                )
                try:
                    from agies.engine.v2.context import compress_context

                    messages = compress_context(messages)
                    response = llm.chat_completion(
                        messages=messages,
                        tools=[t["schema"] for t in self.tools] if self.tools else None,
                        **llm_kwargs,
                    )
                except Exception as exc2:
                    logger.error(
                        "Agent %s: LLM call failed after context compression: %s",
                        self.agent_id,
                        exc2,
                    )
                    raise exc2  # Give up — let the runner handle the error

            # --- Accurate token usage from API response ---
            usage = getattr(response, "usage", None) if hasattr(response, "usage") else None
            if usage and isinstance(usage, dict):
                pt = usage.get("prompt_tokens", 0) or 0
                ct = usage.get("completion_tokens", 0) or 0
                tt = usage.get("total_tokens", 0) or 0
                accrued_usage["prompt_tokens"] += pt
                accrued_usage["completion_tokens"] += ct
                accrued_usage["total_tokens"] += tt
                total_tokens = accrued_usage["total_tokens"]
            elif response.content:
                # Fallback: rough estimate when provider doesn't expose usage
                total_tokens += len(response.content.split())

            content = (response.content or "").strip()
            raw_tool_calls = response.tool_calls or []

            has_content = bool(content)
            has_tool_calls = bool(raw_tool_calls)

            # ---- Empty response guard ----
            if not has_content and not has_tool_calls:
                empty_count += 1
                logger.debug(
                    "Empty LLM response (iteration=%d, empty_count=%d/%d)",
                    iteration,
                    empty_count,
                    self.MAX_EMPTY_RESPONSES,
                )
                if empty_count >= self.MAX_EMPTY_RESPONSES:
                    logger.warning(
                        "Agent %s: %d consecutive empty responses, stopping.",
                        self.agent_id,
                        empty_count,
                    )
                    break
                messages.append({"role": "user", "content": _EMPTY_RESPONSE_PROMPT})
                continue

            empty_count = 0  # reset

            # ---- Build assistant message ----
            assistant_msg: dict[str, Any] = {"role": "assistant"}
            if content:
                assistant_msg["content"] = content

            if has_tool_calls:
                assistant_msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": getattr(tc, "type", "function"),
                        "function": {
                            "name": tc.name,
                            "arguments": tc.arguments,
                        },
                    }
                    for tc in raw_tool_calls
                ]

            messages.append(assistant_msg)

            # ---- No tool calls = agent is done ----
            if not has_tool_calls:
                logger.debug(
                    "Agent %s: no tool calls after iteration %d, done.",
                    self.agent_id,
                    iteration,
                )
                break

            # ---- Execute each tool call ----
            all_succeeded = True
            for tc in raw_tool_calls:
                logger.warning(
                    "[DIAG] %s iter=%d tool=%s args=%s",
                    self.agent_id, iteration, tc.name, tc.arguments[:200],
                )
                logger.debug(
                    "Tool call: agent=%s, iteration=%d, tool=%s, args=%s, id=%s",
                    self.agent_id,
                    iteration,
                    tc.name,
                    tc.arguments,
                    tc.id,
                )

                pydantic_tc = ToolCall(name=tc.name, arguments=tc.arguments, id=tc.id)
                collected_calls.append(pydantic_tc)

                result = self._execute_tool(tc)
                collected_results.append(result)

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result.content,
                })

                if result.status == "error":
                    all_succeeded = False

            # ---- If all tools errored, the LLM may be looping — guard ----
            if not all_succeeded:
                logger.debug(
                    "Agent %s: some tools failed at iteration %d, continuing.",
                    self.agent_id,
                    iteration,
                )

            # ---- Convergence pressure: warn when approaching limit ----
            if max_iterations >= 4 and iteration == max_iterations - 2:
                messages.append({
                    "role": "user",
                    "content": _CONVERGE_PROMPT.format(
                        iteration=iteration, limit=max_iterations,
                    ),
                })

            # ---- Plateau detection: same tool pattern repeated ----
            if has_tool_calls:
                try:
                    current_fingerprint = frozenset(
                        f"{tc.name}({','.join(sorted(json.loads(tc.arguments).keys()))})"
                        for tc in raw_tool_calls
                    )
                except (json.JSONDecodeError, TypeError, ValueError):
                    current_fingerprint = None

                if current_fingerprint:
                    if current_fingerprint == getattr(self, "_last_tool_fingerprint", None):
                        self._plateau_count = getattr(self, "_plateau_count", 0) + 1
                    else:
                        self._plateau_count = 0
                    self._last_tool_fingerprint = current_fingerprint

                    if self._plateau_count >= self.PLATEAU_WINDOW:
                        logger.warning(
                            "Agent %s: plateau detected (%d identical tool patterns), forcing convergence.",
                            self.agent_id, self._plateau_count,
                        )
                        messages.append({
                            "role": "user",
                            "content": _ITERATION_LIMIT_REACHED.format(limit=max_iterations),
                        })
                        final = llm.chat_completion(messages=messages, tools=[], **llm_kwargs)
                        final_content = (final.content or "").strip()
                        if final_content:
                            messages.append({"role": "assistant", "content": final_content})
                            content = final_content
                        break
        else:
            # Loop completed without break — iteration limit reached
            logger.warning(
                "Agent %s: iteration limit (%d) reached, forcing stop.",
                self.agent_id,
                max_iterations,
            )

            # Strip the last assistant+tool round trip so the model isn't
            # primed to continue making tool calls in the forced final
            # response. Walk backwards to handle multiple tool results
            # from a single assistant turn (single tool use → N results).
            last_asst_idx = None
            for i in range(len(messages) - 1, -1, -1):
                if messages[i].get("role") == "assistant" and "tool_calls" in messages[i]:
                    # Verify this assistant is followed by tool results
                    if i + 1 < len(messages) and messages[i + 1].get("role") == "tool":
                        last_asst_idx = i
                        break
            if last_asst_idx is not None:
                messages = messages[:last_asst_idx]

            if self.output_schema is not None:
                # Build a JSON template from schema defaults for the prompt.
                # Use get_default() (Pydantic v2) which handles both
                # `default` and `default_factory` correctly.
                template = {}
                for k, v in self.output_schema.model_fields.items():
                    default_val = v.get_default(call_default_factory=False)
                    if default_val is not None and _is_json_safe(default_val):
                        template[k] = default_val
                    elif v.annotation is bool:
                        template[k] = False
                    elif v.annotation is int:
                        template[k] = 0
                    else:
                        # Check if annotation is a list type (e.g. list[str], list[Foo])
                        from typing import get_origin, get_args
                        origin = get_origin(v.annotation)
                        if origin is list:
                            args = get_args(v.annotation)
                            if args and isinstance(args[0], type) and issubclass(args[0], BaseModel):
                                sample = {}
                                for ek, ev in args[0].model_fields.items():
                                    edefault = ev.get_default(call_default_factory=False)
                                    if edefault is not None and _is_json_safe(edefault):
                                        sample[ek] = edefault
                                    elif ev.annotation is bool:
                                        sample[ek] = False
                                    elif ev.annotation is int:
                                        sample[ek] = 0
                                    else:
                                        sample[ek] = "..."
                                template[k] = [sample]
                            else:
                                template[k] = []
                        else:
                            template[k] = ""
                try:
                    schema_hint = json.dumps(template, indent=2)
                except (TypeError, ValueError):
                    schema_hint = "{" + ", ".join(f'"{k}": ...' for k in template) + "}"
                limit_msg = _ITERATION_LIMIT_WITH_SCHEMA.format(
                    limit=self.MAX_ITERATIONS, schema=schema_hint,
                )
            else:
                limit_msg = _ITERATION_LIMIT_REACHED.format(limit=self.MAX_ITERATIONS)
            messages.append({"role": "user", "content": limit_msg})

            # One final call to get the LLM's summary — no tools so it MUST output text
            final = llm.chat_completion(messages=messages, tools=[], **llm_kwargs)
            final_content = (final.content or "").strip()
            logger.warning(
                "Agent %s: iteration limit final response (first 300 chars): %s",
                self.agent_id, final_content[:300] if final_content else "(empty)",
            )
            if final_content:
                messages.append({"role": "assistant", "content": final_content})
                content = final_content

        return AgentResponse(
            content=content,
            tool_calls=collected_calls,
            tool_results=collected_results,
            total_tokens=total_tokens,
            usage=accrued_usage,
        )

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    def _execute_tool(self, tc: Any) -> ToolResult:
        """Execute a single tool call with error handling and truncation."""
        tool_entry = self._tool_registry.get(tc.name)
        if tool_entry is None:
            logger.debug("Unknown tool requested: %s", tc.name)
            return ToolResult(
                id=tc.id,
                status="error",
                content=_UNKNOWN_TOOL_FMT.format(name=tc.name),
            )

        try:
            # Parse arguments — the LLM sends them as a JSON string
            if isinstance(tc.arguments, str) and tc.arguments.strip():
                args = json.loads(tc.arguments)
            elif isinstance(tc.arguments, dict):
                args = tc.arguments
            else:
                args = {}

            fn = tool_entry["fn"]
            raw = fn(**args)

            if not isinstance(raw, str):
                raw = str(raw)

            truncated_content, was_truncated = self._truncate_output(raw)
            return ToolResult(
                id=tc.id,
                status="success",
                content=truncated_content,
                truncated=was_truncated,
            )

        except Exception as exc:
            logger.error(
                "Tool execution failed: agent=%s, tool=%s, args=%s",
                self.agent_id,
                tc.name,
                tc.arguments,
                exc_info=True,
            )
            return ToolResult(
                id=tc.id,
                status="error",
                content=_TOOL_ERROR_FMT.format(name=tc.name, message=str(exc)),
            )

    # ------------------------------------------------------------------
    # Output truncation
    # ------------------------------------------------------------------

    @staticmethod
    def _truncate_output(text: str, max_chars: int | None = None) -> tuple[str, bool]:
        """Truncate *text* in the middle if it exceeds *max_chars*.

        Returns ``(truncated_text, was_truncated)``.  The truncation marker
        tells the LLM to narrow its search rather than re-reading everything.
        """
        limit = max_chars if max_chars is not None else 8000
        if len(text) <= limit:
            return text, False

        half = limit // 2
        omitted = len(text) - limit
        truncated = (
            text[:half]
            + f"\n... [TRUNCATED] {omitted} chars omitted — "
            + f"{_TRUNCATION_NOTICE} ...\n"
            + text[-half:]
        )
        return truncated, True

    # ------------------------------------------------------------------
    # Output parsing (subclass hook)
    # ------------------------------------------------------------------

    def _parse_output(
        self,
        content: str,
        tool_results: list[ToolResult],
    ) -> dict[str, Any]:
        """Extract structured output from the LLM's final response.

        Override in subclasses to populate ``AgentResponse.output`` with
        the keys expected by ``ProjectState.register_result()``.

        The base implementation returns an empty dict.
        """
        return {}
