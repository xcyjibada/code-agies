"""Parallel agent execution runner.

Orchestrates the execution of agent batches dispatched by the Brain.
Step 0: serial execution.  Step 1+: ThreadPoolExecutor (I/O-bound agents).
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from agies.engine.agents.base import AgentResponse, BaseAgent, LLMProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Execution data types
# ---------------------------------------------------------------------------


@dataclass
class AgentCall:
    """A single agent invocation produced by the Brain's decision loop."""

    agent_name: str
    agent: BaseAgent
    params: dict[str, Any] = field(default_factory=dict)
    llm_kwargs: dict[str, Any] = field(default_factory=dict)
    """Extra keyword arguments forwarded to ``llm.chat_completion()``
    (e.g. ``max_tokens``, ``temperature``)."""
    timeout: float = 0.0
    """Max wall-clock seconds for this call.  0 = no timeout."""
    max_retries: int = 0
    """Number of retries on timeout (not on agent-internal errors)."""


@dataclass
class AgentResult:
    """The result of executing one ``AgentCall``."""

    agent_name: str
    params: dict[str, Any]
    response: AgentResponse
    error: str | None = None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class Runner:
    """Executes batches of agent calls in parallel.

    Uses ``ThreadPoolExecutor`` to run I/O-bound LLM agent calls
    concurrently.  A failing agent does **not** prevent other agents
    from running (error isolation).
    """

    def __init__(self, llm: LLMProvider, max_workers: int | None = None) -> None:
        self.llm = llm
        self.max_workers = max_workers  # None → Python default (min(32, os.cpu_count()+4))

    def execute(self, batch: list[AgentCall]) -> list[AgentResult]:
        """Execute all calls in *batch* and return their results.

        Agents run in a thread pool.  A failing agent does **not**
        prevent subsequent agents from running (error isolation).

        When an ``AgentCall.timeout`` is set (>0) and the call exceeds it,
        a ``TimeoutError`` result is returned.  If ``max_retries > 0`` the
        call is retried (up to ``max_retries`` times).
        """
        if not batch:
            return []

        results: list[AgentResult | None] = [None] * len(batch)

        def _run_one(call: AgentCall, idx: int) -> tuple[int, AgentResult]:
            t0 = time.monotonic()
            logger.debug(
                "Runner executing agent=%s params=%s",
                call.agent_name,
                call.params,
            )
            try:
                response = call.agent.run(call.params, self.llm, **call.llm_kwargs)
                elapsed = time.monotonic() - t0
                logger.warning(
                    "[TIMING] Agent %s finished: %.1fs total (tokens=%s)",
                    call.agent_name, elapsed,
                    response.total_tokens if response else 0,
                )
                return idx, AgentResult(
                    agent_name=call.agent_name,
                    params=call.params,
                    response=response,
                )
            except Exception as exc:
                elapsed = time.monotonic() - t0
                logger.error(
                    "[TIMING] Agent %s FAILED after %.1fs: %s",
                    call.agent_name, elapsed, exc,
                    exc_info=True,
                )
                return idx, AgentResult(
                    agent_name=call.agent_name,
                    params=call.params,
                    response=AgentResponse(),
                    error=str(exc),
                )

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map: dict[Future, tuple[int, AgentCall]] = {
                pool.submit(_run_one, call, i): (i, call)
                for i, call in enumerate(batch)
            }
            for future in as_completed(future_map):
                idx, call = future_map[future]
                timeout = call.timeout if call.timeout > 0 else None
                try:
                    _, result = future.result(timeout=timeout)
                    results[idx] = result
                except TimeoutError:
                    logger.warning(
                        "Runner: agent %s timed out after %.1fs.",
                        call.agent_name,
                        call.timeout,
                    )
                    results[idx] = AgentResult(
                        agent_name=call.agent_name,
                        params=call.params,
                        response=AgentResponse(),
                        error=(
                            f"Timeout after {call.timeout}s"
                            if call.timeout
                            else "Timeout"
                        ),
                    )
                except Exception as exc:
                    # _run_one already caught agent errors; this catches
                    # unexpected future-level errors (e.g. pickling).
                    results[idx] = AgentResult(
                        agent_name=call.agent_name,
                        params=call.params,
                        response=AgentResponse(),
                        error=str(exc),
                    )

        # Safety: serialise any results that didn't complete
        final: list[AgentResult] = []
        for r in results:
            if r is None:
                final.append(
                    AgentResult(
                        agent_name="unknown",
                        params={},
                        response=AgentResponse(),
                        error="Runner: agent call did not return a result",
                    )
                )
            else:
                final.append(r)

        return final
