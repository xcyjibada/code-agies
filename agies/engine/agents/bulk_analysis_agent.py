"""Bulk Analysis Agent — runs Phase 1 parallel per-function LLM analysis.

Wraps the sync ``agies.engine.analysis.bulk`` module into a BaseAgent
so the Brain can dispatch it like any other agent.
"""

from __future__ import annotations

import logging
from typing import Any

from agies.engine.agents.base import AgentResponse, BaseAgent
from agies.engine.analysis.bulk import analyze_single_functions
from agies.engine.sourcer.models import BulkAnalysisOutput

logger = logging.getLogger(__name__)


class BulkAnalysisAgent(BaseAgent):
    """Phase 1 bulk analysis — parallel LLM calls per function.

    Non-interactive: no tools, just a single batched LLM pass over all
    functions in the FunctionIndex.
    """

    agent_id = "bulk_analysis"
    system_prompt = ""
    tools = []

    MAX_OUTPUT_CHARS: int = 2000
    DEFAULT_LLM_KWARGS: dict[str, Any] = {"max_tokens": 1024}

    def run(
        self,
        params: dict[str, Any],
        llm: Any = None,
        **llm_kwargs: Any,
    ) -> AgentResponse:
        """Run Phase 1 bulk analysis via ThreadPoolExecutor."""
        index = params.get("function_index")
        if index is None:
            return AgentResponse(
                content="No FunctionIndex provided",
                output={
                    "candidates": [],
                    "total_functions_analyzed": 0,
                    "total_llm_calls": 0,
                },
            )

        result: BulkAnalysisOutput = analyze_single_functions(
            index,
            llm,
            priority_map=params.get("priority_map"),
            max_functions=params.get("max_functions", 0),
            function_context=params.get("function_context"),
        )

        return AgentResponse(
            content=(
                f"Bulk analysis complete: {result.total_functions_analyzed} "
                f"functions → {len(result.candidates)} candidates"
            ),
            output={
                "candidates": result.candidates,
                "total_functions_analyzed": result.total_functions_analyzed,
                "total_llm_calls": result.total_llm_calls,
            },
        )
