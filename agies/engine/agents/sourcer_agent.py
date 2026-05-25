"""Sourcer Agent — builds FunctionIndex deterministically (no LLM).

Runs after Mapping Agent to parse ALL project files with tree-sitter.
Produces a FunctionIndex that feeds into Phase 1 bulk analysis.
"""

from __future__ import annotations

from typing import Any

from agies.engine.agents.base import AgentResponse, BaseAgent
from agies.engine.sourcer.loader import build_index


class SourcerAgent(BaseAgent):
    """Deterministic agent that builds a FunctionIndex from project source.

    Overrides ``run()`` to skip the LLM entirely — this is a pure
    tree-sitter based extraction step.
    """

    agent_id = "sourcer"
    system_prompt = ""  # No LLM needed

    def run(
        self,
        params: dict[str, Any],
        llm: Any = None,
        **llm_kwargs: Any,
    ) -> AgentResponse:
        project_path = params.get("project_path", "")
        full_index_paths: set[str] | None = params.get("full_index_paths")
        index = build_index(project_path, full_index_paths=full_index_paths)
        return AgentResponse(
            content=f"Built FunctionIndex: {index.summary()}",
            output={"function_index": index},
        )
