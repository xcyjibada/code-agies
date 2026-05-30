"""State machine engine — Brain-driven multi-agent code audit orchestration.

Architecture:
  Brain (LLM decision loop) → batch dispatch → Parallel Runner → Agents → aggregate
  Each agent is a specialized LLM call with focused prompt + deterministic tools.

Module layout:
  v2/   — xint-style per-function bulk analysis pipeline (Brain + Agents + Director)
  graph/  — Joern/tree-sitter graph generators (v3 graph analysis engine)
"""

from .v2.state import ProjectState
from .v2.brain import Brain
from .v2.runner import Runner, AgentCall, AgentResult

__all__ = ["ProjectState", "Brain", "Runner", "AgentCall", "AgentResult"]
