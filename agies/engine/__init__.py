"""State machine engine — Brain-driven multi-agent code audit orchestration.

Architecture:
  Brain (LLM decision loop) → batch dispatch → Parallel Runner → Agents → aggregate
  Each agent is a specialized LLM call with focused prompt + deterministic tools.
"""

from .state import ProjectState
from .brain import Brain
from .runner import Runner, AgentCall, AgentResult

__all__ = ["ProjectState", "Brain", "Runner", "AgentCall", "AgentResult"]
