"""Phase D agent pool — parallel Intent extraction + contradiction detection.

Three agent types run in parallel:

1. **IntentAgent** — reads 4-5 functions, outputs "developer intent" pseudocode
2. **Merge** — deterministically orders Intent outputs by node index
3. **LogicAgent** — reads pseudocode chain, finds intent/reality contradictions

Design rationale in ``docs/v3/plan.md`` Phase D.
"""

from agies.engine.v3.agents.intent_agent import IntentAgent, IntentAgentTask
from agies.engine.v3.agents.logic_agent import LogicAgent
from agies.engine.v3.agents.merge import MergeLayer
from agies.engine.v3.agents.path_code_loader import PathCodeLoader
from agies.engine.v3.agents.aggregator import PathResultAggregator
from agies.engine.v3.agents.synthesis_agent import SynthesisAgent, SynthesisHypothesis, SynthesisResult

__all__ = [
    "IntentAgent",
    "IntentAgentTask",
    "LogicAgent",
    "MergeLayer",
    "PathCodeLoader",
    "PathResultAggregator",
    "SynthesisAgent",
    "SynthesisHypothesis",
    "SynthesisResult",
]
