# Capability Discovery — Feature → Question → Assumption pipeline
#
# New analysis phase: before any AST/sink/source analysis,
# identify what product-level CAPABILITIES the code introduces.
#
# Pipeline:
#   Capability Discovery (AST + heuristics)
#         ↓
#   Question Generation (feature_questions.yaml)
#         ↓
#   Assumption Extraction (invariant_library.yaml)
#         ↓
#   Contradiction Detection (cross-feature)
#
# References:
#   docs/boxIdea.md — full design rationale
#   capability/data/feature_taxonomy.yaml — feature definitions
#   capability/data/invariant_library.yaml — invariant definitions
#   capability/data/feature_questions.yaml — question mappings

from agies.engine.v3.capability.taxonomy import (
    Feature,
    FeatureTaxonomy,
    load_taxonomy,
)
from agies.engine.v3.capability.invariants import (
    Invariant,
    InvariantLibrary,
    load_invariant_library,
)
from agies.engine.v3.capability.questions import (
    FeatureQuestion,
    QuestionBank,
    load_question_bank,
)
from agies.engine.v3.capability.discovery import (
    CapabilityDiscoveryEngine,
    CapabilityResult,
    discover_capabilities,
)
from agies.engine.v3.capability.agent import (
    CapabilityAgent,
    CapabilityContext,
    CapabilityAnalysis,
    GeneratedQuestion,
    build_context,
)

__all__ = [
    "Feature",
    "FeatureTaxonomy",
    "load_taxonomy",
    "Invariant",
    "InvariantLibrary",
    "load_invariant_library",
    "FeatureQuestion",
    "QuestionBank",
    "load_question_bank",
    "CapabilityDiscoveryEngine",
    "CapabilityResult",
    "discover_capabilities",
    "CapabilityAgent",
    "CapabilityContext",
    "CapabilityAnalysis",
    "GeneratedQuestion",
    "build_context",
]
