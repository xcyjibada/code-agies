"""Verification pipeline — hallucination defense + attacker control analysis for LLM audit findings.

Provides multi-stage validation:
1. File existence + boundary checks (no LLM)
2. Line number + code snippet matching (no LLM)
3. Contradiction detection vs static analysis (no LLM)
4. Cross-model verification with stronger LLM (optional)
5. Attacker control verification — 6-dimension pipeline (P0/P1) + exploitability scoring

Usage:
    from agies.verification import VerificationPipeline

    pipeline = VerificationPipeline(target_root="/path/to/target")
    verified_findings = pipeline.run(findings)
"""

from .pipeline import VerificationPipeline
from .evidence import VerificationResult, Evidence, add_verification
from .file_check import FileExistenceValidator, LineNumberValidator
from .contradiction import ContradictionDetector
from .cross_model import CrossModelVerifier
from .attacker_control import (
    AttackerControlVerifier,
    AttackerControlResult,
    ValidatorResult,
    ExecutionContextValidator,
    TrustBoundaryValidator,
    ExternalReachabilityValidator,
    ValidationChainValidator,
    ThreadModelValidator,
    SemanticPatternValidator,
)
from .exploitability import assess_exploitability, compute_exploitability
from .language_patterns import get_language_patterns

__all__ = [
    "VerificationPipeline",
    "VerificationResult",
    "Evidence",
    "add_verification",
    "FileExistenceValidator",
    "LineNumberValidator",
    "ContradictionDetector",
    "CrossModelVerifier",
    "AttackerControlVerifier",
    "AttackerControlResult",
    "ValidatorResult",
    "ExecutionContextValidator",
    "TrustBoundaryValidator",
    "ExternalReachabilityValidator",
    "ValidationChainValidator",
    "ThreadModelValidator",
    "SemanticPatternValidator",
    "assess_exploitability",
    "compute_exploitability",
    "get_language_patterns",
]
