"""Evidence chain data model."""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Evidence:
    """A single piece of evidence supporting or refuting a finding."""
    type: str       # "file_exists", "line_match", "code_match", "static_analysis", "llm_verification"
    status: str     # "passed", "failed", "uncertain"
    detail: str     # Human-readable explanation
    source: str     # "file_check", "line_check", "contradiction", "cross_model"


@dataclass
class VerificationResult:
    """Verification metadata attached to each finding."""
    file_exists: bool = False
    file_corrected: bool = False
    original_path: str = ""
    line_valid: bool = False
    code_match: bool = False
    contradictions: list[str] = field(default_factory=list)
    verification_status: str = "unverified"  # unverified | verified | uncertain | contradicted
    evidence_chain: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file_exists": self.file_exists,
            "file_corrected": self.file_corrected,
            "original_path": self.original_path,
            "line_valid": self.line_valid,
            "code_match": self.code_match,
            "contradictions": self.contradictions,
            "verification_status": self.verification_status,
            "evidence_chain": self.evidence_chain,
        }


def add_verification(finding: dict, verification: VerificationResult):
    """Attach verification metadata to a finding dict."""
    finding["verification"] = verification.to_dict()
