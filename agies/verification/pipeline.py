"""Verification pipeline orchestrator.

Composes all verification stages into a single pass over findings:

1. File existence + boundary check
2. Line number + code snippet validation
3. Static analysis contradiction detection
4. Cross-model verification (stronger LLM) — optional
5. Attacker control verification (6-dimension pipeline) — optional
"""

from .evidence import VerificationResult, add_verification
from .file_check import FileExistenceValidator, LineNumberValidator
from .contradiction import ContradictionDetector
from .cross_model import CrossModelVerifier
from agies.tools.report import get_analyzer_result


class VerificationPipeline:
    """Full verification pipeline for LLM audit findings."""

    def __init__(
        self,
        target_root: str,
        strong_model=None,
        enable_file_check: bool = True,
        enable_contradiction: bool = True,
        enable_cross_model: bool = True,
        enable_attacker_control: bool = True,
    ):
        self.target_root = target_root
        self.enable_file_check = enable_file_check
        self.enable_contradiction = enable_contradiction
        self.enable_cross_model = enable_cross_model
        self.enable_attacker_control = enable_attacker_control

        self.file_validator = FileExistenceValidator(target_root) if enable_file_check else None
        self.line_validator = LineNumberValidator() if enable_file_check else None
        self.contradiction_detector = None
        self.cross_model_verifier = CrossModelVerifier(strong_model) if enable_cross_model and strong_model else None
        self.attacker_control_verifier = None

    def run(self, findings: list[dict]) -> list[dict]:
        """Run the verification pipeline on a list of findings.

        Each finding dict gains 'verification' and optionally 'attacker_control'
        and 'exploitability' keys. Returns the same list (mutated in place).
        """
        # Load static analysis results for contradiction detection
        static_findings = []
        if self.enable_contradiction:
            analyzer_result = get_analyzer_result()
            if analyzer_result and hasattr(analyzer_result, "findings"):
                static_findings = list(analyzer_result.findings)
            self.contradiction_detector = ContradictionDetector(static_findings)

        for finding in findings:
            result = VerificationResult()

            # Stage 1: File existence + boundary
            if self.file_validator:
                result = self.file_validator.validate(finding)

            # Stage 2: Line number + code match
            if self.line_validator and result.file_exists:
                result = self.line_validator.validate(finding, result)

            # Stage 3: Contradiction detection (static vs LLM)
            if self.contradiction_detector and result.file_exists:
                result = self.contradiction_detector.validate(finding, result)

            # Stage 4: Cross-model verification
            if self.cross_model_verifier:
                result = self.cross_model_verifier.validate(finding, result)

            # Determine overall verification status
            if result.verification_status == "unverified":
                if result.contradictions:
                    result.verification_status = "uncertain"
                elif result.file_exists and result.line_valid:
                    result.verification_status = "verified"
                else:
                    result.verification_status = "uncertain"

            # Attach verification result
            add_verification(finding, result)

            # Stage 5: Attacker control verification
            if self.enable_attacker_control:
                self._run_attacker_control(finding)

        return findings

    def _run_attacker_control(self, finding: dict) -> None:
        """Run attacker control verification on a single finding."""
        from .attacker_control import AttackerControlVerifier
        from .exploitability import assess_exploitability

        verifier = AttackerControlVerifier(self.target_root)
        ac_result = verifier.verify(finding)

        finding["attacker_control"] = ac_result.to_dict()

        # Run exploitability assessment
        assessment = assess_exploitability(ac_result, finding)
        finding["exploitability"] = assessment.to_dict()
