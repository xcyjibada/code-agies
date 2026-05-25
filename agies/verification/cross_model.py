"""Cross-model verification — verify uncertain findings with a stronger model.

Inspired by Sandyaa's approach: when a cheap/fast model produces
uncertain findings, escalate to a more capable (expensive) model
for confirmation.
"""

from .evidence import VerificationResult


class CrossModelVerifier:
    """Verify findings across models for hallucination defense.

    Strategy:
    - Critical/high findings with uncertain status → verify with stronger model
    - The verifier asks the stronger model to check the finding against source code
    """

    def __init__(self, strong_model=None):
        """Initialize with a stronger LLM provider for verification.

        Args:
            strong_model: An LLMProvider instance (e.g., Claude Opus).
                          If None, cross-model verification is skipped.
        """
        self.strong_model = strong_model

    def validate(self, finding: dict, existing_result: VerificationResult) -> VerificationResult:
        """Run cross-model verification on a finding."""
        result = existing_result

        if not self.strong_model:
            result.evidence_chain.append({
                "type": "llm_verification",
                "status": "skipped",
                "detail": "No strong model configured for cross-model verification",
                "source": "cross_model",
            })
            return result

        # Only verify findings that pass basic checks and are critical/high
        if not result.file_exists or not result.line_valid:
            result.evidence_chain.append({
                "type": "llm_verification",
                "status": "skipped",
                "detail": "Skipping LLM verification: finding failed basic file/line checks",
                "source": "cross_model",
            })
            return result

        severity = (finding.get("severity") or "").lower()
        if severity not in ("critical", "high"):
            result.evidence_chain.append({
                "type": "llm_verification",
                "status": "skipped",
                "detail": f"Skipping LLM verification: severity '{severity}' below threshold",
                "source": "cross_model",
            })
            return result

        # Read the relevant code context
        code_context = self._read_code_context(finding)
        if not code_context:
            result.evidence_chain.append({
                "type": "llm_verification",
                "status": "uncertain",
                "detail": "Cannot read code for verification",
                "source": "cross_model",
            })
            return result

        # Build verification prompt
        verify_prompt = (
            f"You are verifying a security finding from an automated audit. "
            f"Examine the code and determine if the finding is valid.\n\n"
            f"## Finding\n"
            f"Title: {finding.get('title')}\n"
            f"Severity: {finding.get('severity')}\n"
            f"Detail: {finding.get('detail')}\n"
            f"File: {finding.get('file_path')}:{finding.get('line_number')}\n"
            f"Confidence: {finding.get('confidence')}\n\n"
            f"## Code Context\n"
            f"```\n{code_context}\n```\n\n"
            f"Respond with one of:\n"
            f"- VERIFIED: The finding is valid and accurate based on the code\n"
            f"- CONTRADICTED: The finding is wrong or misleading\n"
            f"- UNCERTAIN: Cannot determine from available context"
        )

        try:
            response = self.strong_model.chat_completion(
                messages=[{"role": "user", "content": verify_prompt}],
                max_tokens=256,
            )
            verdict = (response.content or "").strip().upper()

            if "VERIFIED" in verdict:
                result.verification_status = "verified"
                result.evidence_chain.append({
                    "type": "llm_verification",
                    "status": "passed",
                    "detail": "Cross-model verification confirmed the finding",
                    "source": "cross_model",
                })
            elif "CONTRADICTED" in verdict:
                result.verification_status = "contradicted"
                result.contradictions.append("Cross-model verification refuted this finding")
                result.evidence_chain.append({
                    "type": "llm_verification",
                    "status": "failed",
                    "detail": f"Cross-model verification refuted: {verdict[:200]}",
                    "source": "cross_model",
                })
            else:
                result.verification_status = "uncertain"
                result.evidence_chain.append({
                    "type": "llm_verification",
                    "status": "uncertain",
                    "detail": f"Cross-model verification uncertain: {verdict[:200]}",
                    "source": "cross_model",
                })
        except Exception as e:
            result.evidence_chain.append({
                "type": "llm_verification",
                "status": "uncertain",
                "detail": f"Cross-model verification failed: {e}",
                "source": "cross_model",
            })

        return result

    @staticmethod
    def _read_code_context(finding: dict, context_lines: int = 10) -> str | None:
        """Read code around the reported line number."""
        file_path = finding.get("file_path", "")
        line_number = finding.get("line_number")

        if not file_path or not line_number:
            return None

        try:
            with open(file_path, "r", errors="replace") as f:
                lines = f.readlines()
        except (FileNotFoundError, IOError):
            return None

        start = max(0, line_number - 1 - context_lines)
        end = min(len(lines), line_number + context_lines)
        context = "".join(lines[start:end])

        header = f"{file_path} (lines {start + 1}-{end})"
        return f"{header}\n{context}"
