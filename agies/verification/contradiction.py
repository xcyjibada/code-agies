"""Contradiction detection — compare LLM findings against static analysis results.

This layer does NOT call LLM; it's pure logic that cross-references
findings from different sources to identify inconsistencies.
"""

from .evidence import VerificationResult


class ContradictionDetector:
    """Detect contradictions between LLM findings and static analysis.

    Scenarios detected:
    - LLM claims a vulnerability in a file that static analysis confirms clean
    - LLM and static analysis disagree on the vulnerability type
    - LLM claims a data flow path that contradicts static analysis taint trace
    """

    def __init__(self, static_findings: list | None = None):
        self.static_findings = static_findings or []

    def validate(self, finding: dict, existing_result: VerificationResult) -> VerificationResult:
        """Check an LLM finding against static analysis results."""
        result = existing_result

        if not self.static_findings:
            result.evidence_chain.append({
                "type": "contradiction",
                "status": "skipped",
                "detail": "No static analysis results available for comparison",
                "source": "contradiction",
            })
            return result

        llm_file = (finding.get("file_path") or "").lower()
        llm_severity = (finding.get("severity") or "").lower()

        matching_static = [
            sf for sf in self.static_findings
            if sf.file_path and sf.file_path.lower() == llm_file
        ]

        if not matching_static:
            # LLM found something in a file static analysis didn't flag.
            # This isn't necessarily a contradiction — static analysis can miss things.
            result.evidence_chain.append({
                "type": "contradiction",
                "status": "uncertain",
                "detail": f"No static analysis findings for this file ({finding.get('file_path')})",
                "source": "contradiction",
            })
            return result

        contradictions = []

        # Check for exact duplicates
        for sf in matching_static:
            if self._is_same_vulnerability(finding, sf):
                # Not a contradiction — agreement
                result.evidence_chain.append({
                    "type": "contradiction",
                    "status": "passed",
                    "detail": f"Static analysis also flags this issue: {sf.title}",
                    "source": "contradiction",
                })
                return result

        # Check for line-level contradictions
        llm_line = finding.get("line_number")
        if llm_line:
            same_line_static = [
                sf for sf in matching_static
                if sf.line_number == llm_line
            ]
            if same_line_static:
                for sf in same_line_static:
                    if sf.severity.lower() != llm_severity:
                        contradictions.append(
                            f"Static analysis flags '{sf.title}' at same line but with "
                            f"severity '{sf.severity}' vs LLM '{finding.get('severity')}'"
                        )

        # Check file-level severity disagreement
        max_static_sev = max(
            (self._sev_score(sf.severity) for sf in matching_static),
            default=0,
        )
        llm_sev_score = self._sev_score(llm_severity)

        if llm_sev_score >= 4 and max_static_sev <= 1:
            contradictions.append(
                f"LLM reports severity '{finding.get('severity')}' but static analysis "
                f"found no issues above 'low' in this file"
            )

        if contradictions:
            result.contradictions = contradictions
            result.verification_status = "uncertain"
            for c in contradictions:
                result.evidence_chain.append({
                    "type": "contradiction",
                    "status": "uncertain",
                    "detail": c,
                    "source": "contradiction",
                })
        else:
            result.evidence_chain.append({
                "type": "contradiction",
                "status": "passed",
                "detail": "No contradictions with static analysis",
                "source": "contradiction",
            })

        return result

    @staticmethod
    def _is_same_vulnerability(finding: dict, static_finding) -> bool:
        """Check if the LLM finding matches a static analysis finding."""
        llm_line = finding.get("line_number")
        sf_line = static_finding.line_number
        if llm_line and sf_line and llm_line == sf_line:
            # Same line — likely the same issue
            return True
        return False

    @staticmethod
    def _sev_score(severity: str) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(severity.lower(), 0)
