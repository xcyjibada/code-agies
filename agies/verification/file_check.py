"""File existence and line number validation.

This is the lightest-weight verification layer — zero LLM calls,
purely filesystem-level checks.
"""

import os
import subprocess

from .evidence import VerificationResult, Evidence


class FileExistenceValidator:
    """Verify that reported file paths actually exist on disk.

    If a file isn't found at the reported path, attempts to locate
    it by filename to correct hallucinated paths.
    """

    def __init__(self, target_root: str):
        self.target_root = os.path.abspath(target_root)

    def validate(self, finding: dict) -> VerificationResult:
        result = VerificationResult()

        file_path = finding.get("file_path", "")
        if not file_path:
            result.evidence_chain.append({
                "type": "file_exists",
                "status": "skipped",
                "detail": "No file path reported",
                "source": "file_check",
            })
            return result

        abs_path = os.path.abspath(file_path) if not os.path.isabs(file_path) else file_path
        result.original_path = abs_path

        if os.path.exists(abs_path):
            # File exists on disk regardless of boundary
            result.file_exists = True
            # Verify it's within the target boundary
            if self._is_within_target(abs_path):
                result.evidence_chain.append({
                    "type": "file_exists",
                    "status": "passed",
                    "detail": f"File exists: {abs_path}",
                    "source": "file_check",
                })
            else:
                result.evidence_chain.append({
                    "type": "file_exists",
                    "status": "failed",
                    "detail": f"File exists but is outside target boundary: {abs_path}",
                    "source": "file_check",
                })
        else:
            # Try to find the file by basename
            corrected = self._find_by_name(file_path)
            if corrected:
                result.file_exists = True
                result.file_corrected = True
                result.evidence_chain.append({
                    "type": "file_exists",
                    "status": "passed",
                    "detail": f"Path corrected: {file_path} → {corrected}",
                    "source": "file_check",
                })
                # Update the finding with the corrected path
                finding["file_path"] = corrected
                finding["_path_corrected"] = True
            else:
                result.evidence_chain.append({
                    "type": "file_exists",
                    "status": "failed",
                    "detail": f"File not found: {abs_path}. Searched by name, no match in target.",
                    "source": "file_check",
                })

        return result

    def _is_within_target(self, abs_path: str) -> bool:
        return abs_path.startswith(self.target_root)

    def _find_by_name(self, original_path: str) -> str | None:
        """Search for the file by basename within the target directory."""
        basename = os.path.basename(original_path)
        if not basename:
            return None
        try:
            result = subprocess.run(
                ["find", self.target_root, "-name", basename, "-type", "f"],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout.strip():
                return result.stdout.strip().split("\n")[0]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None


class LineNumberValidator:
    """Verify line number is within the file and code snippet matches."""

    def __init__(self, context_lines: int = 3):
        self.context_lines = context_lines

    def validate(self, finding: dict, file_exists_result: VerificationResult) -> VerificationResult:
        """Continue from file_exists result, adding line-level checks."""
        result = file_exists_result

        if not result.file_exists:
            # Can't validate lines if file doesn't exist
            result.line_valid = False
            result.evidence_chain.append({
                "type": "line_match",
                "status": "skipped",
                "detail": "Cannot validate line number: file does not exist",
                "source": "line_check",
            })
            return result

        file_path = finding.get("file_path", "")
        line_number = finding.get("line_number")

        if line_number is None:
            result.line_valid = False
            result.evidence_chain.append({
                "type": "line_match",
                "status": "skipped",
                "detail": "No line number reported",
                "source": "line_check",
            })
            return result

        # Read file and check line count
        try:
            with open(file_path, "r", errors="replace") as f:
                file_lines = f.readlines()
        except (FileNotFoundError, IOError) as e:
            result.line_valid = False
            result.evidence_chain.append({
                "type": "line_match",
                "status": "failed",
                "detail": f"Cannot read file: {e}",
                "source": "line_check",
            })
            return result

        total_lines = len(file_lines)

        if line_number < 1 or line_number > total_lines:
            result.line_valid = False
            result.evidence_chain.append({
                "type": "line_match",
                "status": "failed",
                "detail": f"Line {line_number} out of range: file has {total_lines} lines",
                "source": "line_check",
            })
            return result

        result.line_valid = True
        result.evidence_chain.append({
            "type": "line_match",
            "status": "passed",
            "detail": f"Line {line_number} is valid (file has {total_lines} lines)",
            "source": "line_check",
        })

        # Optional: try to fuzzy-match any code context in the detail
        detail = finding.get("detail", "")
        code_hint = self._extract_code_hint(detail)
        if code_hint:
            nearby_lines = file_lines[max(0, line_number - 1 - self.context_lines):
                                       min(total_lines, line_number + self.context_lines)]
            nearby_text = "".join(nearby_lines)
            if self._fuzzy_match(code_hint, nearby_text):
                result.code_match = True
                result.evidence_chain.append({
                    "type": "code_match",
                    "status": "passed",
                    "detail": f"Code context matches around line {line_number}",
                    "source": "line_check",
                })
            else:
                result.evidence_chain.append({
                    "type": "code_match",
                    "status": "uncertain",
                    "detail": f"Code context does not closely match around line {line_number}",
                    "source": "line_check",
                })

        return result

    @staticmethod
    def _extract_code_hint(text: str) -> str | None:
        """Extract a short code snippet from finding detail text."""
        import re
        # Try to find code blocks or quoted code
        for pattern in [r"`([^`]+)`", r"'([^']{10,})'", r'"([^"]{10,})"']:
            matches = re.findall(pattern, text)
            if matches:
                return max(matches, key=len)
        return None

    @staticmethod
    def _fuzzy_match(hint: str, text: str) -> bool:
        """Check if key tokens from the hint appear in the text."""
        import re
        tokens = set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,}', hint))
        if not tokens:
            return False
        # Allow some tokens to be missing (LLM may paraphrase)
        found = sum(1 for t in tokens if t in text)
        return found / len(tokens) >= 0.6
