"""Data models for sandbox verification results."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SandboxResult:
    """Result of running a PoC in the verification sandbox.

    ``status`` is one of:
    - PASS    — verification confirmed: PoC triggered the vulnerability
    - FAIL    — PoC ran but did not trigger the vulnerability
    - ERROR   — PoC itself crashed or had missing dependencies
    - TIMEOUT — PoC exceeded the time limit
    - SKIP    — sandbox skipped this PoC (e.g. no verify() function found)
    """

    path_id: str
    status: str
    exit_code: int
    evidence: str = ""
    duration: float = 0.0
    error: str = ""
    logs: str = ""
    """Full stdout + stderr from the subprocess."""

    @property
    def is_pass(self) -> bool:
        return self.status == "PASS"

    @property
    def is_actionable(self) -> bool:
        """True when we got a clean verdict (not a sandbox infrastructure issue)."""
        return self.status in ("PASS", "FAIL")


@dataclass
class SandboxConfig:
    """Configuration for the verification sandbox."""

    enabled: bool = False
    """Master switch — sandbox is opt-in."""

    timeout: int = 30
    """Seconds before a PoC subprocess is killed."""

    max_output: int = 10_000
    """Max bytes of stdout/stderr to capture."""


# ── stdout patterns used for fallback heuristic ──

_SUCCESS_PATTERNS = {
    "[+]",
    "SUCCESS",
    "AGIES_RESULT=",  # structured result, handled in runner
    "pwned",
    "exploit succeeded",
    "confirmed",
    "vulnerable",
    "arbitrary file read",
    "got /etc/passwd",
    "root:x:",
}
"""Known keywords a PoC might print to indicate exploitation succeeded.
Used when the PoC has no structured ``verify()`` function."""

_FAILURE_PATTERNS = {
    "[-]",
    "FAILED",
    "exploit failed",
    "not vulnerable",
    "could not connect",
    "connection refused",
    "access denied",
    "blocked",
    "rejected",
}
"""Keywords suggesting the PoC ran but the exploit didn't work."""
