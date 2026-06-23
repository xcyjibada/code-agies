"""Process-level verification sandbox — runs PoC scripts with resource limits.

Simplest possible implementation: each PoC executes as a subprocess in the
current Python environment (no Docker, no pip install).  The PoC itself is
responsible for:

1. Starting any needed target server (for HTTP PoCs)
2. Sending the exploit payload
3. Checking the result
4. Reporting via ``verify() -> dict`` or ``AGIES_RESULT=...`` stdout line

The sandbox only enforces:
- Timeout (default 30s, kills the subprocess)
- Output capture (stdout + stderr)
- Exit code analysis
- Structured result extraction from ``verify()``

Usage in v3 pipeline
--------------------
::

    from agies.engine.v3.sandbox.runner import SandboxRunner

    runner = SandboxRunner()
    result = runner.run_poc("pocs/myproject/rce_poc.py")
    if result.is_pass:
        confidence = max(confidence, 8)  # boost
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time

from agies.engine.v3.sandbox.models import SandboxResult, SandboxConfig

logger = logging.getLogger(__name__)

# ── Wrapper template ────────────────────────────────────────────────────
# When a PoC script defines ``verify() -> dict``, we call it from a thin
# wrapper that prints structured JSON to stdout.  This avoids modifying the
# user's PoC file while still getting reliable verification results.

_WRAPPER_TEMPLATE = textwrap.dedent("""\
    # Sandbox wrapper - calls PoC.verify() and prints structured result.
    import json, sys, traceback
    sys.path.insert(0, {poc_dir!r})
    try:
        import poc as _poc
        if hasattr(_poc, "verify"):
            _result = _poc.verify()
        else:
            _result = {{"success": False, "evidence": "No verify() function found"}}
    except Exception as _exc:
        _result = {{"success": False, "evidence": traceback.format_exc()}}
    print("AGIES_RESULT=" + json.dumps(_result))""")


class SandboxRunner:
    """Runs PoC scripts in an isolated subprocess.

    Each PoC gets its own temp directory.  The script is copied there,
    executed as a subprocess, and the sandbox parses structured results
    from its output.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self.config = config or SandboxConfig()
        self._work_dir = os.path.join(
            tempfile.gettempdir(), "agies-sandbox",
        )
        os.makedirs(self._work_dir, exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────

    def run_poc(
        self,
        poc_path: str,
        path_id: str = "",
        timeout: int | None = None,
    ) -> SandboxResult:
        """Run a single PoC script in the sandbox.

        Parameters
        ----------
        poc_path : str
            Path to the PoC Python script.
        path_id : str
            Path identifier for result tracking (e.g. ``"rce-003"``).
        timeout : int or None
            Override the default timeout in seconds.

        Returns
        -------
        SandboxResult
            Structured verdict from the sandbox.
        """
        if not os.path.isfile(poc_path):
            return SandboxResult(
                path_id=path_id or os.path.basename(poc_path),
                status="ERROR",
                exit_code=-1,
                error=f"PoC file not found: {poc_path}",
            )

        # Create a fresh run directory
        run_tag = path_id or os.path.basename(poc_path).replace(".py", "")
        run_dir = os.path.join(
            self._work_dir,
            f"{run_tag}-{int(time.time())}",
        )
        os.makedirs(run_dir, exist_ok=True)

        # Copy the PoC script into the run dir as ``poc.py``
        dest = os.path.join(run_dir, "poc.py")
        shutil.copy2(poc_path, dest)

        # Decide execution mode:
        #   1. Try structured verify() wrapper (preferred)
        #   2. Fall back to running the PoC directly
        has_verify = self._check_has_verify(dest)

        if has_verify:
            return self._run_structured(dest, run_dir, path_id, timeout or self.config.timeout)
        else:
            return self._run_direct(dest, run_dir, path_id, timeout or self.config.timeout)

    def cleanup(self, max_age_hours: int = 24) -> int:
        """Remove sandbox temp dirs older than *max_age_hours*.

        Returns the number of directories cleaned.
        """
        now = time.time()
        cleaned = 0
        for entry in os.listdir(self._work_dir):
            path = os.path.join(self._work_dir, entry)
            if os.path.isdir(path) and (now - os.path.getmtime(path)) > max_age_hours * 3600:
                try:
                    shutil.rmtree(path, ignore_errors=True)
                    cleaned += 1
                except OSError:
                    pass
        return cleaned

    # ── Execution modes ───────────────────────────────────────────────

    def _run_structured(
        self,
        poc_path: str,
        run_dir: str,
        path_id: str,
        timeout: int,
    ) -> SandboxResult:
        """Run the PoC via a structured ``verify()`` wrapper.

        Creates a small wrapper script in *run_dir* that imports the PoC
        (already copied to *run_dir*/poc.py) and calls its ``verify()``
        function, capturing structured output.
        """
        wrapper = _WRAPPER_TEMPLATE.format(poc_dir=run_dir)
        wrapper_path = os.path.join(run_dir, "_verify_wrapper.py")
        with open(wrapper_path, "w") as f:
            f.write(wrapper)

        start = time.time()
        try:
            proc = subprocess.run(
                [sys.executable, wrapper_path],
                cwd=run_dir,
                capture_output=True, text=True,
                timeout=timeout,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                path_id=path_id,
                status="TIMEOUT",
                exit_code=-1,
                duration=timeout,
                error=f"PoC timed out after {timeout}s",
            )

        duration = time.time() - start
        return self._parse_structured_output(
            proc, path_id, duration,
        )

    def _run_direct(
        self,
        poc_path: str,
        run_dir: str,
        path_id: str,
        timeout: int,
    ) -> SandboxResult:
        """Run the PoC script directly without a verify() function.

        Uses heuristic stdout patterns to determine success/failure.
        """
        start = time.time()
        try:
            proc = subprocess.run(
                [sys.executable, poc_path],
                cwd=run_dir,
                capture_output=True, text=True,
                timeout=timeout,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                path_id=path_id,
                status="TIMEOUT",
                exit_code=-1,
                duration=timeout,
                error=f"PoC timed out after {timeout}s",
            )

        duration = time.time() - start
        return self._parse_heuristic_result(proc, path_id, duration)

    # ── Output parsing ───────────────────────────────────────────────

    def _parse_structured_output(
        self,
        proc: subprocess.CompletedProcess,
        path_id: str,
        duration: float,
    ) -> SandboxResult:
        """Parse ``AGIES_RESULT=...`` from stdout."""
        logs = (proc.stdout or "") + "\n---stderr---\n" + (proc.stderr or "")
        logs = logs[:self.config.max_output]

        for line in (proc.stdout or "").splitlines():
            if line.startswith("AGIES_RESULT="):
                try:
                    data = json.loads(line[len("AGIES_RESULT="):])
                    success = data.get("success", False)
                    evidence = data.get("evidence", "")
                    status = "PASS" if success else "FAIL"
                    return SandboxResult(
                        path_id=path_id,
                        status=status,
                        exit_code=0 if success else proc.returncode,
                        evidence=str(evidence)[:2000],
                        duration=duration,
                        logs=logs,
                    )
                except (json.JSONDecodeError, ValueError):
                    continue

        # verify() returned but we didn't find AGIES_RESULT — the wrapper
        # itself probably crashed
        error = proc.stderr[:2000] if proc.stderr else "No AGIES_RESULT found in output"
        return SandboxResult(
            path_id=path_id,
            status="ERROR",
            exit_code=proc.returncode,
            error=error,
            duration=duration,
            logs=logs,
        )

    def _parse_heuristic_result(
        self,
        proc: subprocess.CompletedProcess,
        path_id: str,
        duration: float,
    ) -> SandboxResult:
        """Determine success/failure from stdout patterns.

        This is the fallback for older PoCs that don't have ``verify()``.
        """
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        logs = stdout + "\n---stderr---\n" + stderr
        logs = logs[:self.config.max_output]

        stdout_lower = stdout.lower()

        # Check structured result first (some PoCs may print it even without
        # a dedicated verify() function)
        for line in stdout.splitlines():
            if line.startswith("AGIES_RESULT="):
                try:
                    data = json.loads(line[len("AGIES_RESULT="):])
                    status = "PASS" if data.get("success") else "FAIL"
                    return SandboxResult(
                        path_id=path_id,
                        status=status,
                        exit_code=proc.returncode,
                        evidence=data.get("evidence", stdout[-500:]),
                        duration=duration,
                        logs=logs,
                    )
                except (json.JSONDecodeError, ValueError):
                    continue

        # Heuristic: check success keywords first
        from agies.engine.v3.sandbox.models import _SUCCESS_PATTERNS, _FAILURE_PATTERNS

        has_success = any(p in stdout for p in _SUCCESS_PATTERNS)
        has_failure = any(p in stdout for p in _FAILURE_PATTERNS)

        if has_success and not has_failure:
            return SandboxResult(
                path_id=path_id,
                status="PASS",
                exit_code=proc.returncode,
                evidence=stdout[-1000:],
                duration=duration,
                logs=logs,
            )

        if has_failure:
            evidence = stdout[-500:] if stdout else ""
            return SandboxResult(
                path_id=path_id,
                status="FAIL",
                exit_code=proc.returncode,
                evidence=evidence,
                duration=duration,
                logs=logs,
            )

        # No clear signal from heuristic — use exit code
        if proc.returncode == 0:
            return SandboxResult(
                path_id=path_id,
                status="PASS",
                exit_code=0,
                evidence=stdout[-1000:],
                duration=duration,
                logs=logs,
            )

        return SandboxResult(
            path_id=path_id,
            status="ERROR",
            exit_code=proc.returncode,
            error=stderr[:2000] or f"Non-zero exit: {proc.returncode}",
            duration=duration,
            logs=logs,
        )

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _check_has_verify(py_path: str) -> bool:
        """Quick check whether a Python module defines ``verify()``.

        Uses AST (fast, no import) — looks for ``def verify(...)`` at
        module level.
        """
        try:
            import ast
            with open(py_path, "r") as f:
                tree = ast.parse(f.read())
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name == "verify":
                        return True
            return False
        except (SyntaxError, OSError):
            return False
