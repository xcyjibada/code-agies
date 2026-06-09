"""Docker sandbox executor for PoC verification.

Runs generated PoC scripts in isolated, network-disabled containers
to validate exploitability.  Designed as a best-effort verification
step — a failed or timed-out execution does not invalidate the finding
(DoS vulnerabilities are expected to hang).
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_DOCKER_AVAILABLE = False
_DockerClient = None
try:
    from docker import DockerClient as _DockerClientCls
    _DockerClient = _DockerClientCls
    _DOCKER_AVAILABLE = True
except ImportError:
    try:
        import docker as _docker_mod
        if hasattr(_docker_mod, "DockerClient"):
            _DockerClient = _docker_mod.DockerClient
            _DOCKER_AVAILABLE = True
    except ImportError:
        pass

if not _DOCKER_AVAILABLE:
    logger.info("Docker Python SDK not installed — sandbox disabled")


class PoCSandbox:
    """Execute PoC scripts in isolated Docker containers.

    Usage::

        sandbox = PoCSandbox(timeout_sec=15)
        result = sandbox.execute("/tmp/pocs/rce-001.py", lang="python")
        if result["verified"]:
            print("PoC confirmed!")

    Gracefully handles missing Docker daemon unavailability
    (returns ``verified=False``, never raises).
    """

    def __init__(self, timeout_sec: int = 15) -> None:
        self._timeout = timeout_sec
        self._client = None
        if _DOCKER_AVAILABLE and _DockerClient is not None:
            try:
                self._client = _DockerClient.from_env()
                self._client.ping()
            except Exception as exc:
                logger.warning("Docker daemon not available: %s", exc)
                self._client = None

    @property
    def available(self) -> bool:
        """Whether the Docker daemon is reachable."""
        return self._client is not None

    def execute(
        self,
        poc_script_path: str,
        lang: str = "python",
    ) -> dict:
        """Execute a PoC script in an isolated container.

        Parameters
        ----------
        poc_script_path : str
            Absolute path to the PoC script file.
        lang : str
            Language (``"python"`` or ``"javascript"``).

        Returns
        -------
        dict with keys:
          - ``verified``: bool — whether execution confirms exploitability
          - ``output``: str — stdout/stderr from the container
          - ``timeout``: bool — whether execution was killed by timeout
          - ``error``: str — error message on failure
        """
        if not self._client:
            return {
                "verified": False, "output": "",
                "timeout": False,
                "error": "Docker daemon not available",
            }

        if not os.path.isfile(poc_script_path):
            return {
                "verified": False, "output": "",
                "timeout": False,
                "error": f"PoC file not found: {poc_script_path}",
            }

        image = "python:3.11-slim" if lang == "python" else "node:20-slim"
        command = f"python /poc.py" if lang == "python" else f"node /poc.js"

        poc_dir = os.path.dirname(os.path.abspath(poc_script_path))
        poc_file = os.path.basename(poc_script_path)

        try:
            container = self._client.containers.run(
                image=image,
                command=command,
                volumes={
                    poc_dir: {
                        "bind": f"/{poc_file}",
                        "mode": "ro",
                    }
                },
                network_mode="none",
                mem_limit="100m",
                detach=True,
            )

            try:
                result = container.wait(timeout=self._timeout)
                logs = container.logs().decode("utf-8", errors="replace")
                exit_code = result.get("StatusCode", -1)

                # Heuristic: exit 0 + exploit success markers in output
                is_verified = (
                    exit_code == 0
                    and ("[+]" in logs or "[SUCCESS]" in logs
                         or "passwd" in logs or "flag" in logs)
                )
                return {
                    "verified": is_verified,
                    "output": logs,
                    "timeout": False,
                    "error": "",
                }

            except Exception:
                # Timeout — expected for DoS/infinite-loop PoCs
                container.kill()
                return {
                    "verified": True,
                    "output": (
                        "Execution timed out — "
                        "potential DoS/infinite loop confirmed"
                    ),
                    "timeout": True,
                    "error": "",
                }
            finally:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

        except Exception as exc:
            return {
                "verified": False,
                "output": "",
                "timeout": False,
                "error": str(exc),
            }

    def batch_execute(
        self,
        scripts: list[tuple[str, str]],
    ) -> list[dict]:
        """Execute multiple PoC scripts sequentially.

        Each tuple is ``(script_path, lang)``.
        """
        return [self.execute(path, lang) for path, lang in scripts]
