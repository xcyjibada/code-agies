"""Docker lifecycle management for Joern.

Manages pulling, running, and cleaning up Joern containers for CPG
generation and analysis.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from typing import Any

logger = logging.getLogger(__name__)

# Default Docker image — slim variant is ~1.5GB vs 4GB+ for full joern
DEFAULT_IMAGE = "agies/joern:latest"

# Tags we've confirmed exist on ghcr.io
CONFIRMED_TAGS = {
    "ghcr.io/joernio/joern-slim:latest",
    "ghcr.io/joernio/joern-slim:v4.0.551",
    "ghcr.io/joernio/joern-alma8:latest",
    "ghcr.io/joernio/joern:latest",
}


class JoernDocker:
    """Manages a Joern Docker container for CPG-based code analysis.

    Usage::

        jd = JoernDocker()
        jd.ensure_image()               # pull image once
        cpg_path = jd.parse(project)    # joern-parse → CPG
        nodes, edges = jd.export_cpg(cpg_path)  # joern-export → CSV
    """

    def __init__(
        self,
        image: str = DEFAULT_IMAGE,
        work_dir: str | None = None,
    ) -> None:
        self._image = image
        self._work_dir = work_dir or tempfile.mkdtemp(prefix="joern-")
        self._check_docker()

    def _check_docker(self) -> None:
        """Verify Docker is available."""
        try:
            subprocess.run(
                ["docker", "--version"],
                check=True, capture_output=True, timeout=10,
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            raise RuntimeError("Docker is not available. Install Docker first.")

    # ------------------------------------------------------------------
    # Image management
    # ------------------------------------------------------------------

    def ensure_image(self) -> bool:
        """Pull the Joern image if not already cached locally.

        Returns True if the image is available.
        """
        # Check if already pulled
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", self._image],
                capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                logger.info("Joern image %s already cached", self._image)
                return True
        except subprocess.TimeoutExpired:
            pass

        logger.info("Pulling Joern image %s (this may take a while)...", self._image)
        logger.info(
            "Tip: set HTTP_PROXY/HTTPS_PROXY env vars if behind a firewall"
        )
        try:
            subprocess.run(
                ["docker", "pull", self._image],
                check=True, capture_output=True, timeout=600,
            )
            logger.info("Joern image pulled successfully")
            return True
        except subprocess.TimeoutExpired:
            logger.error("Docker pull timed out for %s", self._image)
            return False
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode() if exc.stderr else ""
            logger.error("Docker pull failed: %s", stderr[:300])
            return False

    def check_available(self) -> bool:
        """Return True if the Joern image is available locally."""
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", self._image],
                capture_output=True, timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    # ------------------------------------------------------------------
    # CPG generation
    # ------------------------------------------------------------------

    def parse(self, project_path: str) -> str:
        """Run ``joern-parse`` to create a CPG binary.

        Returns the path to the generated CPG file (on the host).
        """
        cpg_path = os.path.join(self._work_dir, "cpg.bin")
        subset_path = os.path.join(self._work_dir, "project")
        os.makedirs(self._work_dir, exist_ok=True)

        logger.info("Joern: parsing %s ...", project_path)
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{project_path}:/app/src:ro",
            "-v", f"{self._work_dir}:/work:rw",
            "-w", "/work",
            self._image,
            "joern-parse", "-o", "/work/cpg.bin", "/app/src",
        ]

        try:
            result = subprocess.run(
                cmd, check=True, capture_output=True, timeout=600,
            )
            logger.info("Joern: parse complete — %s", cpg_path)
            if result.stdout:
                logger.debug("joern-parse stdout: %s", result.stdout.decode()[:500])
        except subprocess.TimeoutExpired:
            logger.error("Joern parse timed out for %s", project_path)
            raise
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode() if exc.stderr else ""
            logger.error("Joern parse failed: %s", stderr[:500])
            raise

        return cpg_path

    # ------------------------------------------------------------------
    # CPG export
    # ------------------------------------------------------------------

    def export_cpg(
        self,
        cpg_path: str,
        out_dir: str | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Export CPG to GraphSON and parse nodes/edges.

        Uses ``joern-export --repr=all --format=graphson``.

        .. note::

            Docker volume mounts create the target directory inside the
            container, which causes ``joern-export`` to reject it with
            "Output directory already exists".  We work around this by
            exporting to a temp path inside the container and copying back.

        Returns
        -------
        tuple[list[dict], list[dict]]
            (nodes, edges) where each is a list of property dicts.
        """
        export_dir = out_dir or os.path.join(self._work_dir, "export")
        os.makedirs(export_dir, exist_ok=True)

        # CPG may be at a host path; mount its directory
        cpg_dir = os.path.dirname(cpg_path)
        cpg_file = os.path.basename(cpg_path)
        cpg_in_container = f"/cpgmount/{cpg_file}"

        logger.info("Joern: exporting CPG...")

        # Mount the whole work_dir so we can export to a fresh subdirectory
        # inside the container (avoiding Docker-created dirs).
        mount_target = "/data"
        export_subdir = "joern_export_out"
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{cpg_dir}:/cpgmount:ro",
            "-v", f"{self._work_dir}:{mount_target}:rw",
            self._image,
            "sh", "-c",
            f"joern-export {cpg_in_container} "
            f"--repr=all --format=graphson "
            f"--out {mount_target}/{export_subdir} "
            f"&& cp -r {mount_target}/{export_subdir}/* {mount_target}/export/",
        ]

        try:
            subprocess.run(
                cmd, check=True, capture_output=True, timeout=300,
            )
        except subprocess.TimeoutExpired:
            logger.error("Joern export timed out")
            raise
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode() if exc.stderr else ""
            logger.error("Joern export failed: %s", stderr[:500])
            raise

        # Parse the exported JSON files
        nodes, edges = self._parse_export_json(export_dir)

        logger.info("Joern: exported %d nodes, %d edges", len(nodes), len(edges))
        return nodes, edges

    @staticmethod
    def _parse_export_json(
        export_dir: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Parse joern-export JSON output into node/edge lists."""
        all_nodes: list[dict[str, Any]] = []
        all_edges: list[dict[str, Any]] = []

        for fname in sorted(os.listdir(export_dir)):
            fpath = os.path.join(export_dir, fname)
            if not fname.endswith(".json") or not os.path.isfile(fpath):
                continue

            with open(fpath) as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    continue

            # joern-export GraphSON format:
            #   {"@type": "tinker:graph", "@value": {"vertices": [...], "edges": [...]}}
            if isinstance(data, dict):
                # Unwrap TinkerPop GraphSON envelope
                if "@value" in data and isinstance(data["@value"], dict):
                    gv = data["@value"]
                    all_nodes.extend(gv.get("vertices", []))
                    all_edges.extend(gv.get("edges", []))
                else:
                    all_nodes.extend(data.get("vertices", data.get("nodes", [])))
                    all_edges.extend(data.get("edges", []))
            elif isinstance(data, list):
                # Some Joern versions output a list of graphs
                for entry in data:
                    if isinstance(entry, dict):
                        if "@value" in entry and isinstance(entry["@value"], dict):
                            gv = entry["@value"]
                            all_nodes.extend(gv.get("vertices", []))
                            all_edges.extend(gv.get("edges", []))
                        else:
                            all_nodes.extend(entry.get("vertices", entry.get("nodes", [])))
                            all_edges.extend(entry.get("edges", []))

        return all_nodes, all_edges

    # ------------------------------------------------------------------
    # Direct query (via joern --script)
    # ------------------------------------------------------------------

    def run_script(
        self,
        script_path: str,
        cpg_path: str,
        params: dict[str, str] | None = None,
    ) -> str:
        """Run a Scala query script via ``joern --script``.

        Parameters
        ----------
        script_path : str
            Path to the .sc script file (on host).
        cpg_path : str
            Path to the CPG binary (on host).
        params : dict or None
            Additional parameters passed as ``--param key=val``.

        Returns
        -------
        str
            Script stdout output.
        """
        script_dir = os.path.dirname(script_path)
        script_file = os.path.basename(script_path)
        cpg_dir = os.path.dirname(cpg_path)
        cpg_file = os.path.basename(cpg_path)

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{script_dir}:/script:ro",
            "-v", f"{cpg_dir}:/cpg:ro",
            self._image,
            "joern", "--script", f"/script/{script_file}",
            "--param", f"cpgFile=/cpg/{cpg_file}",
        ]

        if params:
            for k, v in params.items():
                cmd.extend(["--param", f"{k}={v}"])

        logger.debug("Joern: running script %s", script_file)
        try:
            result = subprocess.run(
                cmd, check=True, capture_output=True, timeout=300,
            )
            return result.stdout.decode()
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode() if exc.stderr else ""
            raise RuntimeError(f"Joern script failed: {stderr[:500]}") from exc

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup(self) -> None:
        """Remove the working directory."""
        import shutil

        if self._work_dir and os.path.isdir(self._work_dir):
            shutil.rmtree(self._work_dir, ignore_errors=True)
            logger.debug("Joern: cleaned up %s", self._work_dir)
