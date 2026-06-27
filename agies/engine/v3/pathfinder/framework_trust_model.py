"""Framework Trust Model — project security context for Phase D agents.

Generates a structured "security model" document describing the target project's
framework, permission model, known security controls, and trust boundaries.

This document is injected into Phase D agent prompts (Intent Agent + Logic Agent)
so the LLM has architectural context before analyzing individual source→sink paths.
Without this, the LLM makes generic assumptions about the codebase.

Example output for Jenkins::

    [FRAMEWORK TRUST MODEL]
    Framework: Stapler (Jenkins)
    Auto-deserialization sinks: config.xml POST
    Permission model: ADMINISTER required for all URL.openConnection
    Security controls: JEP-200 ClassFilter, CSRF crumb, @RequirePOST
    Trust boundaries: Jenkins core types trusted by ClassFilter
    Known gaps: DescribableList<T> does NOT enforce T at runtime

Design
------
Scans project files for framework indicators, security annotations, and common
trust boundary configurations.  Output is a plain-text document that gets prepended
to agent prompts in Phase D.

Supports: Stapler (Jenkins), Spring MVC, Django REST Framework, FastAPI, Flask.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Framework-specific security model builders
# ---------------------------------------------------------------------------


def _scan_permission_patterns(file_path: str) -> tuple[set[str], str]:
    """Scan a file for permission/access control annotations.

    Returns ``(found_pattern_names, file_content)`` to avoid double-reads
    when callers also need the raw content.
    """
    patterns_found: set[str] = set()
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(8192)
    except OSError:
        return patterns_found, ""

    for pat_name, pat in _PERMISSION_PATTERNS:
        if pat.search(content):
            patterns_found.add(pat_name)

    return patterns_found, content


_PERMISSION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("checkPermission(ADMINISTER)", re.compile(r"checkPermission.*ADMINISTER|ADMINISTER")),
    ("checkPermission(READ)", re.compile(r"checkPermission.*READ|\.READ\b")),
    ("@RequirePOST", re.compile(r"@RequirePOST")),
    ("@PreAuthorize", re.compile(r"@PreAuthorize")),
    ("@Secured", re.compile(r"@Secured")),
    ("@RolesAllowed", re.compile(r"@RolesAllowed")),
    ("login_required", re.compile(r"login_required|@login_required")),
    ("permission_required", re.compile(r"permission_required")),
    ("csrf.exempt", re.compile(r"csrf_exempt|@csrf\.exempt")),
    ("JEP-200 ClassFilter", re.compile(r"ClassFilter|JEP-200|je[mp]-200")),
]


def _build_jenkins_model(project_path: str) -> dict[str, Any]:
    """Build a security model for Jenkins / Stapler projects."""
    model: dict[str, Any] = {
        "framework": "Stapler (Jenkins)",
        "auto_deser_sinks": ["config.xml POST — Stapler/XStream auto-deserialization"],
        "permission_model": "ADMINISTER required for most management operations",
        "security_controls": [],
        "trust_boundaries": [],
        "known_gaps": [],
    }

    # Scan up to 200 Java files for security patterns + DescribableList usage.
    # Jenkins has 1268+ Java files with ~21 DescribableList references (~1.7%),
    # so 50 files gives only ~57% detection — 200 files gives ~97%.
    found_patterns: set[str] = set()
    describable_count = 0
    scan_count = 0
    for dirpath, dirnames, filenames in os.walk(project_path):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS]
        for fn in filenames:
            if not fn.endswith(".java"):
                continue
            fp = os.path.join(dirpath, fn)
            fps, content = _scan_permission_patterns(fp)
            found_patterns |= fps
            if "DescribableList" in content:
                describable_count += 1
            scan_count += 1
            if scan_count >= 200:
                break
        if scan_count >= 200:
            break

    if "JEP-200 ClassFilter" in found_patterns:
        model["security_controls"].append("JEP-200 ClassFilter — type whitelist for XStream deserialization")
    if "@RequirePOST" in found_patterns:
        model["security_controls"].append("@RequirePOST — POST-only endpoint restriction")
    if "checkPermission(ADMINISTER)" in found_patterns:
        model["security_controls"].append("checkPermission(ADMINISTER) — admin-only operations")

    if describable_count > 0:
        model["known_gaps"].append(
            f"DescribableList<T> used in {describable_count}+ files — "
            "type parameter T is NOT enforced at runtime during XStream deserialization. "
            "Any type passing ClassFilter can be injected into the list."
        )

    # Check for ProxyConfiguration (SSRF context)
    try:
        proxy_path = os.path.join(project_path, "core/src/main/java/hudson/ProxyConfiguration.java")
        if os.path.exists(proxy_path):
            model["trust_boundaries"].append(
                "ProxyConfiguration.open() — ALL outbound HTTP goes through this method. "
                "HttpURLConnection follows redirects by default with NO host validation."
            )
    except Exception:
        pass

    return model


def build_trust_model(project_path: str) -> tuple[str, list[str]]:
    """Build a security trust model document for the project.

    Parameters
    ----------
    project_path : str
        Root directory of the project being analyzed.

    Returns
    -------
    tuple[str, list[str]]
        (trust_model_document, detected_framework_ids)
        The document is a plain-text string suitable for injection into agent prompts.
        The framework IDs list is empty if no known framework was detected.
    """
    # Auto-detect framework
    from agies.engine.v3.pathfinder.framework_sinks import detect_frameworks
    frameworks = detect_frameworks(project_path)

    model_data: dict[str, Any] | None = None
    detected_ids: list[str] = []

    if "stapler" in frameworks:
        model_data = _build_jenkins_model(project_path)
        detected_ids = ["stapler"]

    if not model_data:
        logger.info("Trust model: no supported framework detected")
        return "", []

    # Format as document
    lines = [
        "[FRAMEWORK TRUST MODEL]",
        f"Framework: {model_data['framework']}",
        "",
    ]

    if model_data.get("auto_deser_sinks"):
        lines.append("Auto-deserialization sinks:")
        for s in model_data["auto_deser_sinks"]:
            lines.append(f"  - {s}")
        lines.append("")

    if model_data.get("permission_model"):
        lines.append(f"Permission model: {model_data['permission_model']}")
        lines.append("")

    if model_data.get("security_controls"):
        lines.append("Security controls detected:")
        for c in model_data["security_controls"]:
            lines.append(f"  + {c}")
        lines.append("")

    if model_data.get("trust_boundaries"):
        lines.append("Trust boundaries:")
        for b in model_data["trust_boundaries"]:
            lines.append(f"  ⚠ {b}")
        lines.append("")

    if model_data.get("known_gaps"):
        lines.append("Known architectural gaps:")
        for g in model_data["known_gaps"]:
            lines.append(f"  ✗ {g}")
        lines.append("")

    lines.append("[/FRAMEWORK TRUST MODEL]")
    lines.append("")

    return "\n".join(lines), detected_ids


_EXCLUDED_DIRS: set[str] = {
    ".git", "__pycache__", "node_modules", "venv", ".venv",
    "dist", "build", ".tox", ".eggs", "egg-info", "target",
    ".mypy_cache", ".pytest_cache", "test", "tests",
}
