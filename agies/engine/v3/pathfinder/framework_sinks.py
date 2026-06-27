"""Framework-level sink discovery — Phase A pass.

Extends TreeSitterPathFinder with awareness of web framework auto-deserialization
patterns that don't match traditional function-name-based sink detection.

The problem
-----------
Traditional sink detection matches function names like ``exec`` or ``readObject``.
But many real-world vulnerabilities (e.g. CVE-2026-53435) occur when a web
framework automatically deserializes user input (XML/JSON/form data) into objects
without proper type validation.  The "sink" is the framework's binding mechanism,
not a single dangerous function.

This module detects framework-specific indicators and flags functions that
participate in auto-deserialization as potential sinks.

Supported frameworks
--------------------
- Java: Stapler (Jenkins) — methods handling ``config.xml`` POST
- Java: Spring MVC — methods with ``@RequestBody``, ``@ModelAttribute``
- Python: Django REST Framework — ``ModelSerializer``, ``APIView``
- Python: FastAPI — Pydantic route parameter binding
- Python: Flask — ``request.get_json()`` in route handlers
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Framework indicator patterns — per-file scans
# ---------------------------------------------------------------------------

# Each framework lists: (file_name_pattern, content_pattern)
# where file_name_pattern filters files and content_pattern confirms the framework.

_FRAMEWORK_INDICATORS: dict[str, list[tuple[re.Pattern, re.Pattern]]] = {
    "stapler": [
        # Jenkins Stapler: look for @RequirePOST or StaplerRequest2
        (re.compile(r".*\.java$"), re.compile(r"@RequirePOST|StaplerRequest2|StaplerResponse2")),
        # Stapler extends PageDecorator, AbstractModelObject, etc.
        (re.compile(r".*\.java$"), re.compile(r"extends PageDecorator|extends AbstractModelObject")),
        # config.xml is a strong signal
        (re.compile(r".*\.java$"), re.compile(r"config\.xml")),
    ],
    "spring": [
        (re.compile(r".*\.java$"), re.compile(r"@SpringBootApplication|@RestController|@Controller")),
        (re.compile(r".*\.java$"), re.compile(r"import org\.springframework")),
    ],
    "django_rest": [
        (re.compile(r".*\.py$"), re.compile(r"from rest_framework|import rest_framework")),
        (re.compile(r".*\.py$"), re.compile(r"class \w+\(.*ModelSerializer.*\)")),
        (re.compile(r".*\.py$"), re.compile(r"class \w+\(.*APIView.*\)")),
    ],
    "fastapi": [
        (re.compile(r".*\.py$"), re.compile(r"from fastapi|import fastapi")),
        (re.compile(r".*\.py$"), re.compile(r"@\w+\.(get|post|put|delete|patch)")),
    ],
    "flask": [
        (re.compile(r".*\.py$"), re.compile(r"from flask import|import flask")),
        (re.compile(r".*\.py$"), re.compile(r"@\w+\.route")),
    ],
}

# ---------------------------------------------------------------------------
# Framework-specific auto-deserialization sink patterns
# ---------------------------------------------------------------------------
# For each framework, define patterns that identify functions performing
# automatic deserialization of user input.

# Attention: These are annotation/detection patterns (checks on function
# metadata, not on function names), so they use different matching logic.

_FRAMEWORK_SINK_DETECTORS: dict[str, list[dict[str, Any]]] = {
    "stapler": [
        {
            "name": "config_xml_post",
            "vuln_type": "RCE",
            "description": "Stapler config.xml POST handler — framework auto-deserializes XML into Java objects",
            # Match functions named do* in a Stapler project that reference config.xml
            "function_name": re.compile(r"^do\w+"),
            "body_pattern": re.compile(r"config\.xml|getConfigFile|submitSignedConfig|updateConfig|submitConfig"),
            # Also check annotations in source context (5 lines above)
            "annotation_pattern": re.compile(r"@RequirePOST"),
        },
        {
            "name": "stapler_generic_post",
            "vuln_type": "SUSPICIOUS",
            "description": "Stapler POST handler receives user data that may be auto-bound",
            "function_name": re.compile(r"^do\w+"),
            "body_pattern": re.compile(r"StaplerRequest2|StaplerResponse2|req\b|HttpResponse"),
            "annotation_pattern": re.compile(r"@RequirePOST"),
        },
    ],
    "spring": [
        {
            "name": "request_body_binding",
            "vuln_type": "RCE",
            "description": "Spring @RequestBody — framework auto-deserializes request body to Java object",
            "function_name": re.compile(r".*"),  # any function name
            # Check the signature and context for @RequestBody
            "annotation_pattern": re.compile(r"@RequestBody"),
        },
        {
            "name": "model_attribute_binding",
            "vuln_type": "SUSPICIOUS",
            "description": "Spring @ModelAttribute — framework binds request params to Java object",
            "function_name": re.compile(r".*"),
            "annotation_pattern": re.compile(r"@ModelAttribute"),
        },
    ],
    "django_rest": [
        {
            "name": "drf_serializer",
            "vuln_type": "SUSPICIOUS",
            "description": "DRF ModelSerializer — framework auto-deserializes request data",
            "function_name": re.compile(r".*Serializer$|.*serializer"),
            "body_pattern": re.compile(r"class Meta|fields\s*=|read_only_fields|create\s*=|update\s*="),
        },
        {
            "name": "drf_api_view",
            "vuln_type": "SUSPICIOUS",
            "description": "DRF APIView — request data auto-parsed by framework",
            "function_name": re.compile(r"^(get|post|put|patch|delete)$"),
            "body_pattern": re.compile(r"request\.data|serializer\.data|request\.query_params"),
            "class_pattern": re.compile(r"APIView|GenericAPIView|ViewSet"),
        },
    ],
    "fastapi": [
        {
            "name": "fastapi_body_param",
            "vuln_type": "SUSPICIOUS",
            "description": "FastAPI route with Pydantic body param — auto-deserialization",
            "function_name": re.compile(r"^get$|^post$|^put$|^patch$|^delete$"),
            "body_pattern": re.compile(r": \w+ \w+,|Body\(|Query\(|Path\("),
        },
    ],
    "flask": [
        {
            "name": "flask_get_json",
            "vuln_type": "SUSPICIOUS",
            "description": "Flask route calls request.get_json() — deserializes JSON body",
            "function_name": re.compile(r".*"),
            "body_pattern": re.compile(r"request\.get_json|request\.form|request\.data|request\.args"),
        },
    ],
}


def detect_frameworks(project_path: str) -> list[str]:
    """Detect which web frameworks the project uses.

    Scans up to 100 source files for framework indicator patterns.
    Returns a sorted list of framework IDs (e.g. ``["stapler"]``, ``["spring"]``,
    ``["django_rest", "fastapi"]``).
    """
    detected: set[str] = set()
    file_count = 0

    # Precompile extension filter: only scan source files matching any
    # framework's name_pat. This prevents non-source files (images, configs,
    # SVGs) from consuming the scan budget — Jenkins root has ~100 non-Java
    # files before the first real source directory.
    _SOURCE_EXTS = re.compile(r"\.(?:java|py)$")

    for dirpath, dirnames, filenames in os.walk(project_path):
        # Skip common non-source dirs
        dirnames[:] = [
            d for d in dirnames
            if d not in (".git", "__pycache__", "node_modules", "venv", ".venv",
                         "dist", "build", ".tox", ".eggs", "egg-info", "target",
                         ".mypy_cache", ".pytest_cache", "test", "tests")
        ]
        for fn in filenames:
            if not _SOURCE_EXTS.search(fn):
                continue

            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(4096)  # read first 4KB
            except OSError:
                continue

            for fw, indicators in _FRAMEWORK_INDICATORS.items():
                if fw in detected:
                    continue
                for name_pat, content_pat in indicators:
                    if name_pat.match(fn) and content_pat.search(content):
                        detected.add(fw)
                        break

            file_count += 1
            if file_count >= 100:
                break
        if file_count >= 100:
            break

    result = sorted(detected)
    if result:
        logger.info("Framework sink detection: detected %s", result)
    return result


def _read_function_context(file_path: str, line_start: int, context_lines: int = 5) -> str:
    """Read a few lines above and including the function definition.

    Used to capture Java annotations (``@RequirePOST``, ``@RequestBody``)
    that appear before the method signature but may not be in the function body
    as extracted by tree-sitter.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return ""

    start = max(0, line_start - context_lines - 1)
    end = min(len(lines), line_start + 2)
    return "".join(lines[start:end])


def find_framework_sinks(
    project_path: str,
    function_index: Any,
    detected_frameworks: list[str] | None = None,
) -> dict[str, str]:
    """Find functions that act as framework-level deserialization sinks.

    Parameters
    ----------
    project_path : str
        Root of the project being scanned.
    function_index : FunctionIndex
        Project function index.
    detected_frameworks : list[str] | None
        Pre-detected frameworks. If None, auto-detect.

    Returns
    -------
    dict[str, str]
        Mapping of ``fullname`` → ``vuln_type`` (e.g. ``"RCE"``, ``"SUSPICIOUS"``)
        for discovered framework sink functions.
    """
    if detected_frameworks is None:
        detected_frameworks = detect_frameworks(project_path)

    if not detected_frameworks or not function_index:
        return {}

    if not hasattr(function_index, "funcs") or not function_index.funcs:
        return {}

    sinks: dict[str, str] = {}
    seen: set[str] = set()  # fullname dedup

    for fw in detected_frameworks:
        detectors = _FRAMEWORK_SINK_DETECTORS.get(fw, [])
        if not detectors:
            continue

        for fn in function_index.funcs:
            if fn.fullname in seen:
                continue
            for det in detectors:
                # Check function name pattern
                name_pat = det.get("function_name", re.compile(r".*"))
                if not name_pat.match(fn.name):
                    continue

                # Check body pattern (if specified). When body exists but
                # doesn't match, skip — the function doesn't contain the
                # expected call. When body is None (e.g. abstract/interface),
                # don't reject (the sink might be in a subclass).
                body_pat = det.get("body_pattern")
                if body_pat and fn.body and not body_pat.search(fn.body):
                    continue

                # Check class pattern (if specified)
                class_pat = det.get("class_pattern")
                if class_pat:
                    try:
                        with open(fn.file_path, "r", encoding="utf-8", errors="ignore") as f:
                            file_content = f.read(4096)
                        if not class_pat.search(file_content):
                            continue
                    except OSError:
                        continue

                # Check annotation pattern — read source context above function
                annot_pat = det.get("annotation_pattern")
                if annot_pat:
                    context = _read_function_context(fn.file_path, fn.line_start)
                    if not annot_pat.search(context):
                        continue

                vtype = det.get("vuln_type", "SUSPICIOUS")

                # Dedup by fullname: already registered, only upgrade RCE→RCE
                existing_vtype = sinks.get(fn.fullname, "")
                if existing_vtype:
                    if vtype == "RCE" and existing_vtype != "RCE":
                        sinks[fn.fullname] = vtype
                    continue

                seen.add(fn.fullname)
                sinks[fn.fullname] = vtype
                logger.debug(
                    "Framework sink: %s (%s) → %s via %s",
                    fn.fullname, fn.file_path, vtype, det["name"],
                )
                break  # first matching detector wins per function

    if sinks:
        logger.info(
            "Framework sink detection: %d framework-level sinks found",
            len(sinks),
        )

    return sinks
