"""Project type classifier for dual-pipeline routing.

Scans the target directory for web framework patterns to determine
whether the code is an **application** (web app with routes) or a
**library** (framework, SDK, utility).

Usage::

    ptype = classify_project("/path/to/project")
    # ptype → "app" or "lib"
"""

from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)

# Web framework patterns — if any of these are found, it's an "app"
_WEB_PATTERNS: list[re.Pattern] = [
    # Flask
    re.compile(r"@\w+\.route\s*\(", re.IGNORECASE),
    re.compile(r"@\w+\.(get|post|put|delete|patch)\s*\(", re.IGNORECASE),
    re.compile(r"from flask import", re.IGNORECASE),
    # FastAPI
    re.compile(r"@\w+\.(get|post|put|delete|patch|websocket)\s*\(", re.IGNORECASE),
    re.compile(r"from fastapi import", re.IGNORECASE),
    re.compile(r"from fastapi\.routing", re.IGNORECASE),
    re.compile(r"APIRouter|FastAPI\(", re.IGNORECASE),
    # Django
    re.compile(r"urlpatterns\s*=", re.IGNORECASE),
    re.compile(r"from django\.urls", re.IGNORECASE),
    re.compile(r"from django\.conf\.urls", re.IGNORECASE),
    re.compile(r"[^a-zA-Z.]path\s*\([\"']"),
    re.compile(r"re_path\s*\(", re.IGNORECASE),
    # aiohttp
    re.compile(r"@\w+\.(get|post|put|delete|patch)\s*\(", re.IGNORECASE),
    re.compile(r"from aiohttp import web", re.IGNORECASE),
    re.compile(r"aiohttp\.web", re.IGNORECASE),
    re.compile(r"routes\s*=\s*web\.RouteTableDef", re.IGNORECASE),
    # Starlette
    re.compile(r"from starlette\.routing", re.IGNORECASE),
    re.compile(r"@\w+\.route\s*\(", re.IGNORECASE),
    # Gradio
    re.compile(r"gr\.Interface\s*\(", re.IGNORECASE),
    re.compile(r"gr\.(Chat|Blocks|TabbedInterface)\s*\(", re.IGNORECASE),
    # Generic web entry points
    re.compile(r"async def \w+\(.*request.*\)", re.IGNORECASE),
    re.compile(r"def \w+\(.*request.*\)", re.IGNORECASE),
    re.compile(r"\.listen\s*\(\d+", re.IGNORECASE),  # FastAPI uvicorn.run
    re.compile(r"uvicorn\.run", re.IGNORECASE),
]


# Library/package indicators — signals that the code is a library not an app
_LIB_PATTERNS: list[re.Pattern] = [
    re.compile(r"from \w+ import \w+", re.IGNORECASE),
    re.compile(r"__all__\s*=", re.IGNORECASE),
    re.compile(r"__version__\s*=", re.IGNORECASE),
]

# Test directories — skip these
_EXCLUDED_DIRS: set[str] = {
    ".git", "__pycache__", "node_modules", "venv", ".venv",
    "dist", "build", ".tox", ".eggs", "egg-info",
    ".mypy_cache", ".pytest_cache", "tests", "test",
    "docs", "examples",
}


def classify_project(project_path: str) -> str:
    """Auto-detect project type: ``"app"`` or ``"lib"``.

    Scans up to 50 Python files (excluding test dirs) for web
    framework patterns. If any are found, returns ``"app"``.
    Defaults to ``"lib"``.
    """
    if not os.path.isdir(project_path):
        return "lib"

    py_files = _walk_python_files(project_path, max_files=50)

    for fp in py_files:
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            continue

        for pat in _WEB_PATTERNS:
            if pat.search(content):
                logger.info("Project type: app (matched %s in %s)", pat.pattern[:40], fp)
                return "app"

    logger.info("Project type: lib (no web framework patterns found)")
    return "lib"


def _walk_python_files(root: str, max_files: int = 50) -> list[str]:
    """Walk a directory tree and return up to *max_files* .py files."""
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip excluded dirs
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS]
        for fn in filenames:
            if fn.endswith(".py") and len(files) < max_files:
                files.append(os.path.join(dirpath, fn))
            if len(files) >= max_files:
                return files
    return files
