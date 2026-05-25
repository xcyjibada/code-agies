"""Walk project files, extract functions, and build a FunctionIndex.

Usage::

    index = build_index("/path/to/project")
    print(index.summary())
"""

from __future__ import annotations

import os

from agies.engine.sourcer.extractor import (
    LANGUAGE_PARSERS,
    extract_call_graph,
    extract_functions,
)
from agies.engine.sourcer.models import FunctionIndex, SourceFile

# Files containing these import patterns get full function extraction even
# when outside the Director's hot/warm set.  Without this, trivial wrappers
# around shelve/pickle/yaml/etc. in "cold" files are never extracted, so
# Phase 1 bulk analysis never even sees them.
_DANGEROUS_IMPORT_PATTERNS = frozenset({
    "import shelve", "from shelve",
    "import pickle", "from pickle",
    "import marshal", "from marshal",
    "import yaml", "from yaml",
    "import subprocess", "from subprocess",
    "import tarfile", "from tarfile",
    "import zipfile", "from zipfile",
})


# Directories always skipped when walking
EXCLUDED_DIRS = frozenset({
    ".git", ".svn", "__pycache__", "node_modules", "venv", ".venv",
    ".env", "dist", "build", ".tox", ".eggs", "egg-info",
    ".idea", ".vscode", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".terraform", ".next", ".nuxt",
})

# File extensions we can parse
SUPPORTED_EXTS = frozenset(LANGUAGE_PARSERS.keys())

# ── Noise file heuristics ──────────────────────────────────────────────

# Skip files larger than this (bytes).  Bundled JS libs easily exceed this.
MAX_FILE_SIZE = 512 * 1024  # 500 KB

# Files whose average line length exceeds this are likely minified/bundled.
MAX_AVG_LINE_LEN = 200

# Naming patterns that indicate third-party bundled/vendored code.
NOISE_NAME_PATTERNS = frozenset({
    ".min.js", ".min.css",
    "-bundle.js", ".bundle.js",
    "-min.js",
})
NOISE_DIR_FRAGMENTS = frozenset({
    "/vendor/", "/vendors/", "/third_party/", "/third-party/",
})


def _is_noise_file(fpath: str, text: str) -> bool:
    """Return True if *fpath* is likely a third-party bundled/minified file.

    Three heuristic checks (cheapest first):
      1. Naming pattern  (constant-time, no I/O)
      2. File size       (stat, no content read)
      3. Line length     (requires text — call after reading)
    """
    basename = os.path.basename(fpath)
    # Check C: naming patterns
    for pat in NOISE_NAME_PATTERNS:
        if basename.endswith(pat) or basename.endswith(pat.lower()):
            return True
    norm_path = fpath.replace("\\", "/")
    for frag in NOISE_DIR_FRAGMENTS:
        if frag in norm_path:
            return True

    # Check B: file size (stat is cheap)
    try:
        if os.path.getsize(fpath) > MAX_FILE_SIZE:
            return True
    except OSError:
        pass

    # Check A: average line length (sample first 20 non-empty lines)
    if text:
        lines = [l for l in text.splitlines()[:20] if l.strip()]
        if lines:
            avg = sum(len(l) for l in lines) / len(lines)
            if avg > MAX_AVG_LINE_LEN:
                return True

    return False


def build_index(
    project_path: str,
    full_index_paths: set[str] | None = None,
) -> FunctionIndex:
    """Walk *project_path*, parse supported files, return a populated FunctionIndex.

    Parameters
    ----------
    project_path : str
        Root directory of the project to index.
    full_index_paths : set[str] | None
        When provided (from Director cards), only files in this set receive
        full AST extraction (functions + call graph). Other files get basic
        source metadata only.  When ``None`` (no Director data available),
        every parseable file gets full extraction (legacy behaviour).

        Paths are normalized against *project_path* so that relative paths
        like ``src/app.py`` are resolved correctly.
    """
    index = FunctionIndex()

    # Normalise full_index_paths to absolute, if provided
    if full_index_paths is not None:
        resolved: set[str] = set()
        for p in full_index_paths:
            if os.path.isabs(p):
                resolved.add(os.path.normpath(p))
            else:
                resolved.add(os.path.normpath(os.path.join(project_path, p)))
        full_index_paths = resolved

    for root, dirs, files in os.walk(project_path):
        # Prune excluded directories in-place (affects os.walk behaviour)
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SUPPORTED_EXTS:
                continue

            fpath = os.path.normpath(os.path.join(root, fname))
            try:
                with open(fpath, "rb") as f:
                    raw = f.read()
            except OSError:
                continue

            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue

            # Skip third-party bundled/minified files (type 14 noise guard)
            if _is_noise_file(fpath, text):
                continue

            sf = SourceFile(path=fpath, source=text)

            # When full_index_paths is set, only extract functions for
            # files the Director identified as hot/warm — unless the file
            # contains dangerous imports (shelve/pickle/yaml/subprocess etc.)
            # that warrant full extraction regardless.
            do_full = True
            if full_index_paths is not None:
                do_full = fpath in full_index_paths
            if not do_full:
                do_full = any(p in text for p in _DANGEROUS_IMPORT_PATTERNS)

            if do_full:
                funcs = extract_functions(sf)
                index.add(sf, funcs)

                # Build call graph for this file
                if funcs:
                    try:
                        calls = extract_call_graph(sf)
                        if calls:
                            index.build_call_graph_from_calls(calls)
                    except Exception:
                        # Gracefully degrade — call graph is best-effort
                        pass
            else:
                # Basic metadata only — add file without function extraction
                index.sources[sf.path] = sf

    index.build_lut()
    return index


def count_supported_files(project_path: str) -> int:
    """Quick count of parseable files without extracting functions."""
    count = 0
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in SUPPORTED_EXTS:
                count += 1
    return count
