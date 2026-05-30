"""Code search tool using ripgrep (with grep fallback)."""

import subprocess
import shutil


def _find_rg() -> str | None:
    """Locate rg binary, checking common paths."""
    # Check PATH
    rg = shutil.which("rg")
    if rg:
        return rg
    # Common fallback locations
    for p in ["/usr/bin/rg", "/usr/local/bin/rg", f"{__import__('os').path.expanduser('~')}/.local/bin/rg"]:
        import os as _os
        if _os.path.isfile(p):
            return p
    return None


def grep_search(pattern: str, path: str, glob: str | None = None) -> str:
    """Search for a pattern in files using ripgrep (falls back to grep)."""
    from agies.engine.v2.router import validate_tool_call
    err = validate_tool_call("grep_search", {"pattern": pattern, "glob": glob})
    if err:
        return f"Error: {err}"
    rg_path = _find_rg()
    if rg_path:
        return _rg_search(rg_path, pattern, path, glob)
    return _grep_fallback(pattern, path, glob)


def _rg_search(rg_path: str, pattern: str, path: str, glob: str | None = None) -> str:
    cmd = [rg_path, "-n", "--heading", "--color", "never"]
    if glob:
        cmd.extend(["--glob", glob])
    cmd.extend([pattern, path])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return "Error: search timed out (30s)"

    if result.returncode == 0:
        lines = result.stdout.split("\n")
        if len(lines) > 10:
            lines = lines[:10] + ["... [TRUNCATED: Refine your search] ..."]
        return "\n".join(lines)
    elif result.returncode == 1:
        return "No matches found."
    else:
        return f"Error: rg exited with code {result.returncode}\n{result.stderr[:500]}"


def _grep_fallback(pattern: str, path: str, glob: str | None = None) -> str:
    """Fallback to grep when ripgrep is not available."""
    import os, fnmatch

    matches = []
    pattern_compiled = __import__('re').compile(pattern)

    def search_file(filepath: str):
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f, 1):
                    if pattern_compiled.search(line):
                        matches.append(f"{filepath}:{i}:{line.rstrip()[:200]}")
        except (PermissionError, IsADirectoryError):
            pass

    if os.path.isfile(path):
        search_file(path)
    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "venv", ".venv", "__pycache__")]
            for fname in files:
                if glob and not fnmatch.fnmatch(fname, glob):
                    continue
                search_file(os.path.join(root, fname))

    if not matches:
        return "No matches found."
    if len(matches) > 10:
        matches = matches[:10] + ["... [TRUNCATED: Refine your search] ..."]
    return "\n".join(matches)
