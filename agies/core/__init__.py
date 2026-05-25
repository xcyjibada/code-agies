"""Project context collector."""

import os


def collect_context(target: str) -> dict:
    """Gather basic project context for the audit."""
    target = os.path.abspath(target)
    if not os.path.exists(target):
        return {"error": f"Target does not exist: {target}"}

    context = {
        "target": target,
        "is_dir": os.path.isdir(target),
        "file_count": 0,
        "languages": set(),
        "dependencies": {},
        "entry_points": [],
    }

    if os.path.isfile(target):
        context["file_count"] = 1
        ext = os.path.splitext(target)[1]
        context["languages"].add(_ext_to_lang(ext))
        context["entry_points"].append(os.path.basename(target))
        return _finalize(context)

    # Scan directory structure
    for root, dirs, files in os.walk(target):
        # Skip hidden dirs and common non-code dirs
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "venv", ".venv", "__pycache__", "dist", "build")]

        for f in files:
            ext = os.path.splitext(f)[1]
            lang = _ext_to_lang(ext)
            if lang:
                context["languages"].add(lang)

            context["file_count"] += 1

            # Track key config files
            if f == "package.json":
                context["entry_points"].append(os.path.join(root, f))
            elif f == "requirements.txt":
                context["entry_points"].append(os.path.join(root, f))
            elif f == "pyproject.toml":
                context["entry_points"].append(os.path.join(root, f))

    return _finalize(context)


def collect_files(target: str) -> list[str]:
    """Return a sorted list of all file paths under target."""
    target = os.path.abspath(target)
    if os.path.isfile(target):
        return [target]

    files = []
    for root, dirs, names in os.walk(target):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "venv", ".venv", "__pycache__", "dist", "build")]
        for name in names:
            files.append(os.path.join(root, name))
    return sorted(files)


def _ext_to_lang(ext: str) -> str | None:
    mapping = {
        ".py": "Python",
        ".js": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript React",
        ".jsx": "JavaScript React",
        ".go": "Go",
        ".rs": "Rust",
        ".java": "Java",
        ".sol": "Solidity",
        ".yaml": "YAML",
        ".yml": "YAML",
        ".json": "JSON",
        ".sh": "Shell",
        ".bash": "Shell",
    }
    return mapping.get(ext)


def _finalize(context: dict) -> dict:
    context["languages"] = sorted(context["languages"])
    return context
