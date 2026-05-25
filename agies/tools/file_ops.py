"""File read and directory listing tools."""


def read_file(path: str, start_line: int = 1, end_line: int | None = None) -> str:
    """Read a file or a range of lines from a file."""
    from agies.engine.router import validate_tool_call
    err = validate_tool_call("read_file", {"file_path": path})
    if err:
        return f"Error: {err}"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return f"Error: file not found: {path}"
    except PermissionError:
        return f"Error: permission denied: {path}"
    except IsADirectoryError:
        return f"Error: path is a directory: {path}"

    total = len(lines)
    if end_line is None or end_line > total:
        end_line = total
    if start_line < 1:
        start_line = 1
    if start_line > total:
        return f"Error: start_line {start_line} exceeds file length ({total} lines)"

    result = []
    for i in range(start_line - 1, end_line):
        result.append(f"{i + 1:6d}  {lines[i].rstrip()}")

    # Context Armor: hard cap at 150 lines to prevent context flooding.
    if len(result) > 150:
        result = result[:150]
        result.append(
            "... [TRUNCATED: File too long. Use start_line/end_line.] ..."
        )

    header = f"{path} (lines {start_line}-{end_line} of {total})"
    return header + "\n" + "\n".join(result) + "\n"


def list_directory(path: str) -> str:
    """List files and directories in a path."""
    import os
    import stat

    try:
        entries = os.scandir(path)
    except FileNotFoundError:
        return f"Error: directory not found: {path}"
    except PermissionError:
        return f"Error: permission denied: {path}"
    except NotADirectoryError:
        return f"Error: not a directory: {path}"

    items = []
    for entry in sorted(entries, key=lambda e: (not e.is_dir(), e.name.lower())):
        if entry.name.startswith("."):
            continue
        if entry.is_dir():
            items.append(f"  [DIR]  {entry.name}/")
        elif entry.is_file():
            size = entry.stat().st_size
            if size < 1024:
                size_str = f"{size}B"
            elif size < 1024 * 1024:
                size_str = f"{size // 1024}KB"
            else:
                size_str = f"{size // (1024 * 1024)}MB"
            items.append(f"  {size_str:>6}  {entry.name}")
    return f"{path}/\n" + "\n".join(items)
