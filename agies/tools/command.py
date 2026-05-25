"""Command execution tool."""

import subprocess


def run_command(command: str, timeout: int = 30) -> str:
    """Run a shell command and return its output."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return f"Error: command timed out after {timeout}s"
    except OSError as e:
        return f"Error: {e}"

    output = ""
    if result.stdout:
        output += result.stdout
    if result.stderr:
        output += f"\n[stderr]\n{result.stderr}"

    output = output.strip()
    if not output:
        output = "(no output)"

    return f"Exit code: {result.returncode}\n{output}"
