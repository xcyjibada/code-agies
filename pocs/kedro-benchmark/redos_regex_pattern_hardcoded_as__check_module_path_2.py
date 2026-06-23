#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: redos-003
# Sink: _check_module_path
# Auto-generated — run with: python3 redos_regex_pattern_hardcoded_as__check_module_path_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: ReDoS in kedro _check_module_path

This script demonstrates that the regex pattern r"^[\w.]+$" used in
kedro's _check_module_path function is NOT vulnerable to ReDoS.
The pattern is hardcoded and contains no nested quantifiers or
overlapping alternations, making it safe even with user-controlled input.

The script will:
1. Test the regex against various payloads (including potentially malicious ones)
2. Show that the regex completes instantly for all inputs
3. Confirm that no ReDoS is possible

Usage:
    python3 poc_kedro_redos.py [--target TARGET_URL]
"""

import re
import time
import sys
import argparse

# The regex pattern from kedro's _check_module_path
SAFE_PATTERN = r"^[\w.]+$"

# Test payloads - including ones that would trigger ReDoS in vulnerable patterns
TEST_PAYLOADS = [
    # Normal valid inputs
    "valid.module.path",
    "simple",
    "a.b.c.d.e.f.g",
    
    # Invalid inputs (should fail fast)
    "",
    "invalid path with spaces",
    "path/with/slashes",
    "path-with-dashes",
    
    # Potentially problematic inputs for vulnerable patterns
    "." * 1000,  # 1000 dots
    "a" * 10000,  # 10000 word characters
    "a." * 5000,  # alternating pattern
    "a" * 100 + "." * 100 + "b" * 100,  # mixed long strings
    
    # Backtracking-heavy patterns (if pattern were vulnerable)
    "a" * 100 + "!" + "a" * 100,  # would cause catastrophic backtracking in vulnerable patterns
    "a" * 1000 + "!" + "a" * 1000,
    
    # Unicode word characters
    "café.über.straße",
    "中文.测试.路径",
    
    # Edge cases
    "_" * 10000,  # underscores are word characters
    "test." * 2000 + "end",  # many dots with content
]

def test_regex_safety():
    """Test that the regex pattern is safe against ReDoS."""
    print("=" * 70)
    print("Testing kedro _check_module_path regex for ReDoS vulnerability")
    print("Pattern: r\"^[\\w.]+$\"")
    print("=" * 70)
    print()
    
    compiled_pattern = re.compile(SAFE_PATTERN)
    
    all_safe = True
    max_time = 0.0
    
    for i, payload in enumerate(TEST_PAYLOADS, 1):
        # Time the regex match
        start_time = time.perf_counter()
        try:
            result = bool(compiled_pattern.match(payload))
        except Exception as e:
            print(f"  [{i:2d}] ERROR: {type(e).__name__}: {e}")
            all_safe = False
            continue
        
        elapsed = time.perf_counter() - start_time
        max_time = max(max_time, elapsed)
        
        # Show results for interesting cases
        if elapsed > 0.1 or len(payload) > 100 or i <= 5:
            status = "✓ MATCH" if result else "✗ NO MATCH"
            print(f"  [{i:2d}] {status} | Time: {elapsed:.6f}s | Len: {len(payload):6d} | Payload: {payload[:80]}{'...' if len(payload) > 80 else ''}")
    
    print()
    print("-" * 70)
    print(f"Results: Max time: {max_time:.6f}s")
    print(f"Verdict: {'SAFE' if all_safe else 'POTENTIALLY VULNERABLE'}")
    print()
    
    if max_time < 1.0:
        print("✓ The regex completes instantly for all tested inputs.")
        print("  No ReDoS vulnerability exists in this pattern.")
        print()
        print("Explanation:")
        print("  The pattern r\"^[\\w.]+$\" uses a single character class [\\w.]")
        print("  with a possessive-like quantifier (+). There are no nested")
        print("  quantifiers, no alternations, and no overlapping patterns.")
        print("  This makes it inherently safe against ReDoS attacks.")
    else:
        print("⚠ Warning: Some inputs took significant time to process.")
        print("  This may indicate a potential ReDoS vulnerability.")
    
    return all_safe

def main():
    parser = argparse.ArgumentParser(
        description="PoC: Test kedro _check_module_path regex for ReDoS"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (not used in this PoC as the vulnerability is local)"
    )
    args = parser.parse_args()
    
    print(f"Target: {args.target}")
    print("(Note: This PoC tests the regex locally, no network connection needed)")
    print()
    
    is_safe = test_regex_safety()
    
    if is_safe:
        print()
        print("=" * 70)
        print("CONCLUSION: The finding is a FALSE POSITIVE.")
        print("The regex pattern r\"^[\\w.]+$\" is NOT vulnerable to ReDoS.")
        print("=" * 70)
        sys.exit(0)
    else:
        print()
        print("=" * 70)
        print("CONCLUSION: Unexpected behavior detected.")
        print("The pattern may have unexpected performance characteristics.")
        print("=" * 70)
        sys.exit(1)

if __name__ == "__main__":
    main()
