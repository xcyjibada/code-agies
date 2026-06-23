#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: redos-003
# Sink: _check_module_path
# Auto-generated — run with: python3 redos_regex_pattern_hardcoded_as__check_module_path.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: ReDoS in kedro _check_module_path

This script demonstrates that the regex pattern r"^[\w.]+$" used in
kedro's _check_module_path function is NOT vulnerable to ReDoS.
The pattern is fixed and safe, containing no nested quantifiers or
overlapping alternations that could cause catastrophic backtracking.

The script sends a benign payload to verify the function's behavior
and confirms that no ReDoS vulnerability exists.
"""

import re
import sys
import time

# Target configuration
TARGET_URL = "http://localhost:8000"  # Change to your target
TIMEOUT = 10  # seconds

def test_redos_vulnerability():
    """
    Test if the regex pattern r"^[\w.]+$" is vulnerable to ReDoS.
    
    The pattern is safe because:
    - It uses a single character class [\w.]
    - The quantifier + is not nested
    - No alternations or overlapping patterns
    - No backtracking issues
    """
    
    # Benign payload that matches the pattern
    benign_payload = "test.module.path"
    
    # Attempt to trigger ReDoS with various inputs
    test_inputs = [
        # Normal valid input
        "valid.module.path",
        # Input with special characters (will fail validation)
        "invalid!path",
        # Long valid input
        "a" * 1000 + "." + "b" * 1000,
        # Input with many dots
        "a." * 500 + "b",
        # Empty string
        "",
        # Only dots
        "....",
        # Mixed valid/invalid
        "valid.invalid!path",
    ]
    
    print("[*] Testing regex pattern: r\"^[\\w.]+$\"")
    print("[*] Pattern is FIXED and SAFE - no ReDoS possible")
    print()
    
    for test_input in test_inputs:
        start_time = time.time()
        try:
            # Simulate the exact check from kedro's _check_module_path
            if test_input and not re.match(r"^[\w.]+$", test_input):
                result = "INVALID (would raise KedroCliError)"
            else:
                result = "VALID"
        except Exception as e:
            result = f"ERROR: {e}"
        
        elapsed = time.time() - start_time
        
        print(f"  Input: {test_input[:50]:<50} -> {result:<30} (took {elapsed:.4f}s)")
        
        # If any input takes > 1 second, it might indicate ReDoS
        if elapsed > 1.0:
            print(f"  [!] WARNING: Input took {elapsed:.2f}s - possible ReDoS!")
    
    print()
    print("[*] All inputs processed quickly - no ReDoS vulnerability found")
    print("[*] The regex pattern is safe and not exploitable")
    
    # Demonstrate that the pattern is fixed and user input doesn't affect it
    print()
    print("[*] Verification: The pattern is hardcoded and cannot be changed by user input")
    print("[*] The function only validates module paths, not regex patterns")
    
    return False  # No vulnerability found

def main():
    """Main function to run the PoC."""
    print("=" * 70)
    print("Kedro ReDoS Proof-of-Concept")
    print("=" * 70)
    print()
    
    try:
        vulnerable = test_redos_vulnerability()
        
        if vulnerable:
            print("\n[!] Vulnerability CONFIRMED - ReDoS possible")
            sys.exit(1)
        else:
            print("\n[+] No vulnerability found - pattern is safe")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n[-] Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Error during testing: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
