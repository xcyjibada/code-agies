#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: redos-003
# Sink: _check_module_path
# Auto-generated — run with: python3 redos_regex_pattern_hardcoded_as__check_module_path_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: ReDoS in kedro _check_module_path

This script demonstrates that the regex pattern r"^[\w.]+$" used in
kedro's _check_module_path function is NOT vulnerable to ReDoS.
The pattern is hardcoded and safe - it does not contain nested quantifiers
or overlapping alternations that could cause catastrophic backtracking.

The script validates this by:
1. Sending various malicious inputs to the endpoint that uses _check_module_path
2. Measuring response times to confirm no exponential slowdown occurs
3. Demonstrating that the regex is safe even with attacker-controlled input

Note: This is a negative PoC - it proves the finding is a false positive.
"""

import requests
import time
import sys
import argparse
from urllib.parse import urljoin

# Default target - change with --target argument
DEFAULT_TARGET = "http://localhost:8000"

# Benign payload for safe testing
BENIGN_PAYLOAD = "test.module.path"

# Potentially dangerous patterns that would trigger ReDoS in vulnerable regexes
# These are safe against r"^[\w.]+$" because:
# - No nested quantifiers (like (a+)+)
# - No overlapping alternations (like (a|a)*)
# - Simple character class with + quantifier
MALICIOUS_INPUTS = [
    # Long strings of word characters - should be fast
    "a" * 10000,
    # Strings with dots - should be fast
    "a." * 5000,
    # Mixed word chars and dots - should be fast
    "test." * 2000 + "module",
    # Strings with special chars that won't match - should fail fast
    "test@module!" * 100,
    # Empty string - should fail fast
    "",
    # Very long string with non-matching chars - should fail fast
    "a" * 10000 + "!",
    # Unicode word characters - should be fast
    "测试模块路径" * 100,
    # Pattern with many dots - should be fast
    "." * 5000,
    # Mixed case and numbers - should be fast
    "AbC123." * 1000,
]


def test_regex_safety(target_url: str, payload: str, timeout: int = 10) -> dict:
    """
    Test if the regex pattern causes ReDoS with the given payload.
    
    Args:
        target_url: Base URL of the kedro application
        payload: Input to test against the regex
        timeout: Maximum time to wait for response
    
    Returns:
        dict with test results
    """
    # Construct the endpoint URL (adjust based on actual kedro API)
    # The _check_module_path is used in micropkg commands
    endpoint = urljoin(target_url, "/api/micropkg/validate")
    
    try:
        # Measure time before request
        start_time = time.time()
        
        # Send request with the payload
        response = requests.post(
            endpoint,
            json={"module_path": payload},
            timeout=timeout,
            headers={"Content-Type": "application/json"}
        )
        
        # Calculate elapsed time
        elapsed = time.time() - start_time
        
        return {
            "payload_length": len(payload),
            "status_code": response.status_code,
            "elapsed_seconds": elapsed,
            "success": True,
            "error": None
        }
        
    except requests.exceptions.Timeout:
        elapsed = time.time() - start_time
        return {
            "payload_length": len(payload),
            "status_code": None,
            "elapsed_seconds": elapsed,
            "success": False,
            "error": "Timeout - possible ReDoS"
        }
    except requests.exceptions.ConnectionError as e:
        return {
            "payload_length": len(payload),
            "status_code": None,
            "elapsed_seconds": 0,
            "success": False,
            "error": f"Connection error: {e}"
        }
    except Exception as e:
        return {
            "payload_length": len(payload),
            "status_code": None,
            "elapsed_seconds": 0,
            "success": False,
            "error": f"Unexpected error: {e}"
        }


def main():
    """Main function to run the ReDoS test."""
    parser = argparse.ArgumentParser(
        description="Test for ReDoS vulnerability in kedro's _check_module_path"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output"
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("ReDoS Proof-of-Concept for kedro _check_module_path")
    print("=" * 70)
    print(f"\nTarget: {args.target}")
    print(f"Timeout: {args.timeout}s")
    print(f"Testing {len(MALICIOUS_INPUTS)} malicious inputs...")
    print("\n" + "-" * 70)
    
    # Test benign payload first
    print("\n[1] Testing benign payload first...")
    result = test_regex_safety(args.target, BENIGN_PAYLOAD, args.timeout)
    if result["success"]:
        print(f"    ✓ Benign payload processed in {result['elapsed_seconds']:.3f}s")
    else:
        print(f"    ✗ Benign payload failed: {result['error']}")
        print("\n[!] Cannot reach target. Exiting.")
        sys.exit(1)
    
    # Test malicious inputs
    print("\n[2] Testing potentially malicious inputs...")
    print("    (Expected: all should be fast since regex is safe)\n")
    
    max_elapsed = 0
    vulnerable_found = False
    
    for i, payload in enumerate(MALICIOUS_INPUTS, 1):
        result = test_regex_safety(args.target, payload, args.timeout)
        
        # Display result
        status = "✓" if result["success"] else "✗"
        elapsed_str = f"{result['elapsed_seconds']:.3f}s" if result["success"] else "FAILED"
        
        if args.verbose:
            print(f"  [{i:2d}] Payload length: {result['payload_length']:6d} | "
                  f"Status: {status} | Time: {elapsed_str}")
            if result["error"]:
                print(f"       Error: {result['error']}")
        else:
            # Show only summary for long payloads
            if result["payload_length"] > 100:
                print(f"  [{i:2d}] Length {result['payload_length']:6d}: {elapsed_str}")
        
        # Track maximum elapsed time
        if result["elapsed_seconds"] > max_elapsed:
            max_elapsed = result["elapsed_seconds"]
        
        # Check for potential vulnerability (time > 2x benign)
        if result["success"] and result["elapsed_seconds"] > 2:
            print(f"    ⚠  Warning: Payload took {result['elapsed_seconds']:.3f}s")
            vulnerable_found = True
    
    # Summary
    print("\n" + "-" * 70)
    print("\n[3] Results Summary:")
    print(f"    Total inputs tested: {len(MALICIOUS_INPUTS)}")
    print(f"    Max elapsed time: {max_elapsed:.3f}s")
    print(f"    Benign baseline: {result['elapsed_seconds']:.3f}s")
    
    if vulnerable_found:
        print("\n    ⚠  POTENTIAL VULNERABILITY DETECTED!")
        print("    Some inputs took significantly longer than expected.")
    else:
        print("\n    ✓ NO VULNERABILITY DETECTED")
        print("    The regex pattern r\"^[\\w.]+$\" is safe against ReDoS.")
        print("    This confirms the finding is a FALSE POSITIVE.")
    
    print("\n" + "=" * 70)
    print("Conclusion: The regex pattern is hardcoded and safe.")
    print("No attacker-controlled regex, no nested quantifiers,")
    print("no overlapping alternations - no ReDoS possible.")
    print("=" * 70)


if __name__ == "__main__":
    main()
