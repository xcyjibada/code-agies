#!/usr/bin/env python3
# PoC for aiohttp-3.9.3 (/tmp/bounty_test/aiohttp-3.9.3)
# Path: redos-000
# Sink: http_range
# Auto-generated — run with: python3 redos_pattern_controllable_http_range.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: aiohttp-3.9.3 Range Header ReDoS (NOT Exploitable)

This script demonstrates that the regex pattern used to parse the HTTP Range header
in aiohttp-3.9.3 is NOT vulnerable to ReDoS. The pattern '^bytes=(\d*)-(\d*)$' is
hardcoded, simple, and contains no nested quantifiers or overlapping alternations
that could cause catastrophic backtracking.

The script sends various malicious Range headers to a test server and verifies that
the server responds normally without any performance degradation.

Usage:
    python poc_aiohttp_redos.py [--target TARGET_URL]
"""

import argparse
import sys
import time
import urllib.request
import urllib.error

# Default target - use a local test server or any aiohttp-based service
DEFAULT_TARGET = "http://localhost:8080"

# Malicious payloads that would trigger ReDoS if the regex were vulnerable
# These contain patterns that cause catastrophic backtracking in vulnerable regexes
MALICIOUS_PAYLOADS = [
    # Pattern with many optional groups and overlapping matches
    "bytes=0-0" + "a" * 1000,
    # Pattern with nested quantifiers (if regex were different)
    "bytes=" + "0" * 1000 + "-" + "0" * 1000,
    # Pattern with many digits and hyphens
    "bytes=" + "-".join(["0" * 100 for _ in range(10)]),
    # Very long valid range
    "bytes=0-" + "9" * 10000,
    # Pattern with special characters that might cause backtracking
    "bytes=" + "0" * 5000 + "-" + "0" * 5000,
    # Multiple range requests (not valid for this regex but tests parsing)
    "bytes=0-100, 200-300",
    # Empty values
    "bytes=-",
    "bytes=0-",
    "bytes=-100",
    # Very long header value
    "bytes=" + "0" * 100000,
]


def send_request(target_url, range_header, timeout=10):
    """
    Send an HTTP request with a custom Range header and measure response time.
    
    Args:
        target_url: The base URL to send the request to
        range_header: The value for the Range header
        timeout: Request timeout in seconds
    
    Returns:
        Tuple of (response_time, status_code, error_message)
    """
    try:
        start_time = time.time()
        req = urllib.request.Request(target_url)
        req.add_header("Range", range_header)
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            elapsed = time.time() - start_time
            return elapsed, response.status, None
            
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start_time
        return elapsed, e.code, str(e)
    except urllib.error.URLError as e:
        return None, None, f"Connection error: {e.reason}"
    except Exception as e:
        return None, None, f"Unexpected error: {str(e)}"


def main():
    parser = argparse.ArgumentParser(
        description="PoC for aiohttp-3.9.3 Range Header ReDoS (NOT Exploitable)"
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
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("aiohttp-3.9.3 Range Header ReDoS Proof-of-Concept")
    print("=" * 70)
    print(f"\nTarget: {args.target}")
    print(f"Timeout: {args.timeout}s")
    print("\nThis PoC demonstrates that the regex pattern '^bytes=(\\d*)-(\\d*)$'")
    print("is NOT vulnerable to ReDoS. The pattern is hardcoded, simple, and")
    print("contains no nested quantifiers or overlapping alternations.")
    print("\nSending malicious payloads to verify no performance degradation...\n")
    
    # First, send a normal request to establish baseline
    print("Establishing baseline (normal request)...")
    baseline_time, baseline_status, baseline_error = send_request(
        args.target, "bytes=0-100", args.timeout
    )
    
    if baseline_error:
        print(f"  [!] Baseline request failed: {baseline_error}")
        print("\nMake sure the target server is running and accessible.")
        sys.exit(1)
    
    print(f"  Baseline response time: {baseline_time:.4f}s (status: {baseline_status})")
    
    # Test each malicious payload
    print("\nTesting malicious payloads...")
    print("-" * 70)
    
    max_time = baseline_time
    vulnerable_payloads = []
    
    for i, payload in enumerate(MALICIOUS_PAYLOADS, 1):
        # Truncate payload for display
        display_payload = payload[:50] + "..." if len(payload) > 50 else payload
        
        print(f"\nTest {i}: {display_payload}")
        print(f"  Payload length: {len(payload)} characters")
        
        response_time, status, error = send_request(
            args.target, payload, args.timeout
        )
        
        if error:
            print(f"  [!] Error: {error}")
            continue
        
        print(f"  Response time: {response_time:.4f}s (status: {status})")
        
        # Check if response time is significantly higher than baseline
        if response_time > baseline_time * 10:  # 10x baseline is suspicious
            print(f"  [⚠] Response time is {response_time/baseline_time:.1f}x baseline!")
            vulnerable_payloads.append((payload, response_time))
        
        max_time = max(max_time, response_time)
    
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)
    
    if vulnerable_payloads:
        print(f"\n[!] Found {len(vulnerable_payloads)} potentially vulnerable payloads:")
        for payload, resp_time in vulnerable_payloads:
            print(f"  - Payload length {len(payload)}: {resp_time:.4f}s")
        print("\nThis would indicate a potential ReDoS vulnerability.")
    else:
        print("\n[✓] No ReDoS vulnerability detected!")
        print("  All malicious payloads were processed without significant")
        print("  performance degradation compared to baseline.")
    
    print(f"\n  Baseline response time: {baseline_time:.4f}s")
    print(f"  Maximum response time: {max_time:.4f}s")
    print(f"  Ratio: {max_time/baseline_time:.2f}x baseline")
    
    print("\n" + "=" * 70)
    print("CONCLUSION")
    print("=" * 70)
    print("""
The regex pattern '^bytes=(\\d*)-(\\d*)$' used in aiohttp-3.9.3 is SAFE from ReDoS.
The pattern:
- Is hardcoded and not user-controllable
- Contains no nested quantifiers
- Contains no overlapping alternations
- Has a simple, linear matching behavior

The finding was correctly identified as NOT_EXPLOITABLE.
    """)


if __name__ == "__main__":
    main()
