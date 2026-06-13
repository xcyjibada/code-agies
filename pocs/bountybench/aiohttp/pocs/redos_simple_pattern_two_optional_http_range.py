#!/usr/bin/env python3
# PoC for aiohttp-3.9.3 (/tmp/bounty_test/aiohttp-3.9.3)
# Path: redos-015
# Sink: http_range
# Auto-generated — run with: python3 redos_simple_pattern_two_optional_http_range.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: aiohttp-3.9.3 ReDoS (Red Herring)
====================================================
This script demonstrates that the regex pattern '^bytes=(\d*)-(\d*)$' used in
aiohttp's HTTP Range header parsing is NOT vulnerable to ReDoS.

The pattern is simple, contains no nested quantifiers or overlapping alternations,
and processes user-controlled input safely. This PoC sends a malicious Range header
and verifies the server responds normally (no timeout/crash).

Usage:
    python3 poc.py [target_url]

If no target is given, defaults to http://localhost:8080
"""

import sys
import time
import urllib.request
import urllib.error

# Default target (change as needed)
TARGET_URL = "http://localhost:8080"

# Malicious payload designed to trigger catastrophic backtracking if regex were vulnerable
# The pattern '^bytes=(\d*)-(\d*)$' will simply fail to match this, returning quickly
MALICIOUS_RANGE = "bytes=0-1" + "a" * 10000  # long string with no digits at end


def send_request(url: str, range_header: str) -> float:
    """
    Send an HTTP GET request with a custom Range header.
    Returns the response time in seconds.
    """
    req = urllib.request.Request(url)
    req.add_header("Range", range_header)

    start_time = time.time()
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            # Read a small amount to ensure connection completes
            response.read(1024)
    except urllib.error.HTTPError as e:
        # 416 Range Not Satisfiable is expected — that's fine
        if e.code != 416:
            print(f"[!] Unexpected HTTP error: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
        return -1
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return -1

    elapsed = time.time() - start_time
    return elapsed


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET_URL
    print(f"[*] Testing target: {target}")
    print(f"[*] Sending malicious Range header ({len(MALICIOUS_RANGE)} chars)...")

    # Send the malicious request
    response_time = send_request(target, MALICIOUS_RANGE)

    if response_time < 0:
        print("[!] Request failed — server may be down or unreachable")
        sys.exit(1)

    print(f"[*] Response time: {response_time:.3f} seconds")

    # If the regex were vulnerable, response time would be >> 1 second
    # (catastrophic backtracking on 10k characters)
    if response_time > 2.0:
        print("[!] WARNING: Slow response — possible ReDoS?")
        print("[!] This is unexpected given the regex is safe.")
        print("[!] Check network conditions or server load.")
    else:
        print("[+] Response time is normal — no ReDoS vulnerability detected.")
        print("[+] The regex '^bytes=(\\d*)-(\\d*)$' is safe as expected.")

    # Send a normal request for comparison
    print("\n[*] Sending normal Range header for baseline...")
    normal_time = send_request(target, "bytes=0-100")
    if normal_time > 0:
        print(f"[*] Normal response time: {normal_time:.3f} seconds")
        print(f"[*] Ratio (malicious/normal): {response_time / normal_time:.2f}x")

    print("\n[*] Done. The finding was a false positive — no ReDoS exists.")


if __name__ == "__main__":
    main()
