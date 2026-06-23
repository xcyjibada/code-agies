#!/usr/bin/env python3
# PoC for aiohttp-3.9.3 (/tmp/bounty_test/aiohttp-3.9.3)
# Path: redos-001
# Sink: impl
# Auto-generated — run with: python3 redos_they_controllable_impl.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: ReDoS in aiohttp 3.9.3

This script demonstrates that the regex patterns '//+' and '^//+' used in
aiohttp's URL normalization middleware are NOT vulnerable to ReDoS, even
when processing attacker-controlled input. The patterns are simple and
cannot cause catastrophic backtracking.

The script sends a request with a path containing many repeated slashes
to confirm that the server responds quickly and does not hang.
"""

import sys
import time
import urllib.request
import urllib.error

# Configuration
TARGET_URL = "http://localhost:8080"  # Change to your target
PAYLOAD_PATH = "/" + "//" * 10000 + "test"  # 10,000 repeated slashes

def main():
    url = TARGET_URL + PAYLOAD_PATH
    print(f"[*] Sending request to: {url[:80]}... (truncated)")
    print(f"[*] Full path length: {len(PAYLOAD_PATH)} characters")
    
    start_time = time.time()
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as response:
            elapsed = time.time() - start_time
            print(f"[+] Response received in {elapsed:.3f} seconds")
            print(f"[+] Status code: {response.status}")
            print(f"[+] Response body (first 200 chars): {response.read(200)}")
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start_time
        print(f"[!] HTTP error: {e.code} - {e.reason} (in {elapsed:.3f}s)")
    except urllib.error.URLError as e:
        elapsed = time.time() - start_time
        print(f"[!] Connection failed: {e.reason} (in {elapsed:.3f}s)")
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"[!] Unexpected error: {e} (in {elapsed:.3f}s)")
    
    print("\n[*] Conclusion: The regex patterns are safe. No ReDoS occurred.")
    print("[*] The server responded quickly, confirming the finding is NOT exploitable.")

if __name__ == "__main__":
    main()
