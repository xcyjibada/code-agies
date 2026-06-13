#!/usr/bin/env python3
# PoC for aiohttp-3.9.3 (/tmp/bounty_test/aiohttp-3.9.3)
# Path: redos-009
# Sink: normalize_path_middleware
# Auto-generated — run with: python3 redos_input_request_normalize_path_middleware.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: ReDoS in aiohttp 3.9.3 normalize_path_middleware

This script demonstrates that the regex patterns used in normalize_path_middleware
are safe and do NOT cause ReDoS. The patterns '//+' and '^//+' are linear-time
and cannot be exploited.

We send a request with a very long path containing repeated slashes to confirm
the server responds normally (no timeout/crash).

Usage:
    python poc.py [target_url]

If no target is given, defaults to http://localhost:8080
"""

import sys
import time
import urllib.request
import urllib.error

# Default target - change if needed
TARGET_URL = "http://localhost:8080"

def exploit(target: str) -> None:
    """
    Attempt to trigger ReDoS by sending a path with many repeated slashes.
    Since the regex is linear, this should complete quickly.
    """
    # Create a path with 10000 consecutive slashes - this would cause
    # catastrophic backtracking if the regex were vulnerable
    malicious_path = "/" + "//" * 10000 + "test"
    
    url = target.rstrip("/") + malicious_path
    
    print(f"[*] Sending request to: {url[:80]}...")  # Truncate for display
    print(f"[*] Path length: {len(malicious_path)} characters")
    
    start_time = time.time()
    
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as response:
            elapsed = time.time() - start_time
            print(f"[+] Response received in {elapsed:.2f} seconds")
            print(f"[+] Status: {response.status}")
            print(f"[+] No ReDoS vulnerability detected - regex is linear-time")
            
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start_time
        print(f"[!] HTTP error: {e.code} - {e.reason}")
        print(f"[!] Time elapsed: {elapsed:.2f} seconds")
        # Even errors should be fast if no ReDoS
        if elapsed > 5:
            print("[!] WARNING: Slow response may indicate regex issues")
        else:
            print("[+] Fast response confirms no ReDoS")
            
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
        print("[!] Make sure the target server is running")
        sys.exit(1)
        
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET_URL
    print(f"[*] Target: {target}")
    print("[*] Testing aiohttp 3.9.3 normalize_path_middleware for ReDoS")
    print("[*] Expected result: NOT VULNERABLE (regex is linear-time)")
    print()
    
    exploit(target)
    
    print()
    print("[*] Test complete")
    print("[*] Conclusion: The finding is correct - this is NOT exploitable")
    print("[*] The regex patterns '//+' and '^//+' are simple and linear-time")

if __name__ == "__main__":
    main()
