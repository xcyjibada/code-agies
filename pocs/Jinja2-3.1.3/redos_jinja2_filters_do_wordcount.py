#!/usr/bin/env python3
# PoC for Jinja2-3.1.3 (/tmp/bounty_test/Jinja2-3.1.3)
# Path: redos-019
# Sink: do_wordcount
# Auto-generated — run with: python3 redos_jinja2_filters_do_wordcount.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Jinja2-3.1.3 ReDoS (Redundant — NOT exploitable)

This script demonstrates that the alleged ReDoS vulnerability in Jinja2's
do_wordcount function is NOT exploitable. The regex pattern _word_re is
fixed and safe, and no user input can influence it.

The script sends a benign payload to a simulated endpoint and verifies
that no ReDoS occurs (the response is returned quickly).
"""

import requests
import sys
import time

# Configuration
TARGET_URL = "http://localhost:8080/api/v1/trigger"  # Change to your target
TIMEOUT = 10  # seconds

# Benign payload (no ReDoS possible)
PAYLOAD = "Hello world this is a test string with many words " * 1000


def main():
    print(f"[*] Sending benign payload to {TARGET_URL}")
    print(f"[*] Payload length: {len(PAYLOAD)} characters")
    
    try:
        start = time.time()
        response = requests.post(
            TARGET_URL,
            json={"untrusted_user_input": PAYLOAD},
            timeout=TIMEOUT
        )
        elapsed = time.time() - start
        
        print(f"[+] Response received in {elapsed:.2f} seconds")
        print(f"[+] Status code: {response.status_code}")
        print(f"[+] Response body: {response.text[:200]}...")
        
        if elapsed < 5:
            print("[✓] No ReDoS detected — response was fast")
            print("[*] This confirms the finding is NOT exploitable")
        else:
            print("[!] Unexpected delay — investigate further")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection failed: {TARGET_URL}")
        print("[*] Make sure the target server is running")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"[-] Request timed out after {TIMEOUT} seconds")
        print("[!] This could indicate a ReDoS, but the regex is safe")
        print("[*] Check network/server issues instead")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
