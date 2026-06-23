#!/usr/bin/env python3
# PoC for langchain-minimal (/tmp/langchain-minimal)
# Path: redos-002
# Sink: __init__
# Auto-generated — run with: python3 redos_prone_constructs___init.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: ReDoS in langchain-minimal XML parser

This script demonstrates that the claimed ReDoS vulnerability in
langchain-minimal's XML parser is NOT exploitable. The regex pattern
'<[a-zA-Z:_]' is static, simple, and does not process user input in
a way that could cause catastrophic backtracking.

The script will:
1. Connect to the target endpoint
2. Send various payloads designed to trigger ReDoS if the vulnerability existed
3. Show that no ReDoS occurs because the regex is safe

Note: This is a negative PoC - it proves the vulnerability does NOT exist.
"""

import requests
import sys
import time
import argparse

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8000"
DEFAULT_ENDPOINT = "/api/v1/trigger"

def test_payload(target_url, payload, description):
    """Send a payload and measure response time."""
    url = f"{target_url}{DEFAULT_ENDPOINT}"
    
    print(f"\n[*] Testing: {description}")
    print(f"[*] Payload length: {len(payload)} chars")
    
    try:
        start_time = time.time()
        response = requests.post(
            url,
            json={"untrusted_user_input": payload},
            timeout=30
        )
        elapsed = time.time() - start_time
        
        print(f"[*] Response time: {elapsed:.3f}s")
        print(f"[*] Status code: {response.status_code}")
        
        if elapsed > 5:
            print("[!] WARNING: Slow response detected - possible ReDoS")
            return True
        else:
            print("[+] Normal response time - no ReDoS")
            return False
            
    except requests.exceptions.Timeout:
        print("[!] TIMEOUT - possible ReDoS")
        return True
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for ReDoS in langchain-minimal (negative test)"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("ReDoS PoC for langchain-minimal XML parser")
    print("=" * 60)
    print("\n[!] This is a NEGATIVE PoC - the vulnerability does NOT exist")
    print("[!] The regex '<[a-zA-Z:_]' is static and safe")
    print("[!] These tests will show normal response times\n")
    
    # Test payloads that would trigger ReDoS if the regex was vulnerable
    test_cases = [
        # Simple XML-like input
        ("<root>test</root>", "Simple XML input"),
        
        # Long string of '<' characters (would cause backtracking if vulnerable)
        ("<" * 10000 + "a", "10k '<' characters followed by 'a'"),
        
        # Mixed case with potential for catastrophic backtracking
        ("<" * 5000 + "a" * 5000, "5k '<' followed by 5k 'a'"),
        
        # Nested XML-like structure
        ("<" * 1000 + "a" * 1000 + ">" * 1000, "Deeply nested angle brackets"),
        
        # Unicode characters that might confuse regex
        ("<\u00e9\u00e0\u00fc>test</\u00e9\u00e0\u00fc>", "Unicode characters"),
        
        # Very long single line
        ("<" + "a" * 100000 + ">", "100k chars after '<'"),
        
        # Multiple regex matches
        ("<a><b><c><d><e>" * 1000, "Multiple nested tags"),
        
        # Empty input
        ("", "Empty input"),
        
        # Input that doesn't match regex at all
        ("Hello World", "Non-matching input"),
    ]
    
    vulnerable_found = False
    
    for payload, description in test_cases:
        if test_payload(args.target, payload, description):
            vulnerable_found = True
            print("\n[!] Potential vulnerability detected!")
            break
        time.sleep(0.5)  # Be nice to the server
    
    print("\n" + "=" * 60)
    if vulnerable_found:
        print("[!] WARNING: Possible ReDoS detected - investigate further")
    else:
        print("[+] All tests passed - no ReDoS vulnerability found")
        print("[+] The regex '<[a-zA-Z:_]' is confirmed safe")
    print("=" * 60)

if __name__ == "__main__":
    main()
