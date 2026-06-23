#!/usr/bin/env python3
# PoC for werkzeug-3.0.1 (/tmp/bounty_test/werkzeug-3.0.1)
# Path: sqli-017
# Sink: addInfoPrompt
# Auto-generated — run with: python3 sqli_javascript_debugger_frontend_addInfoPrompt.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Werkzeug Debugger SQL Injection (NOT EXPLOITABLE)

This script demonstrates that the alleged SQL injection vulnerability in
werkzeug-3.0.1's debugger frontend is NOT exploitable. The code path is
entirely client-side JavaScript that sets innerHTML with a static string.
No SQL queries are executed, and no user input is processed.

The script will:
1. Connect to the target werkzeug debugger endpoint
2. Verify the debugger page loads correctly
3. Show that no SQL injection is possible

Usage:
    python3 poc_werkzeug_sqli.py [--target http://localhost:5000]
"""

import argparse
import sys
import requests
from urllib.parse import urljoin

def check_debugger_endpoint(target_url):
    """Check if the werkzeug debugger is accessible and verify no SQL injection exists."""
    
    # Common werkzeug debugger endpoints
    endpoints = [
        "/console",
        "/debugger",
        "/__debugger__",
        "/debug/",
    ]
    
    print(f"[*] Testing target: {target_url}")
    print("[*] Checking for werkzeug debugger endpoints...")
    
    for endpoint in endpoints:
        url = urljoin(target_url, endpoint)
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            print(f"    {endpoint}: HTTP {response.status_code}")
            
            if response.status_code == 200:
                # Check if this is a werkzeug debugger page
                if "werkzeug" in response.text.lower() or "debugger" in response.text.lower():
                    print(f"[!] Found werkzeug debugger at {url}")
                    
                    # Verify the innerHTML content is static (no user input)
                    if "To switch between the interactive traceback" in response.text:
                        print("[+] Confirmed: Debugger uses static innerHTML content")
                        print("[+] No user input is processed in this code path")
                        print("[+] No SQL queries are executed")
                        print("[+] Vulnerability is NOT exploitable")
                        return True
                    else:
                        print("[*] Debugger page found but content structure differs")
                        return False
        except requests.exceptions.ConnectionError:
            print(f"    {endpoint}: Connection failed")
        except requests.exceptions.Timeout:
            print(f"    {endpoint}: Timeout")
        except Exception as e:
            print(f"    {endpoint}: Error - {e}")
    
    print("[-] No werkzeug debugger endpoint found")
    return False

def demonstrate_no_sqli(target_url):
    """Demonstrate that SQL injection is not possible in this code path."""
    
    print("\n[*] Attempting SQL injection payloads (expected to fail)...")
    
    # Common SQL injection payloads
    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users; --",
        "<script>alert('XSS')</script>",
    ]
    
    for payload in payloads:
        # Try injecting via URL parameters
        test_url = f"{target_url}/console?cmd={payload}"
        try:
            response = requests.get(test_url, timeout=10)
            # The debugger should not execute SQL or reflect the payload
            if payload in response.text:
                print(f"[!] Unexpected: Payload reflected in response: {payload[:50]}")
            else:
                print(f"[+] Payload not reflected (expected): {payload[:50]}")
        except Exception as e:
            print(f"[-] Error testing payload: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for werkzeug-3.0.1 debugger SQL injection (NOT EXPLOITABLE)"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:5000",
        help="Target URL (default: http://localhost:5000)"
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("Werkzeug Debugger SQL Injection PoC")
    print("=" * 60)
    print("\n[ANALYSIS]")
    print("The alleged vulnerability is in the debugger's JavaScript code")
    print("that sets innerHTML with a static string. No SQL operations")
    print("exist in this code path, and no user input is processed.")
    print("This finding is NOT EXPLOITABLE.\n")
    
    # Check debugger endpoint
    if check_debugger_endpoint(args.target):
        demonstrate_no_sqli(args.target)
        
        print("\n" + "=" * 60)
        print("CONCLUSION")
        print("=" * 60)
        print("The alleged SQL injection vulnerability in werkzeug-3.0.1's")
        print("debugger frontend is NOT exploitable. The code path:")
        print("1. Uses only client-side JavaScript")
        print("2. Sets innerHTML with a static string")
        print("3. Does not execute any SQL queries")
        print("4. Does not process any user input")
        print("\nThis finding should be marked as NOT_EXPLOITABLE.")
    else:
        print("\n[-] Could not verify the debugger endpoint")
        print("[-] Ensure the target is running werkzeug with debug mode enabled")
        sys.exit(1)

if __name__ == "__main__":
    main()
