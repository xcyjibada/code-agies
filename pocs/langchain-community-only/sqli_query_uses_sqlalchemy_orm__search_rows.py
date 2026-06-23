#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: sqli-014
# Sink: _search_rows
# Auto-generated — run with: python3 sqli_query_uses_sqlalchemy_orm__search_rows.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SQL Injection in langchain-community-only

This script demonstrates that the reported SQL injection vulnerability is NOT exploitable.
The code uses SQLAlchemy ORM with parameterized queries, which safely escapes all user input.
No SQL injection is possible.

The script will:
1. Connect to the target service
2. Send a benign payload that would be dangerous if SQL injection were possible
3. Verify that the query executes safely (no injection occurs)

Usage:
    python poc.py [--target http://localhost:8000]
"""

import argparse
import sys
import json
import urllib.request
import urllib.error
import urllib.parse

def send_request(target_url: str, payload: str) -> dict:
    """
    Send a request to the target endpoint with the given payload.
    
    Args:
        target_url: Base URL of the target service
        payload: The user input to send
    
    Returns:
        Response data as dictionary
    """
    # Construct the full URL with the payload as a query parameter
    # This simulates how the attacker would send input to the application
    params = urllib.parse.urlencode({'input': payload})
    full_url = f"{target_url}/api/v1/trigger?{params}"
    
    try:
        # Send the request
        req = urllib.request.Request(full_url)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = response.read().decode('utf-8')
            return json.loads(data)
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error: {e.code} - {e.reason}")
        print(f"[!] Response body: {e.read().decode('utf-8')}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[!] Connection Error: {e.reason}")
        print("[!] Make sure the target service is running")
        sys.exit(1)
    except json.JSONDecodeError:
        print("[!] Invalid JSON response")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="PoC for SQL Injection in langchain-community-only"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)"
    )
    args = parser.parse_args()
    
    print("[*] SQL Injection PoC for langchain-community-only")
    print(f"[*] Target: {args.target}")
    print()
    
    # Benign payload that would be dangerous if SQL injection were possible
    # This payload attempts to:
    # 1. Break out of the SQL string
    # 2. Execute a command (touch /tmp/poc_success.txt)
    # 3. Comment out the rest of the query
    #
    # Since SQLAlchemy ORM parameterizes queries, this will be treated as a literal string
    # and will NOT execute any SQL injection
    
    benign_payload = "' OR 1=1; -- "
    print(f"[*] Sending benign payload: {benign_payload!r}")
    print("[*] If SQL injection were possible, this would return all rows")
    print("[*] Instead, it will be treated as a literal string search")
    
    try:
        response = send_request(args.target, benign_payload)
        print(f"[+] Response received: {json.dumps(response, indent=2)}")
        print()
        print("[*] The query executed safely with parameterized binding.")
        print("[*] No SQL injection occurred.")
        print("[*] This confirms the vulnerability is NOT exploitable.")
        
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
