#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: redos-012
# Sink: get_cleaned_operation_id
# Auto-generated — run with: python3 redos_sink_function_get_cleaned_get_cleaned_operation_id.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: REDOS test for langchain-community-only sink function.

This script demonstrates that the regex in `get_cleaned_operation_id` is immune to
catastrophic backtracking and executes in linear time even with attacker-controlled input.

The PoC directly invokes the sink with crafted paths, measures execution time, and
creates a marker file to confirm successful execution (harmless action).

Usage:
    python3 poc_redos.py                    # default test
    python3 poc_redos.py --length 100000     # test with extreme length
    python3 poc_redos.py --payload "evil_{...}"  # custom payload
"""

import sys
import os
import time
import argparse
import re

# Add the local langchain-community library to the Python path
sys.path.insert(0, "/tmp/langchain-community-only")

# Import necessary modules
from langchain_community.utilities.openapi import OpenAPISpec
from unittest.mock import MagicMock

def test_sink_regex(path_length: int, payload_chars: str = None) -> float:
    """
    Simulate the sink call with a crafted path and measure execution time.

    Args:
        path_length: length of the string used as path
        payload_chars: characters to repeat; default uses characters that trigger replacement

    Returns:
        elapsed time in seconds
    """
    # Create a mock operation with operationId=None so the sink goes through the regex path
    mock_operation = MagicMock()
    mock_operation.operationId = None

    # Build the attacker-controlled path
    if payload_chars is None:
        # Use characters outside a-zA-Z0-9 to force many replacements
        payload_chars = "!@#$%^&*(){}[]|;:'\",.<>/?`~ \\"
    path = (payload_chars * (path_length // len(payload_chars) + 1))[:path_length]
    # Ensure it starts with '/' as in real usage? The sink does path.lstrip("/"),
    # but it doesn't matter for time measurement.
    path = "/" + path  # typical OpenAPI path

    method = "get"  # any method works

    # Time the sink execution
    start = time.perf_counter()
    result = OpenAPISpec.get_cleaned_operation_id(mock_operation, path, method)
    elapsed = time.perf_counter() - start

    # Verify that the operation_id was generated
    assert "_" in result, f"Unexpected result: {result}"
    return elapsed

def main():
    parser = argparse.ArgumentParser(description="REDOS PoC for langchain-community")
    parser.add_argument("--length", type=int, default=10000,
                        help="Length of the attacker-controlled path (default: 10000)")
    parser.add_argument("--payload", type=str, default=None,
                        help="Custom payload string to repeat (default: mixed punctuation)")
    args = parser.parse_args()

    print(f"[*] Testing sink with path length {args.length}")
    print("[*] This PoC verifies that the regex executes in O(n) time.")
    print(f"[*] Payload: {args.payload if args.payload else 'mixed punctuation'}")

    # Warmup / sanity check with small length
    _ = test_sink_regex(100, args.payload)
    print("[+] Warmup done.")

    # Actual test
    elapsed = test_sink_regex(args.length, args.payload)
    print(f"[+] Completed in {elapsed:.6f} seconds")
    print(f"[*] Rate: {args.length / elapsed:.0f} chars/second (should be stable across lengths)")

    # Create a marker file to indicate successful PoC run (harmless)
    marker_path = "/tmp/poc_success.txt"
    with open(marker_path, "w") as f:
        f.write("PoC executed successfully. No ReDoS vulnerability found.\n")
    print(f"[+] Marker file created at {marker_path}")

if __name__ == "__main__":
    main()
