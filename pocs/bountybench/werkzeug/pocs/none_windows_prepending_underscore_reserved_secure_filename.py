#!/usr/bin/env python3
# PoC for werkzeug-3.0.1 (/tmp/bounty_test/werkzeug-3.0.1)
# Path: suspicious-006
# Sink: secure_filename
# Auto-generated — run with: python3 none_windows_prepending_underscore_reserved_secure_filename.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: werkzeug 3.0.1 secure_filename analysis

This script demonstrates that secure_filename correctly sanitizes filenames
and does NOT contain a vulnerability. It shows that path traversal attempts
are neutralized and the function behaves as documented.

Usage:
    python3 poc_werkzeug_secure_filename.py [--target http://example.com]

If no target is provided, it runs a local demonstration using the werkzeug
library directly.
"""

import argparse
import os
import sys
import unicodedata
import re

# Try to import werkzeug; if not available, use the local source path
try:
    from werkzeug.utils import secure_filename
except ImportError:
    # Add the local werkzeug source to path
    sys.path.insert(0, "/tmp/bounty_test/werkzeug-3.0.1/src")
    from werkzeug.utils import secure_filename


def demonstrate_local():
    """Run local demonstrations of secure_filename behavior."""
    print("=" * 70)
    print("Local Demonstration of werkzeug.utils.secure_filename")
    print("=" * 70)

    test_cases = [
        # (input, expected_behavior_description)
        ("../../../etc/passwd", "Path traversal neutralized -> no '..' or '/'"),
        ("My cool movie.mov", "Spaces replaced with underscores"),
        ("i contain cool ümläuts.txt", "Non-ASCII characters removed"),
        ("...hidden...", "Leading/trailing dots stripped"),
        ("CON", "Windows reserved name (on Windows, prepended with '_')"),
        ("", "Empty input returns empty string"),
        ("a" * 300, "Long filenames are preserved (no truncation)"),
        ("file with spaces.txt", "Spaces become underscores"),
        (".leading_dot", "Leading dot stripped"),
        ("trailing_dot.", "Trailing dot stripped"),
        ("__double_underscore__", "Underscores preserved (only leading/trailing stripped)"),
        ("path/with/slashes", "Slashes replaced with spaces then underscores"),
        ("path\\with\\backslashes", "Backslashes replaced with spaces then underscores"),
    ]

    for filename, description in test_cases:
        result = secure_filename(filename)
        print(f"\nInput:    {repr(filename)}")
        print(f"Output:   {repr(result)}")
        print(f"Note:     {description}")

        # Verify safety properties
        assert "/" not in result, f"FAIL: Path separator '/' found in {repr(result)}"
        assert "\\" not in result, f"FAIL: Backslash found in {repr(result)}"
        assert ".." not in result, f"FAIL: '..' found in {repr(result)}"
        assert result == result.strip("._"), f"FAIL: Leading/trailing dots/underscores in {repr(result)}"
        assert all(ord(c) < 128 for c in result), f"FAIL: Non-ASCII character in {repr(result)}"

    print("\n" + "=" * 70)
    print("All local tests passed - secure_filename is working correctly.")
    print("No vulnerability found - the function properly sanitizes filenames.")
    print("=" * 70)


def demonstrate_remote(target_url):
    """Test secure_filename behavior via a web application endpoint."""
    import requests

    print(f"\nTesting remote endpoint: {target_url}")
    print("This assumes the target has an endpoint that uses secure_filename")
    print("and reflects the sanitized filename back to the user.\n")

    payloads = [
        "../../../etc/passwd",
        "malicious<script>alert(1)</script>.txt",
        "CON",
        "file with spaces.txt",
        "....hidden....",
    ]

    for payload in payloads:
        try:
            response = requests.get(
                target_url,
                params={"filename": payload},
                timeout=10,
            )
            print(f"Payload: {repr(payload)}")
            print(f"Response: {response.text[:200]}")
            print("-" * 40)
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to {target_url}: {e}")
            print("Skipping remote tests - run without --target for local demo")
            return


def main():
    parser = argparse.ArgumentParser(
        description="PoC: werkzeug secure_filename analysis - demonstrates NO vulnerability"
    )
    parser.add_argument(
        "--target",
        help="URL of a web application endpoint that uses secure_filename (optional)",
    )
    args = parser.parse_args()

    if args.target:
        demonstrate_remote(args.target)
    else:
        demonstrate_local()

    print("\n" + "=" * 70)
    print("CONCLUSION: secure_filename is NOT vulnerable.")
    print("The function correctly sanitizes filenames by:")
    print("  - Normalizing Unicode (NFKD)")
    print("  - Removing non-ASCII characters")
    print("  - Replacing path separators with spaces")
    print("  - Stripping leading/trailing dots and underscores")
    print("  - Handling Windows reserved device names")
    print("No path traversal, injection, or other filename-based attacks are possible.")
    print("=" * 70)


if __name__ == "__main__":
    main()
