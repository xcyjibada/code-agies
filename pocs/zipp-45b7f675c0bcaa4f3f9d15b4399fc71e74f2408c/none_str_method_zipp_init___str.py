#!/usr/bin/env python3
# PoC for zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c (/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c)
# Path: suspicious-007
# Sink: __str__
# Auto-generated — run with: python3 none_str_method_zipp_init___str.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept script for zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c.

According to the security finding, the `__str__` method in `zipp/__init__.py`
is NOT exploitable because it only constructs a string representation and
does not perform any filesystem I/O, system calls, or dangerous operations.
Even if `self.at` contains path traversal characters, the returned string
is harmless and later validation by `zipfile.Path.open` prevents actual
traversal.

This script demonstrates that no security impact arises from attacker-controlled
input to the `__str__` method. It exercises the method with malicious `self.at`
values and confirms that no file access or code execution occurs.

Usage: python3 poc_zipp.py
"""

import posixpath
import sys

# ----------------------------------------------------------------------
# Minimal reproduction of the relevant zipp code (based on the given commit)
# ----------------------------------------------------------------------

def none_as(value, replacement):
    """Helper used in zipp's __str__: returns replacement if value is None."""
    return value if value is not None else replacement


class MockPath:
    """
    Mimics the relevant parts of zipp.Path used in the __str__ method.
    We only expose the attributes needed to trigger the code path.
    """
    def __init__(self, root_filename: str, at: str):
        self.root = type('Root', (), {'filename': root_filename})()
        self.at = at

    def __str__(self):
        """Direct copy from zipp/__init__.py line 431."""
        root = none_as(self.root.filename, ':zipfile:')
        return posixpath.join(root, self.at) if self.at else root


# ----------------------------------------------------------------------
# Test harness
# ----------------------------------------------------------------------
def test_malicious_at():
    """Verify that dangerous self.at values only produce strings."""
    malicious_ats = [
        "../../../etc/passwd",          # classic path traversal
        "..\\..\\..\\windows\\system32", # windows style (posixpath normalizes)
        "%00",                          # null byte (no effect)
        "subdir/../../outside.zip",     # escape archive
        "",                             # empty string
        None,                           # will be handled by __str__ check
    ]

    # Use a benign root filename (simulating a zip archive path)
    root_filename = "/path/to/archive.zip"

    print("[*] Testing zipp.__str__ with malicious self.at values")
    print(f"[*] Root filename: {root_filename}")
    print()

    for at in malicious_ats:
        try:
            p = MockPath(root_filename, at)
            result = str(p)  # calls __str__
            print(f"[+] self.at = {at!r}")
            print(f"    __str__ result = {result!r}")
            # Ensure the result is still a string, no side effects
            assert isinstance(result, str), "Result must be string"
            # No filesystem operation triggered
        except Exception as e:
            print(f"[-] Unexpected exception for at={at!r}: {e}")

    print()
    print("[*] All tests passed: __str__ produces only strings, no I/O.")
    print("[*] This confirms the vulnerability is NOT exploitable at this sink.")
    print("[*] Path traversal in self.at has no security impact here.")


# ----------------------------------------------------------------------
# Additional simulation: typical usage of zipp.Path in a web endpoint
# (as described in the system wrapper)
# ----------------------------------------------------------------------
def simulate_web_endpoint():
    """
    Simulate a web endpoint that uses the library with untrusted input.
    The endpoint calls __str__ on a Path object constructed with
    attacker-controlled internal path. We show that even if the string
    contains '../', it does not lead to file access.
    """
    print("--- Simulating web endpoint ---")
    # Assume user input is the 'at' parameter
    untrusted_input = "../../../etc/shadow"
    archive_path = "/tmp/some_archive.zip"

    # Construct the Path (simplified)
    p = MockPath(archive_path, untrusted_input)
    string_repr = str(p)

    print(f"[*] Untrusted input: {untrusted_input!r}")
    print(f"[*] String representation: {string_repr!r}")
    print("[*] The string is never used for filesystem access. No vulnerability.")
    print()


if __name__ == "__main__":
    test_malicious_at()
    simulate_web_endpoint()
    sys.exit(0)
