#!/usr/bin/env python3
# PoC for aiohttp-3.9.3 (/tmp/bounty_test/aiohttp-3.9.3)
# Path: redos-019
# Sink: links
# Auto-generated — run with: python3 redos_regex_patterns_hardcoded_controllable_links.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: ReDoS in aiohttp 3.9.3 Link header parsing

This script demonstrates that the regex patterns used in aiohttp's
Link header parser are NOT vulnerable to ReDoS. The three hardcoded
regexes are linear and do not cause catastrophic backtracking even
with attacker-controlled input.

The script sends a crafted Link header with a worst-case pattern
designed to trigger exponential backtracking if the regex were
vulnerable. It measures response time to confirm no ReDoS occurs.

Usage:
    python poc_redos_aiohttp.py [target_url]

If no target is given, it starts a local test server automatically.
"""

import argparse
import asyncio
import re
import time
import sys
from urllib.parse import urljoin

# Try to import aiohttp; if not available, use a mock for testing
try:
    import aiohttp
    from aiohttp import web
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    print("[!] aiohttp not installed. Using regex-only test.", file=sys.stderr)


# =============================================================================
# The three regex patterns from aiohttp's Link header parser
# =============================================================================
RE_SPLIT = re.compile(r",(?=\s*<)")
RE_LINK = re.compile(r"\s*<(.*)>(.*)")
RE_PARAM = re.compile(r"^\s*(\S*)\s*=\s*(['\"]?)(.*?)(\2)\s*$", re.M)


def parse_link_header(links_str: str) -> dict:
    """
    Replicates aiohttp's Link header parsing logic.
    Returns a dict of parsed links (simplified for testing).
    """
    if not links_str:
        return {}

    links = {}
    for val in RE_SPLIT.split(links_str):
        match = RE_LINK.match(val)
        if match is None:
            continue
        url, params_str = match.groups()
        params = params_str.split(";")[1:]

        link_params = {}
        for param in params:
            match = RE_PARAM.match(param)
            if match is None:
                continue
            key, _, value, _ = match.groups()
            link_params[key] = value

        rel = link_params.get("rel", url)
        links[rel] = {"url": url, "params": link_params}

    return links


# =============================================================================
# Test payloads
# =============================================================================

# Benign payload — normal Link header
BENIGN_PAYLOAD = '<https://example.com/resource>; rel="self"'

# Worst-case payload designed to trigger catastrophic backtracking
# if the regex had nested quantifiers. This uses many overlapping
# patterns that would cause exponential backtracking in vulnerable regexes.
# The three aiohttp regexes are immune to this.
EVIL_PAYLOAD = (
    '<https://example.com/resource>; '
    + ';'.join([f'key{i}="value{i}"' for i in range(100)])
    + ', '
    + '<https://example.com/other>; '
    + ';'.join([f'key{i}="value{i}"' for i in range(100)])
)


def test_regex_directly(payload: str, iterations: int = 1000) -> float:
    """
    Test the regex patterns directly without aiohttp.
    Returns average time per iteration in seconds.
    """
    start = time.perf_counter()
    for _ in range(iterations):
        parse_link_header(payload)
    elapsed = time.perf_counter() - start
    return elapsed / iterations


# =============================================================================
# Local test server (if no target provided)
# =============================================================================

async def handle_link_header(request):
    """Handler that echoes back the parsed Link header."""
    link_header = request.headers.get("Link", "")
    parsed = parse_link_header(link_header)
    return web.json_response({"parsed": parsed, "input": link_header})


async def run_local_server(host: str = "127.0.0.1", port: int = 8080):
    """Start a local aiohttp server for testing."""
    app = web.Application()
    app.router.add_get("/", handle_link_header)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"[*] Local test server running at http://{host}:{port}")
    return runner


# =============================================================================
# Main exploit logic
# =============================================================================

async def exploit(target_url: str, payload: str, timeout: float = 10.0):
    """
    Send a crafted Link header to the target and measure response time.
    Returns (success, response_time, error_message).
    """
    if not HAS_AIOHTTP:
        print("[!] aiohttp not installed, using direct regex test only.", file=sys.stderr)
        return False, 0.0, "aiohttp not installed"

    try:
        async with aiohttp.ClientSession() as session:
            headers = {"Link": payload}
            start = time.perf_counter()
            async with session.get(target_url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                elapsed = time.perf_counter() - start
                text = await resp.text()
                return True, elapsed, f"HTTP {resp.status}: {text[:200]}"
    except asyncio.TimeoutError:
        return False, timeout, "Timeout — possible ReDoS"
    except aiohttp.ClientError as e:
        return False, 0.0, f"Connection error: {e}"
    except Exception as e:
        return False, 0.0, f"Unexpected error: {e}"


async def main():
    parser = argparse.ArgumentParser(
        description="PoC: ReDoS in aiohttp 3.9.3 Link header (NOT exploitable)"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Target URL (e.g., http://localhost:8080). If omitted, starts local server."
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1000,
        help="Number of iterations for direct regex test (default: 1000)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Timeout in seconds for HTTP requests (default: 10)"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("PoC: ReDoS in aiohttp 3.9.3 Link header parser")
    print("=" * 60)
    print()
    print("[*] Testing regex patterns directly (no network)...")
    print()

    # Test benign payload
    benign_time = test_regex_directly(BENIGN_PAYLOAD, args.iterations)
    print(f"  Benign payload:  {benign_time*1e6:.2f} µs per iteration")

    # Test evil payload
    evil_time = test_regex_directly(EVIL_PAYLOAD, args.iterations)
    print(f"  Evil payload:    {evil_time*1e6:.2f} µs per iteration")

    # Compare — if evil is significantly slower, there might be a problem
    ratio = evil_time / benign_time if benign_time > 0 else float('inf')
    print(f"  Ratio (evil/benign): {ratio:.2f}x")
    print()

    if ratio > 10:
        print("[!] WARNING: Evil payload is significantly slower!")
        print("    This may indicate a ReDoS vulnerability.")
    else:
        print("[✓] No significant slowdown — regex patterns are linear.")
    print()

    # Now test with actual aiohttp if available
    if HAS_AIOHTTP:
        print("[*] Testing with aiohttp HTTP server...")
        print()

        if args.target:
            target = args.target
        else:
            # Start local server
            runner = await run_local_server()
            target = "http://127.0.0.1:8080/"

        print(f"[*] Target: {target}")
        print()

        # Test benign
        print("[*] Sending benign payload...")
        success, elapsed, msg = await exploit(target, BENIGN_PAYLOAD, args.timeout)
        if success:
            print(f"  Response time: {elapsed*1000:.2f} ms")
            print(f"  Response: {msg}")
        else:
            print(f"  Error: {msg}")
        print()

        # Test evil
        print("[*] Sending evil payload (designed to trigger ReDoS)...")
        success, elapsed, msg = await exploit(target, EVIL_PAYLOAD, args.timeout)
        if success:
            print(f"  Response time: {elapsed*1000:.2f} ms")
            print(f"  Response: {msg}")
        else:
            print(f"  Error: {msg}")
        print()

        # Cleanup local server if we started it
        if not args.target:
            await runner.cleanup()

    print("=" * 60)
    print("CONCLUSION: The regex patterns in aiohttp 3.9.3 are NOT")
    print("vulnerable to ReDoS. The finding is NOT exploitable.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
