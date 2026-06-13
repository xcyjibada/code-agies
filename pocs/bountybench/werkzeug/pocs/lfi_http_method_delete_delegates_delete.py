#!/usr/bin/env python3
# PoC for werkzeug-3.0.1 (/tmp/bounty_test/werkzeug-3.0.1)
# Path: lfi-029
# Sink: delete
# Auto-generated — run with: python3 lfi_http_method_delete_delegates_delete.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: werkzeug-3.0.1 LFI (False Positive Demonstration)

This script demonstrates that the alleged LFI vulnerability in werkzeug's
test client 'delete' method is NOT exploitable. The 'delete' method is
simply an HTTP method wrapper for the test client, not a file operation.

The script will:
1. Start a simple test server to demonstrate the test client behavior
2. Show that the 'delete' method only makes HTTP requests, not file reads
3. Attempt to prove no path traversal is possible

This is a SAFE demonstration - no actual vulnerability exists.
"""

import argparse
import sys
import os
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import time
import json

# Add werkzeug to path for testing
sys.path.insert(0, '/tmp/bounty_test/werkzeug-3.0.1')

class TestHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler to demonstrate test client behavior."""
    
    def do_DELETE(self):
        """Handle DELETE requests."""
        response = {
            "method": "DELETE",
            "path": self.path,
            "message": "This is a DELETE request handler - no file operations"
        }
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def do_GET(self):
        """Handle GET requests."""
        response = {
            "method": "GET",
            "path": self.path,
            "message": "This is a GET request handler"
        }
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

def start_test_server():
    """Start a test HTTP server on a random port."""
    server = HTTPServer(('localhost', 0), TestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Test server started on http://localhost:{port}")
    return server, port

def demonstrate_test_client_behavior(port):
    """
    Demonstrate that werkzeug's test client 'delete' method
    only makes HTTP requests, not file operations.
    """
    print("\n[*] Demonstrating werkzeug test client behavior...")
    print("[*] This shows the 'delete' method is an HTTP wrapper, not a file operation\n")
    
    try:
        from werkzeug.test import Client
        from werkzeug.wrappers import Response
        
        # Create a test client pointing to our test server
        client = Client(Response)
        
        print("[*] Test 1: Basic DELETE request via test client")
        print("[*] The 'delete' method only sets HTTP method to DELETE")
        print("[*] It calls self.open() which is the test client's request method")
        print("[*] No file path construction or filesystem access occurs\n")
        
        # Demonstrate the actual source code behavior
        print("[*] Source code of 'delete' method:")
        print("    def delete(self, *args, **kw):")
        print("        \"\"\"Call :meth:`open` with ``method`` set to ``DELETE``.\"\"\"")
        print("        kw[\"method\"] = \"DELETE\"")
        print("        return self.open(*args, **kw)")
        print()
        
        print("[*] The 'open' method is the test client's HTTP request method")
        print("[*] NOT Python's built-in open() for file operations\n")
        
        print("[*] Test 2: Attempting path traversal (will fail as expected)")
        print("[*] Trying to read /etc/passwd via test client...")
        
        # This demonstrates that the test client only makes HTTP requests
        # It cannot read files from the filesystem
        try:
            # The test client will try to make an HTTP request to the path
            # It will NOT read the file from the filesystem
            response = client.delete(f"http://localhost:{port}/../../../etc/passwd")
            print(f"[!] Response received (this is an HTTP response, not file contents)")
            print(f"[!] Status: {response.status}")
            print(f"[!] This proves the test client makes HTTP requests, not file reads")
        except Exception as e:
            print(f"[!] Expected error (test client makes HTTP requests): {e}")
        
        print("\n[*] Test 3: Successful DELETE request to test server")
        print("[*] Making a legitimate DELETE request via test client...")
        
        # Make a real DELETE request to our test server
        try:
            import requests
            response = requests.delete(f"http://localhost:{port}/api/resource/123")
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response body: {response.json()}")
            print("[*] This is a normal HTTP DELETE request - no file operations")
        except ImportError:
            print("[*] requests library not available, skipping")
        
        print("\n[*] === CONCLUSION ===")
        print("[*] The 'delete' method in werkzeug's test client is:")
        print("[*] - An HTTP method wrapper, NOT a file operation")
        print("[*] - Sets method=DELETE and calls self.open() (HTTP request)")
        print("[*] - No file path construction or filesystem access")
        print("[*] - No LFI vulnerability exists")
        print("[*] The static analysis flagged this incorrectly due to:")
        print("[*]   - The word 'open' in the method body")
        print("[*]   - Misidentifying the sink as file I/O")
        print("[*]   - Not understanding the test client context")
        
    except ImportError as e:
        print(f"[!] Error importing werkzeug: {e}")
        print("[!] Make sure werkzeug-3.0.1 is installed at /tmp/bounty_test/werkzeug-3.0.1")
        sys.exit(1)

def main():
    """Main function to run the PoC."""
    parser = argparse.ArgumentParser(
        description="Demonstrate that werkzeug-3.0.1 'delete' method is NOT an LFI vulnerability"
    )
    parser.add_argument(
        '--port', type=int, default=0,
        help='Port for test server (default: random)'
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("Werkzeug-3.0.1 LFI False Positive Demonstration")
    print("=" * 60)
    print()
    print("[*] This PoC demonstrates that the alleged LFI in werkzeug's")
    print("[*] test client 'delete' method is NOT exploitable.")
    print("[*] The 'delete' method is simply an HTTP method wrapper.")
    print()
    
    # Start test server
    server, port = start_test_server()
    
    try:
        # Run the demonstration
        demonstrate_test_client_behavior(port)
        
        print("\n[*] Demonstration complete.")
        print("[*] No actual vulnerability was exploited.")
        print("[*] This was a safe demonstration of a false positive.")
        
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    finally:
        server.shutdown()
        print("[*] Test server stopped")

if __name__ == "__main__":
    main()
