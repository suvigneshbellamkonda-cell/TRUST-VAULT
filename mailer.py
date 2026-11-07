"""Sends e-mail through an HTTPS e-mail service (Brevo).

Render's free plan blocks the normal e-mail ports, so the usual SMTP route
does not work there. The key and the sender address come from the server
settings (BREVO_API_KEY, MAIL_FROM) and are never in the code.
"""
import json
import os
import urllib.request


def configured():
    return bool(os.environ.get("BREVO_API_KEY") and os.environ.get("MAIL_FROM"))


def send(to_email, to_name, subject, text):
    """True if the service accepted the message. Never raises, and never
    prints the key or the message."""
    if not configured():
        return False
    body = json.dumps({
        "sender": {"name": "TrustVault", "email": os.environ["MAIL_FROM"]},
        "to": [{"email": to_email, "name": to_name}],
        "subject": subject,
        "textContent": text,
    }).encode()
    request = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email", data=body, method="POST",
        headers={"api-key": os.environ["BREVO_API_KEY"],
                 "content-type": "application/json", "accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return 200 <= response.status < 300
    except Exception:
        return False