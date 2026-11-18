# INTENTIONALLY VULNERABLE BENCHMARK FIXTURE (AutoPatch AI).
# Do not import, execute or reuse this code. The credential below is fake.
"""Mail sender with a password hardcoded in a module-level constant."""

import smtplib

SMTP_HOST = "smtp.example.invalid"
SMTP_USER = "notifications"
SMTP_PASSWORD = "fake-benchmark-password-001"


def send_alert(recipient: str, body: str) -> None:
    with smtplib.SMTP(SMTP_HOST, 587) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, [recipient], body)
