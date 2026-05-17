import os
import smtplib
from email.message import EmailMessage
from typing import Tuple
from dotenv import load_dotenv

# load .env values
load_dotenv()

def send_confirmation_email(to_email: str, confirm_url: str, expires_at: str) -> Tuple[bool, str]:
    """
    Try to send email via SMTP configured via env vars.
    Returns (sent_bool, error_message_or_empty).
    """
    smtp_host = os.getenv("SMTP_HOST")
    if not smtp_host:
        # dev: return False so caller can show confirm URL in response/log
        return False, "no-smtp-configured"

    try:
        msg = EmailMessage()
        msg["Subject"] = os.getenv("SMTP_SUBJECT", "Confirm your registration")
        msg["From"] = os.getenv("SMTP_FROM", os.getenv("SMTP_USER", "no-reply@example.com"))
        msg["To"] = to_email
        body = f"Please confirm your registration by visiting the following link:\n\n{confirm_url}\n\nThis link expires at {expires_at} UTC."
        msg.set_content(body)

        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        use_tls = os.getenv("SMTP_TLS", "false").lower() in ("1", "true", "yes")

        # choose TLS or SSL based on USE_TLS and common ports
        if use_tls:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            # if port is 465 and TLS disabled, prefer SMTP_SSL
            if smtp_port == 465:
                server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)

        smtp_user = os.getenv("SMTP_USER")
        smtp_pass = os.getenv("SMTP_PASS")
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        return True, ""
    except Exception as e:
        return False, str(e)
